//! LLM egress guard — a `reqwest-middleware` that gates a rig provider's HTTP
//! egress through a [`RuleEngine`]. The embedder injects it via the provider's
//! `.http_client()`.
//!
//! Each request's destination (host:port) becomes an [`Event::Egress`], which
//! the engine evaluates. `Allow` → forward; `Deny`/`Ask` → block (fail-closed)
//! before the request leaves the process. This is the *cooperative* layer; the
//! kernel eBPF egress guard is the *enforcing* backstop. Design: docs/rig-integration.md

use std::sync::Arc;

use anyhow::anyhow;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};

use pasu_core::{AuditRecord, AuditSink, Event, EventKind, RuleEngine, Verdict};

/// reqwest-middleware that allows or blocks LLM-provider egress by policy.
pub struct PasuEgressMiddleware<E: RuleEngine> {
    engine: E,
    enabled: bool,
    sink: Option<Arc<dyn AuditSink>>,
}

impl<E: RuleEngine> PasuEgressMiddleware<E> {
    /// Enabled guard backed by `engine`.
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            enabled: true,
            sink: None,
        }
    }

    /// Attach an audit sink; every egress decision is recorded (layer "rig-egress").
    pub fn with_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Runtime toggle. When disabled, all egress passes through.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Policy decision for a destination. Separated from `handle` so it is
    /// unit-testable without driving a real HTTP request.
    fn decide(&self, host: &str, port: u16) -> Verdict {
        self.engine.evaluate(&Event {
            kind: EventKind::Egress {
                host: host.to_string(),
                port,
            },
        })
    }
}

#[async_trait::async_trait]
impl<E: RuleEngine + Send + Sync + 'static> Middleware for PasuEgressMiddleware<E> {
    async fn handle(
        &self,
        req: Request,
        extensions: &mut Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        if !self.enabled {
            return next.run(req, extensions).await;
        }
        let host = req.url().host_str().unwrap_or_default().to_string();
        let port = req.url().port_or_known_default().unwrap_or(0);

        let verdict = self.decide(&host, port);
        if let Some(sink) = &self.sink {
            let event = Event {
                kind: EventKind::Egress {
                    host: host.clone(),
                    port,
                },
            };
            sink.record(&AuditRecord::new("rig-egress", &event, &verdict));
        }

        match verdict {
            Verdict::Allow => next.run(req, extensions).await,
            // Egress has no interactive approval path, so Ask is fail-closed (block).
            Verdict::Deny(reason) | Verdict::Ask(reason) => Err(
                reqwest_middleware::Error::Middleware(anyhow!("egress blocked by pasu: {reason}")),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    use reqwest_middleware::ClientBuilder;
    use wiremock::matchers::method;
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// allow `ok.host`, ask `warn.host`, deny everything else.
    struct PolicyEngine;
    impl RuleEngine for PolicyEngine {
        fn evaluate(&self, event: &Event) -> Verdict {
            match &event.kind {
                EventKind::Egress { host, .. } => match host.as_str() {
                    "ok.host" => Verdict::Allow,
                    "warn.host" => Verdict::Ask("confirm".into()),
                    other => Verdict::Deny(format!("host not allowed: {other}")),
                },
                _ => Verdict::Allow,
            }
        }
    }

    /// Allows only the given host (used with a dynamic mock-server address).
    struct AllowOnly(String);
    impl RuleEngine for AllowOnly {
        fn evaluate(&self, event: &Event) -> Verdict {
            match &event.kind {
                EventKind::Egress { host, .. } if *host == self.0 => Verdict::Allow,
                _ => Verdict::Deny("blocked".into()),
            }
        }
    }

    /// Records the (host, port) the engine was asked about, then allows.
    #[derive(Clone, Default)]
    struct Recorder(Arc<Mutex<Vec<(String, u16)>>>);
    impl RuleEngine for Recorder {
        fn evaluate(&self, event: &Event) -> Verdict {
            if let EventKind::Egress { host, port } = &event.kind {
                self.0.lock().unwrap().push((host.clone(), *port));
            }
            Verdict::Allow
        }
    }

    #[test]
    fn decide_maps_each_verdict() {
        let mw = PasuEgressMiddleware::new(PolicyEngine);
        assert!(matches!(mw.decide("ok.host", 443), Verdict::Allow));
        assert!(matches!(mw.decide("warn.host", 443), Verdict::Ask(_)));
        assert!(matches!(mw.decide("evil.example", 80), Verdict::Deny(_)));
    }

    #[test]
    fn decide_forwards_exact_host_and_port_to_engine() {
        let rec = Recorder::default();
        let seen = rec.0.clone();
        let mw = PasuEgressMiddleware::new(rec);
        let _ = mw.decide("api.example", 8443);
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            &[("api.example".into(), 8443)]
        );
    }

    async fn send_get<E: RuleEngine + Send + Sync + 'static>(
        mw: PasuEgressMiddleware<E>,
        url: &str,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        ClientBuilder::new(reqwest::Client::new())
            .with(mw)
            .build()
            .get(url)
            .send()
            .await
    }

    #[tokio::test]
    async fn handle_forwards_allowed_egress() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let host = server.address().ip().to_string();
        let resp = send_get(PasuEgressMiddleware::new(AllowOnly(host)), &server.uri())
            .await
            .expect("allowed egress should reach the server");
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn handle_blocks_denied_egress() {
        // No mock mounted: a denied request must never reach the server.
        let server = MockServer::start().await;
        let resp = send_get(
            PasuEgressMiddleware::new(AllowOnly("not-the-server".into())),
            &server.uri(),
        )
        .await;
        assert!(
            resp.is_err(),
            "denied egress must be blocked by the middleware"
        );
    }

    #[tokio::test]
    async fn handle_disabled_passes_through_despite_deny() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        // Engine would deny, but the disabled guard must forward.
        let mut mw = PasuEgressMiddleware::new(AllowOnly("not-the-server".into()));
        mw.set_enabled(false);
        let resp = send_get(mw, &server.uri())
            .await
            .expect("disabled guard should forward");
        assert_eq!(resp.status(), 200);
    }

    #[tokio::test]
    async fn records_egress_decision_to_sink() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let host = server.address().ip().to_string();
        let sink = Arc::new(pasu_audit::MemorySink::default());
        let mw = PasuEgressMiddleware::new(AllowOnly(host)).with_sink(sink.clone());
        let _ = send_get(mw, &server.uri()).await;

        let recs = sink.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer, "rig-egress");
        assert_eq!(recs[0].verdict, pasu_core::VerdictKind::Allow);
    }
}
