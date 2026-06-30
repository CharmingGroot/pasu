//! LLM egress guard — a `reqwest-middleware` that gates a rig provider's HTTP
//! egress through a [`RuleEngine`]. The embedder injects it via the provider's
//! `.http_client()`.
//!
//! Each request's destination (host:port) becomes an [`Event::Egress`], which
//! the engine evaluates. `Allow` → forward; `Deny`/`Ask` → block (fail-closed)
//! before the request leaves the process. This is the *cooperative* layer; the
//! kernel eBPF egress guard is the *enforcing* backstop. Design: docs/rig-integration.md

use anyhow::anyhow;
use http::Extensions;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};

use pasu_core::{Event, EventKind, RuleEngine, Verdict};

/// reqwest-middleware that allows or blocks LLM-provider egress by policy.
pub struct PasuEgressMiddleware<E: RuleEngine> {
    engine: E,
    enabled: bool,
}

impl<E: RuleEngine> PasuEgressMiddleware<E> {
    /// Enabled guard backed by `engine`.
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            enabled: true,
        }
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

        match self.decide(&host, port) {
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

    /// Engine that allows a single host and denies the rest.
    struct HostAllow(&'static str);
    impl RuleEngine for HostAllow {
        fn evaluate(&self, event: &Event) -> Verdict {
            match &event.kind {
                EventKind::Egress { host, .. } if host == self.0 => Verdict::Allow,
                EventKind::Egress { host, .. } => {
                    Verdict::Deny(format!("host not allowed: {host}"))
                }
                _ => Verdict::Allow,
            }
        }
    }

    #[test]
    fn allows_listed_host_blocks_others() {
        let mw = PasuEgressMiddleware::new(HostAllow("llm.internal"));
        assert!(matches!(mw.decide("llm.internal", 443), Verdict::Allow));
        assert!(matches!(mw.decide("evil.example", 443), Verdict::Deny(_)));
    }
}
