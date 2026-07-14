//! `pasu-proxy` binary — serve the LLM-API guard proxy as a sidecar.
//!
//! App-level composition root: it wires the pure proxy library (router /
//! `ProxyState`) with a concrete rule engine (pasu-rules) and serves it on a
//! TCP port. The agent points its `base_url` at this address; the proxy
//! forwards to the real provider and blocks denied tool calls (fail-closed).
//!
//! With `--ui <addr>` it also serves the pasu-ui approval UI and wires a
//! [`UiApprover`], so `Verdict::Ask` becomes a human-in-the-loop decision
//! (approve/deny in the browser) instead of the default fail-closed deny.
//!
//! The library stays decoupled behind pasu-core; only this binary knows about
//! the concrete engine and the UI.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use pasu_core::{Approver, AuditRecord, AuditSink, Guard, RuleEngine};
use pasu_proxy::{router, Provider, ProxyState};
use pasu_rules::RulesetEngine;
use pasu_ui::{AuditFeed, UiApprover};

#[derive(Debug, Parser)]
#[command(about = "LLM-API guard proxy — parses tool calls and blocks denied ones")]
struct Opt {
    /// The pasu policy YAML — the SAME file the daemon loads.
    #[clap(short, long)]
    policy: std::path::PathBuf,
    /// Address to listen on. The agent points its `base_url` here.
    #[clap(short, long, default_value = "127.0.0.1:8788")]
    listen: String,
    /// Upstream LLM provider base URL to forward to (e.g. https://api.openai.com).
    #[clap(short, long)]
    upstream: String,
    /// Provider wire format of the upstream.
    #[clap(long, default_value = "openai")]
    provider: String,
    /// Serve the human-in-the-loop approval UI on this address (e.g.
    /// 127.0.0.1:8789). When set, `Verdict::Ask` awaits a browser decision;
    /// omit to fail-closed on `Ask`.
    #[clap(long)]
    ui: Option<String>,
}

fn parse_provider(s: &str) -> anyhow::Result<Provider> {
    match s {
        "openai" => Ok(Provider::OpenAi),
        "anthropic" => Ok(Provider::Anthropic),
        "gemini" => Ok(Provider::Gemini),
        other => {
            anyhow::bail!("unsupported provider {other:?} (supported: openai, anthropic, gemini)")
        }
    }
}

/// Minimal stderr JSONL audit — one line per decision, visible to any log
/// pipeline without a heavier sink.
struct StderrAudit;

impl AuditSink for StderrAudit {
    fn record(&self, record: &AuditRecord) {
        if let Ok(line) = serde_json::to_string(record) {
            eprintln!("{line}");
        }
    }
}

/// Fan a record out to several sinks (e.g. stderr JSONL + the UI feed).
struct TeeSink(Vec<Arc<dyn AuditSink>>);

impl AuditSink for TeeSink {
    fn record(&self, record: &AuditRecord) {
        for sink in &self.0 {
            sink.record(record);
        }
    }
}

/// Ring buffer size for the UI audit feed.
const AUDIT_FEED_CAP: usize = 256;

fn load_engine(policy: &std::path::Path) -> anyhow::Result<RulesetEngine> {
    let yaml = std::fs::read_to_string(policy)
        .with_context(|| format!("read policy {}", policy.display()))?;
    RulesetEngine::from_yaml(&yaml).with_context(|| format!("parse policy {}", policy.display()))
}

/// Bind and serve the reverse proxy until the process exits.
async fn serve_proxy<E, A>(state: Arc<ProxyState<E, A>>, listen: &str) -> anyhow::Result<()>
where
    E: RuleEngine + Send + Sync + 'static,
    A: Approver + Send + Sync + 'static,
{
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    eprintln!("pasu-proxy listening on {listen}");
    axum::serve(listener, router(state))
        .await
        .context("serve")?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let provider = parse_provider(&opt.provider)?;
    let engine = load_engine(&opt.policy)?;
    let client = reqwest::Client::new();

    eprintln!(
        "pasu-proxy -> upstream {} (provider: {})",
        opt.upstream, opt.provider
    );

    match opt.ui {
        // HITL: serve the approval UI and route `Ask` through it.
        Some(ui) => {
            let ui_addr: SocketAddr = ui.parse().with_context(|| format!("parse --ui {ui:?}"))?;
            let approver = UiApprover::new();
            let approvals = approver.state();
            let feed = AuditFeed::new(AUDIT_FEED_CAP);
            let sink: Arc<dyn AuditSink> =
                Arc::new(TeeSink(vec![Arc::new(StderrAudit), Arc::new(feed.clone())]));
            let guard = Guard::with_approver(engine, approver, "llm-proxy").with_sink(sink);
            let state = Arc::new(ProxyState {
                guard,
                client,
                upstream_base: opt.upstream.clone(),
                provider,
            });
            eprintln!("pasu-proxy HITL approval UI on http://{ui_addr}");
            tokio::try_join!(serve_proxy(state, &opt.listen), async {
                pasu_ui::serve(ui_addr, approvals, feed)
                    .await
                    .context("serve ui")
            })?;
        }
        // No UI: `Ask` fails closed (DenyAll); decisions go to stderr JSONL.
        None => {
            let guard = Guard::new(engine, "llm-proxy").with_sink(Arc::new(StderrAudit));
            let state = Arc::new(ProxyState {
                guard,
                client,
                upstream_base: opt.upstream.clone(),
                provider,
            });
            serve_proxy(state, &opt.listen).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasu_core::{Event, EventKind, Verdict};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct CountingSink(Arc<AtomicUsize>);
    impl AuditSink for CountingSink {
        fn record(&self, _record: &AuditRecord) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn tee_sink_fans_out_to_every_sink() {
        let a = Arc::new(AtomicUsize::new(0));
        let b = Arc::new(AtomicUsize::new(0));
        let tee = TeeSink(vec![
            Arc::new(CountingSink(a.clone())),
            Arc::new(CountingSink(b.clone())),
        ]);
        let ev = Event {
            kind: EventKind::ToolCall {
                name: "t".into(),
                input: "{}".into(),
            },
        };
        tee.record(&AuditRecord::new("llm-proxy", &ev, &Verdict::Allow));
        assert_eq!(a.load(Ordering::Relaxed), 1);
        assert_eq!(b.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn provider_parsing_accepts_the_three_formats() {
        assert!(parse_provider("openai").is_ok());
        assert!(parse_provider("anthropic").is_ok());
        assert!(parse_provider("gemini").is_ok());
        assert!(parse_provider("bogus").is_err());
    }
}
