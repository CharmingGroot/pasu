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
use std::time::Duration;

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
    /// Refuse any request whose prompt carries Korean PII, before it is sent.
    ///
    /// Off by default. The request path is otherwise forwarded untouched, which
    /// is the behaviour that existed before this flag — a deployment with no
    /// exposure to these patterns should not have an agent stopped mid-task by a
    /// false positive it did not ask for.
    #[clap(long)]
    block_pii_kr: bool,
    /// Load Presidio recognizer YAML and inspect requests with it.
    ///
    /// Reads the format people have already exported rather than asking them to
    /// retype their rules. What does not survive the trip — weak scores, context
    /// words, Python-only regex — is reported by name, and a file with anything
    /// unusable is refused rather than half-loaded.
    #[clap(long, value_name = "PATH")]
    presidio_rules: Option<std::path::PathBuf>,
    /// The lowest Presidio pattern score to import.
    ///
    /// Presidio ships patterns as weak as 0.01 because context words raise them
    /// there; nothing raises them here, so a low value imports patterns that
    /// fire on ordinary text.
    #[clap(long, default_value_t = 0.5)]
    presidio_min_score: f64,
    /// Seconds to wait for the upstream TCP+TLS handshake.
    #[clap(long, default_value_t = 10)]
    connect_timeout_secs: u64,
    /// Seconds to wait between reads from the upstream response.
    ///
    /// This is an *idle* timeout, not a total one: a long generation (or a
    /// streaming response that keeps sending) never trips it, but an upstream
    /// that stops responding mid-body does. A total timeout would cut off
    /// legitimate long completions.
    #[clap(long, default_value_t = 120)]
    read_timeout_secs: u64,
}

/// The request-side inspectors an operator asked for, and a line per inspector
/// saying it is on.
///
/// Silence would be the wrong default here in both directions: an operator who
/// passed the flag needs to see it took effect, and one who did not needs no
/// line at all rather than a reassuring one about a check that is not running.
fn inspectors(opt: &Opt) -> anyhow::Result<Vec<Arc<dyn pasu_core::Inspector>>> {
    let mut chosen: Vec<Arc<dyn pasu_core::Inspector>> = Vec::new();
    if opt.block_pii_kr {
        chosen.push(Arc::new(pasu_proxy::inspectors::PiiKr::builtin()));
    }
    if let Some(path) = &opt.presidio_rules {
        let yaml = std::fs::read_to_string(path)
            .with_context(|| format!("read presidio rules {}", path.display()))?;
        let import = pasu_inspect_presidio::Import {
            min_score: opt.presidio_min_score,
        };
        // Refuse a partial load. An operator who believes a rule file is in
        // force, and is holding half of it, is worse off than one who got an
        // error at startup.
        let rules = import.read(&yaml, "presidio").with_context(|| {
            format!(
                "import presidio rules {}\n\nEither remove those recognizers from \
                 the file, or lower --presidio-min-score (currently {}) if you \
                 accept that a weaker pattern will match more ordinary text.",
                path.display(),
                opt.presidio_min_score
            )
        })?;
        eprintln!("pasu-proxy: {} presidio pattern(s) loaded", rules.len());
        chosen.push(Arc::new(rules));
    }
    for inspector in &chosen {
        eprintln!(
            "pasu-proxy: requests are inspected by {} and refused on a match \
             (rule ids are logged, never the matched text)",
            inspector.name()
        );
    }
    Ok(chosen)
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
    // 종료 신호를 받으면 처리 중인 요청을 마친 뒤 닫는다. 중간에 끊으면
    // 에이전트가 절단된 응답을 받는다.
    axum::serve(listener, router(state))
        .with_graceful_shutdown(pasu_ui::shutdown::signal())
        .await
        .context("serve")?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let provider = parse_provider(&opt.provider)?;
    let engine = load_engine(&opt.policy)?;
    // Built once, before anything listens: a rule file that cannot be honoured
    // must stop startup rather than be discovered on the first request.
    let chosen_inspectors = inspectors(&opt)?;
    // 타임아웃이 없으면 응답하지 않는 업스트림이 요청을 무한히 붙잡고,
    // 커넥션이 쌓여 프록시가 가용성 병목이 된다. 다만 전체(total) 타임아웃은
    // 긴 생성·스트리밍을 잘라내므로 연결/유휴로 나눠 건다.
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(opt.connect_timeout_secs))
        .read_timeout(Duration::from_secs(opt.read_timeout_secs))
        .build()
        .context("build upstream HTTP client")?;

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
                inspectors: chosen_inspectors.clone(),
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
                inspectors: chosen_inspectors.clone(),
            });
            serve_proxy(state, &opt.listen).await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `--help` is where every flag this binary has is documented, so a build
    /// that cannot print it makes the answer to "what can this do" be "read the
    /// source".
    ///
    /// It is a *feature* question, not a code one: clap's `help` is a default
    /// feature, and the workspace turns default features off. This test fails
    /// with a plain `UnknownArgument` when that feature is missing, which is
    /// exactly what shipped.
    #[test]
    fn help_is_actually_available() {
        let error = Opt::try_parse_from(["pasu-proxy", "--help"])
            .expect_err("--help exits rather than parsing");

        assert_eq!(
            error.kind(),
            clap::error::ErrorKind::DisplayHelp,
            "--help must print help, not fail as an unknown argument"
        );
        assert!(
            error.to_string().contains("--upstream"),
            "the flags belong in the help text: {error}"
        );
    }
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
