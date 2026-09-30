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
use pasu_core::{Approver, AuditRecord, AuditSink, Guard};
use pasu_proxy::litellm::{guardrail_router, GuardrailState};
use pasu_proxy::{router, Judge, Provider, ProxyState};
use pasu_rules::RulesetEngine;
use pasu_ui::{AuditFeed, UiApprover};

/// The front-ends this binary can serve. All of them answer with the same
/// [`Judge`]; they differ only in how the bytes arrive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum Frontend {
    /// Reverse proxy: forwards to `--upstream`.
    Reverse,
    /// LiteLLM Generic Guardrail API (`/beta/litellm_basic_guardrail_api`).
    Litellm,
    /// Envoy External Processing (gRPC `envoy.service.ext_proc.v3`).
    #[cfg(feature = "ext-proc")]
    ExtProc,
}

impl Frontend {
    /// The audit `layer` its decisions are recorded under.
    fn layer(self) -> &'static str {
        match self {
            Frontend::Reverse => "llm-proxy",
            Frontend::Litellm => "litellm-guardrail",
            #[cfg(feature = "ext-proc")]
            Frontend::ExtProc => "envoy-ext-proc",
        }
    }
}

/// The shared key LiteLLM sends as `x-api-key` (its `api_key` setting). Read
/// from the environment so it never appears in a process listing.
const GUARDRAIL_API_KEY_ENV: &str = "PASU_GUARDRAIL_API_KEY";

#[derive(Debug, Parser)]
#[command(about = "LLM-API guard proxy — parses tool calls and blocks denied ones")]
struct Opt {
    /// The pasu policy YAML — the SAME file the daemon loads.
    #[clap(short, long)]
    policy: std::path::PathBuf,
    /// Address to listen on. The agent points its `base_url` here.
    #[clap(short, long, default_value = "127.0.0.1:8788")]
    listen: String,
    /// How traffic reaches pasu. `reverse`: agents point `base_url` here and
    /// pasu forwards to `--upstream`. `litellm`: LiteLLM's Generic Guardrail
    /// API. `ext-proc`: Envoy External Processing (gRPC). In the last two the
    /// gateway forwards and pasu decides. See integrations/.
    #[clap(long, value_enum, default_value_t = Frontend::Reverse)]
    frontend: Frontend,
    /// Upstream LLM provider base URL to forward to (e.g. https://api.openai.com).
    /// Required for `--frontend reverse`.
    #[clap(short, long)]
    upstream: Option<String>,
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
    #[cfg(feature = "pii-kr")]
    block_pii_kr: bool,
    /// Load Presidio recognizer YAML and inspect requests with it.
    ///
    /// Reads the format people have already exported rather than asking them to
    /// retype their rules. What does not survive the trip — weak scores, context
    /// words, Python-only regex — is reported by name, and a file with anything
    /// unusable is refused rather than half-loaded.
    #[clap(long, value_name = "PATH")]
    #[cfg(feature = "presidio")]
    presidio_rules: Option<std::path::PathBuf>,
    /// The lowest Presidio pattern score to import.
    ///
    /// Presidio ships patterns as weak as 0.01 because context words raise them
    /// there; nothing raises them here, so a low value imports patterns that
    /// fire on ordinary text.
    #[clap(long, default_value_t = 0.5)]
    #[cfg(feature = "presidio")]
    presidio_min_score: f64,
    /// Replace what an inspector finds instead of refusing the request.
    ///
    /// Off by default: refusing is the safe answer for a rule nobody has decided
    /// about. Redaction is one-way — the value is replaced with a fixed
    /// placeholder and not kept anywhere, so nothing can restore it and this
    /// proxy never becomes a store of the data it exists to stop.
    #[clap(long)]
    redact: bool,
    /// Always refuse on this rule, even with --redact. Repeatable.
    ///
    /// For a rule where the right answer is to stop rather than to carry on
    /// without it — a national ID in a prompt is usually a mistake, not a
    /// formatting problem.
    #[clap(long, value_name = "RULE")]
    block_rule: Vec<String>,
    /// Always replace this rule, even without --redact. Repeatable.
    #[clap(long, value_name = "RULE")]
    redact_rule: Vec<String>,
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
    /// Refuse a request body larger than this many bytes.
    #[clap(long, default_value_t = pasu_proxy::proxy::DEFAULT_MAX_REQUEST_BYTES)]
    max_request_bytes: usize,
    /// Refuse a response body larger than this many bytes instead of buffering
    /// it. The read timeout is an idle one, so this is what bounds a stream
    /// that never stops sending.
    #[clap(long, default_value_t = pasu_proxy::proxy::DEFAULT_MAX_RESPONSE_BYTES)]
    max_response_bytes: usize,
    /// Forward this path (no query) without any inspection. Repeatable.
    ///
    /// Endpoints the provider format does not name — embeddings, files,
    /// batches — are refused, because a path the proxy cannot read is one it
    /// cannot guard. This is how an operator decides otherwise for one of them.
    #[clap(long, value_name = "PATH")]
    passthrough_path: Vec<String>,
}

/// The request-side inspectors an operator asked for, and a line per inspector
/// saying it is on.
///
/// Silence would be the wrong default here in both directions: an operator who
/// passed the flag needs to see it took effect, and one who did not needs no
/// line at all rather than a reassuring one about a check that is not running.
/// How findings are answered, and a line saying so when it is not the default.
///
/// Silence is right when everything blocks — that is what the proxy has always
/// done. It is wrong when prompts are being altered on their way out: a model
/// answering about text the operator never wrote, with nothing in the log
/// saying why, is a debugging trap.
fn redaction_policy(opt: &Opt) -> pasu_core::redact::Policy {
    let mut policy = if opt.redact {
        pasu_core::redact::Policy::redact_everything()
    } else {
        pasu_core::redact::Policy::block_everything()
    };
    for rule in &opt.redact_rule {
        policy = policy.redacting(rule);
    }
    // After the redact list: where an operator named the same rule twice, the
    // stricter reading wins, and `action_for` enforces that too.
    for rule in &opt.block_rule {
        policy = policy.blocking(rule);
    }
    // Said once, and only about what is actually configured. Two lines that
    // disagree about whether a match refuses or rewrites are worse than one.
    if opt.redact || !opt.redact_rule.is_empty() {
        eprintln!(
            "pasu-proxy: a match rewrites the prompt rather than refusing it. The \
             replacement is one-way — no original is kept, so nothing can restore it"
        );
        if !opt.block_rule.is_empty() {
            eprintln!(
                "pasu-proxy: except {}, which still refuse the request",
                opt.block_rule.join(", ")
            );
        }
    } else {
        eprintln!("pasu-proxy: a match refuses the request");
    }
    policy
}

/// The inspectors this build was compiled with and this run asked for.
///
/// The proxy does not know what an inspector is beyond the trait. The two here
/// are behind features because shipping them is a packaging choice, not part of
/// what the proxy is — anyone adapting pasu to a scanner this repository has
/// never heard of implements [`pasu_core::Inspector`] and hands it to
/// `ProxyState`, without touching this function.
#[allow(unused_variables)]
fn inspectors(opt: &Opt) -> anyhow::Result<Vec<Arc<dyn pasu_core::Inspector>>> {
    #[allow(unused_mut)]
    let mut chosen: Vec<Arc<dyn pasu_core::Inspector>> = Vec::new();

    #[cfg(feature = "pii-kr")]
    if opt.block_pii_kr {
        chosen.push(Arc::new(pasu_inspect_pii_kr::PiiKr::builtin()));
    }

    #[cfg(feature = "presidio")]
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
            "pasu-proxy: requests are inspected by {} (rule ids are logged, never the \
             matched text)",
            inspector.name()
        );
    }
    Ok(chosen)
}

/// Size limits and exceptions, and a line for each exception: a path forwarded
/// uninspected is a hole the operator should see every time the proxy starts.
fn proxy_options(opt: &Opt) -> pasu_proxy::ProxyOptions {
    for path in &opt.passthrough_path {
        eprintln!("pasu-proxy: {path} is forwarded WITHOUT inspection (--passthrough-path)");
    }
    pasu_proxy::ProxyOptions {
        max_request_bytes: opt.max_request_bytes,
        max_response_bytes: opt.max_response_bytes,
        passthrough_paths: opt.passthrough_path.clone(),
    }
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

/// Bind and serve `app` until the process exits.
async fn serve_router(app: axum::Router, listen: &str) -> anyhow::Result<()> {
    let listener = tokio::net::TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen}"))?;
    eprintln!("pasu-proxy listening on {listen}");
    // 종료 신호를 받으면 처리 중인 요청을 마친 뒤 닫는다. 중간에 끊으면
    // 에이전트가 절단된 응답을 받는다.
    axum::serve(listener, app)
        .with_graceful_shutdown(pasu_ui::shutdown::signal())
        .await
        .context("serve")?;
    Ok(())
}

/// Serve `judge` on the front-end the operator chose.
async fn serve_frontend<A>(opt: &Opt, judge: Judge<RulesetEngine, A>) -> anyhow::Result<()>
where
    A: Approver + Send + Sync + 'static,
{
    match opt.frontend {
        Frontend::Reverse => {
            let upstream = opt
                .upstream
                .clone()
                .context("--upstream is required with --frontend reverse")?;
            // 타임아웃이 없으면 응답하지 않는 업스트림이 요청을 무한히 붙잡고,
            // 커넥션이 쌓여 프록시가 가용성 병목이 된다. 다만 전체(total) 타임아웃은
            // 긴 생성·스트리밍을 잘라내므로 연결/유휴로 나눠 건다.
            let client = reqwest::Client::builder()
                .connect_timeout(Duration::from_secs(opt.connect_timeout_secs))
                .read_timeout(Duration::from_secs(opt.read_timeout_secs))
                .build()
                .context("build upstream HTTP client")?;
            eprintln!(
                "pasu-proxy -> upstream {upstream} (provider: {})",
                opt.provider
            );
            let state = Arc::new(ProxyState {
                judge,
                client,
                upstream_base: upstream,
            });
            serve_router(router(state), &opt.listen).await
        }
        Frontend::Litellm => {
            let api_key = std::env::var(GUARDRAIL_API_KEY_ENV)
                .ok()
                .filter(|k| !k.is_empty());
            if api_key.is_none() {
                eprintln!(
                    "pasu-proxy: {GUARDRAIL_API_KEY_ENV} is not set, so any caller that \
                     reaches this port can query decisions"
                );
            }
            eprintln!(
                "pasu-proxy: LiteLLM guardrail API at {}",
                pasu_proxy::litellm::LITELLM_GUARDRAIL_PATH
            );
            let state = Arc::new(GuardrailState { judge, api_key });
            serve_router(guardrail_router(state), &opt.listen).await
        }
        #[cfg(feature = "ext-proc")]
        Frontend::ExtProc => serve_ext_proc(judge, &opt.listen).await,
    }
}

/// Serve the ext_proc gRPC service until the process exits.
#[cfg(feature = "ext-proc")]
async fn serve_ext_proc<A>(judge: Judge<RulesetEngine, A>, listen: &str) -> anyhow::Result<()>
where
    A: Approver + Send + Sync + 'static,
{
    use pasu_proxy::ext_proc::{ExtProc, ExternalProcessorServer};
    let addr: SocketAddr = listen
        .parse()
        .with_context(|| format!("parse --listen {listen:?}"))?;
    eprintln!("pasu-proxy: Envoy ext_proc (gRPC) listening on {addr}");
    // Envoy must not fail open: its `failure_mode_allow` default (false) is
    // what makes an unreachable pasu a refusal rather than a pass.
    tonic::transport::Server::builder()
        .add_service(ExternalProcessorServer::new(ExtProc::new(Arc::new(judge))))
        .serve_with_shutdown(addr, pasu_ui::shutdown::signal())
        .await
        .context("serve ext_proc")
}

/// The front-end's configuration errors, found before anything listens.
fn check_frontend(opt: &Opt) -> anyhow::Result<()> {
    if opt.frontend == Frontend::Reverse && opt.upstream.is_none() {
        anyhow::bail!("--upstream is required with --frontend reverse");
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    check_frontend(&opt)?;
    let provider: Arc<dyn pasu_proxy::parse::WireFormat> = Arc::new(parse_provider(&opt.provider)?);
    let engine = load_engine(&opt.policy)?;
    // Built once, before anything listens: a rule file that cannot be honoured
    // must stop startup rather than be discovered on the first request.
    let chosen_inspectors = inspectors(&opt)?;
    let redaction = redaction_policy(&opt);
    let options = proxy_options(&opt);
    let layer = opt.frontend.layer();

    match opt.ui.clone() {
        // HITL: serve the approval UI and route `Ask` through it.
        Some(ui) => {
            let ui_addr: SocketAddr = ui.parse().with_context(|| format!("parse --ui {ui:?}"))?;
            let access = pasu_ui::Access::generate().context("UI access token")?;
            let approver = UiApprover::new();
            let approvals = approver.state();
            let feed = AuditFeed::new(AUDIT_FEED_CAP);
            let sink: Arc<dyn AuditSink> =
                Arc::new(TeeSink(vec![Arc::new(StderrAudit), Arc::new(feed.clone())]));
            let judge = Judge {
                guard: Guard::with_approver(engine, approver, layer).with_sink(sink),
                provider,
                inspectors: chosen_inspectors,
                redaction,
                options,
            };
            // The token is the only thing standing between the guarded agent
            // and its own approvals — it reaches loopback. Printed once, here.
            eprintln!(
                "pasu-proxy HITL approval UI on {}",
                access.login_url(ui_addr)
            );
            tokio::try_join!(serve_frontend(&opt, judge), async {
                pasu_ui::serve(ui_addr, approvals, feed, access)
                    .await
                    .context("serve ui")
            })?;
        }
        // No UI: `Ask` fails closed (DenyAll); decisions go to stderr JSONL.
        None => {
            let judge = Judge {
                guard: Guard::new(engine, layer).with_sink(Arc::new(StderrAudit)),
                provider,
                inspectors: chosen_inspectors,
                redaction,
                options,
            };
            serve_frontend(&opt, judge).await?;
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
