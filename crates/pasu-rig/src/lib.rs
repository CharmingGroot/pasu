//! pasu-rig — rig framework integration (the cooperative, in-process layer).
//!
//! Implements rig's hook points so a rig agent is guarded by default:
//!   - `AgentHook`     — tool-call gate + HITL approval (this module).
//!   - LLM egress       — [`PasuEgressMiddleware`] (the `egress` module).
//!
//! Decisions go through `RuleEngine` and map to `pasu_core::Verdict`. This is
//! the *cooperative* layer: it sees tool_name/args and declared egress, but not
//! arbitrary code a tool runs internally. The kernel eBPF egress guard
//! (pasu-egress / pasu-ebpf) is the *enforcing* backstop. Design: docs/rig-integration.md
//!
//! rig is the only crate allowed to depend on `rig`; pasu-core stays pure so the
//! engine can later gain adapters for other agent frameworks.

mod egress;
pub use egress::PasuEgressMiddleware;

use std::sync::Arc;

use pasu_core::{AuditRecord, AuditSink, Event, EventKind, RuleEngine, Verdict};
use rig::agent::{AgentHook, Flow, StepEvent};
use rig::completion::CompletionModel;

// Approver / DenyAll now live in pasu-core (shared with pasu-ui). Re-export so
// existing `pasu_rig::{Approver, DenyAll}` callers keep working; this also brings
// Approver into scope for the trait bounds below.
pub use pasu_core::{Approver, DenyAll};

/// Guards a rig agent's tool calls through a [`RuleEngine`], with an optional
/// human-approval path for `Ask`.
///
/// On each tool call the hook builds an [`Event::ToolCall`], evaluates it, and
/// maps the [`Verdict`] to a rig [`Flow`]:
/// - `Allow` → continue
/// - `Deny`  → skip (block) with the reason
/// - `Ask`   → ask the [`Approver`]; approved → continue, otherwise skip (fail-closed)
///
/// `enabled` is the runtime toggle (build-time separation stays at the crate level).
pub struct PasuSecurityHook<E: RuleEngine, A: Approver = DenyAll> {
    engine: E,
    approver: A,
    enabled: bool,
    sink: Option<Arc<dyn AuditSink>>,
}

impl<E: RuleEngine> PasuSecurityHook<E, DenyAll> {
    /// Enabled hook backed by `engine`. `Ask` verdicts are denied (fail-closed)
    /// until an approver is supplied via [`Self::with_approver`].
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            approver: DenyAll,
            enabled: true,
            sink: None,
        }
    }
}

impl<E: RuleEngine, A: Approver> PasuSecurityHook<E, A> {
    /// Enabled hook with a human-approval path for `Ask` verdicts.
    pub fn with_approver(engine: E, approver: A) -> Self {
        Self {
            engine,
            approver,
            enabled: true,
            sink: None,
        }
    }

    /// Attach an audit sink; every tool-call decision is recorded (layer "rig-tool").
    pub fn with_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Runtime toggle. When disabled the hook passes everything through.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl<M, E, A> AgentHook<M> for PasuSecurityHook<E, A>
where
    M: CompletionModel,
    E: RuleEngine + Send + Sync,
    A: Approver,
{
    async fn on_event(&self, event: StepEvent<'_, M>) -> Flow {
        if !self.enabled {
            return Flow::cont();
        }
        let StepEvent::ToolCall {
            tool_name, args, ..
        } = event
        else {
            return Flow::cont();
        };

        let event = Event {
            kind: EventKind::ToolCall {
                name: tool_name.to_string(),
                input: args.to_string(),
            },
        };

        let verdict = self.engine.evaluate(&event);
        if let Some(sink) = &self.sink {
            sink.record(&AuditRecord::new("rig-tool", &event, &verdict));
        }

        match verdict {
            Verdict::Allow => Flow::cont(),
            Verdict::Deny(reason) => Flow::skip(reason),
            Verdict::Ask(reason) => {
                if self.approver.approve(&reason).await {
                    Flow::cont()
                } else {
                    Flow::skip(format!("denied by approver (HITL): {reason}"))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    use rig::agent::AgentBuilder;
    use rig::completion::{Prompt, ToolDefinition};
    use rig::test_utils::{MockCompletionModel, MockTurn};
    use rig::tool::Tool;
    use serde_json::json;

    /// RuleEngine that always returns a fixed verdict (test fixture).
    struct FixedEngine(Verdict);
    impl RuleEngine for FixedEngine {
        fn evaluate(&self, _event: &Event) -> Verdict {
            self.0.clone()
        }
    }

    /// Approver that always approves (test fixture for the HITL allow path).
    struct AlwaysApprove;
    impl Approver for AlwaysApprove {
        fn approve(&self, _reason: &str) -> impl Future<Output = bool> + Send {
            std::future::ready(true)
        }
    }

    /// Tool that counts how many times it actually executed.
    #[derive(Clone, serde::Deserialize, serde::Serialize)]
    struct CountTool {
        #[serde(skip)]
        hits: Arc<AtomicUsize>,
    }
    impl Tool for CountTool {
        const NAME: &'static str = "net_call";
        type Error = std::convert::Infallible;
        type Args = serde_json::Value;
        type Output = String;
        async fn definition(&self, _: String) -> ToolDefinition {
            ToolDefinition {
                name: Self::NAME.into(),
                description: "side-effecting call".into(),
                parameters: json!({"type":"object"}),
            }
        }
        async fn call(&self, _: Self::Args) -> Result<Self::Output, Self::Error> {
            self.hits.fetch_add(1, Ordering::SeqCst);
            Ok("ran".into())
        }
    }

    /// Run a single `net_call` tool turn under a hook built from `verdict` +
    /// `approver`; return how many times the tool actually executed.
    async fn tool_runs<A: Approver + 'static>(verdict: Verdict, approver: A) -> usize {
        let hits = Arc::new(AtomicUsize::new(0));
        let model = MockCompletionModel::new([
            MockTurn::tool_call("c1", "net_call", json!({})),
            MockTurn::text("done"),
        ]);
        let agent = AgentBuilder::new(model)
            .preamble("test agent")
            .tool(CountTool { hits: hits.clone() })
            .build();

        let hook = PasuSecurityHook::with_approver(FixedEngine(verdict), approver);
        agent
            .prompt("go")
            .max_turns(4)
            .add_hook(hook)
            .await
            .expect("prompt completes (skip is a normal flow)");

        hits.load(Ordering::SeqCst)
    }

    #[tokio::test]
    async fn allow_lets_tool_run() {
        assert_eq!(tool_runs(Verdict::Allow, DenyAll).await, 1);
    }

    #[tokio::test]
    async fn deny_blocks_tool() {
        // TP: a denied tool never executes.
        assert_eq!(tool_runs(Verdict::Deny("nope".into()), DenyAll).await, 0);
    }

    #[tokio::test]
    async fn ask_fails_closed_by_default() {
        // DenyAll (and PasuSecurityHook::new) must block Ask — no bypass.
        assert_eq!(tool_runs(Verdict::Ask("confirm".into()), DenyAll).await, 0);
    }

    #[tokio::test]
    async fn ask_runs_when_approved() {
        // HITL: an approved Ask lets the tool run.
        assert_eq!(
            tool_runs(Verdict::Ask("confirm".into()), AlwaysApprove).await,
            1
        );
    }

    #[tokio::test]
    async fn new_defaults_to_deny_all() {
        // The convenience constructor must be fail-closed for Ask.
        let hits = Arc::new(AtomicUsize::new(0));
        let model = MockCompletionModel::new([
            MockTurn::tool_call("c1", "net_call", json!({})),
            MockTurn::text("done"),
        ]);
        let agent = AgentBuilder::new(model)
            .preamble("test agent")
            .tool(CountTool { hits: hits.clone() })
            .build();
        let hook = PasuSecurityHook::new(FixedEngine(Verdict::Ask("x".into())));
        agent
            .prompt("go")
            .max_turns(4)
            .add_hook(hook)
            .await
            .expect("prompt completes");
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// Approver that records each reason it is asked about, then approves.
    struct RecordingApprover(Arc<std::sync::Mutex<Vec<String>>>);
    impl Approver for RecordingApprover {
        fn approve(&self, reason: &str) -> impl Future<Output = bool> + Send {
            self.0.lock().unwrap().push(reason.to_string());
            std::future::ready(true)
        }
    }

    #[tokio::test]
    async fn approver_receives_the_ask_reason() {
        // The reason carried by Verdict::Ask must reach the approver verbatim.
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let ran = tool_runs(
            Verdict::Ask("please confirm".into()),
            RecordingApprover(log.clone()),
        )
        .await;
        assert_eq!(ran, 1, "an approved Ask runs the tool");
        assert_eq!(
            log.lock().unwrap().as_slice(),
            &["please confirm".to_string()]
        );
    }

    #[tokio::test]
    async fn disabled_hook_runs_even_denied_tools() {
        // The runtime toggle must short-circuit before any policy check.
        let hits = Arc::new(AtomicUsize::new(0));
        let model = MockCompletionModel::new([
            MockTurn::tool_call("c1", "net_call", json!({})),
            MockTurn::text("done"),
        ]);
        let agent = AgentBuilder::new(model)
            .preamble("test agent")
            .tool(CountTool { hits: hits.clone() })
            .build();
        let mut hook = PasuSecurityHook::new(FixedEngine(Verdict::Deny("blocked".into())));
        hook.set_enabled(false);
        agent
            .prompt("go")
            .max_turns(4)
            .add_hook(hook)
            .await
            .expect("prompt completes");
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "disabled hook forwards everything"
        );
    }

    #[tokio::test]
    async fn records_decision_to_audit_sink() {
        let sink = Arc::new(pasu_audit::MemorySink::default());
        let hits = Arc::new(AtomicUsize::new(0));
        let model = MockCompletionModel::new([
            MockTurn::tool_call("c1", "net_call", json!({})),
            MockTurn::text("done"),
        ]);
        let agent = AgentBuilder::new(model)
            .preamble("test agent")
            .tool(CountTool { hits: hits.clone() })
            .build();
        let hook = PasuSecurityHook::new(FixedEngine(Verdict::Deny("blocked".into())))
            .with_sink(sink.clone());
        agent
            .prompt("go")
            .max_turns(4)
            .add_hook(hook)
            .await
            .expect("prompt completes");

        let recs = sink.records();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].layer, "rig-tool");
        assert_eq!(recs[0].subject, "net_call");
        assert_eq!(recs[0].verdict, pasu_core::VerdictKind::Deny);
    }
}
