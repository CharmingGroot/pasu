//! pasu-rig — rig framework integration (the cooperative, in-process layer).
//!
//! Implements rig's hook points so a rig agent is guarded by default:
//!   - `AgentHook`     — tool-call gate (this module; HITL approval next).
//!   - `HttpClientExt` — LLM egress guard (planned).
//!
//! Decisions go through `RuleEngine` and map to `pasu_core::Verdict`. This is
//! the *cooperative* layer: it sees tool_name/args, but not arbitrary code a
//! tool runs internally. The kernel eBPF egress guard (pasu-egress / pasu-ebpf)
//! is the *enforcing* backstop. Design: docs/rig-integration.md
//!
//! rig is the only crate allowed to depend on `rig`; pasu-core stays pure so the
//! engine can later gain adapters for other agent frameworks.

use pasu_core::{Event, EventKind, RuleEngine, Verdict};
use rig::agent::{AgentHook, Flow, StepEvent};
use rig::completion::CompletionModel;

/// Guards a rig agent's tool calls through a [`RuleEngine`].
///
/// On each tool call the hook builds an [`Event::ToolCall`], evaluates it, and
/// maps the [`Verdict`] to a rig [`Flow`]:
/// - `Allow` → continue
/// - `Deny`  → skip (block) with the reason
/// - `Ask`   → skip (fail-closed) until a human-approval path is wired in
///
/// `enabled` is the runtime toggle (build-time separation stays at the crate level).
pub struct PasuSecurityHook<E: RuleEngine> {
    engine: E,
    enabled: bool,
}

impl<E: RuleEngine> PasuSecurityHook<E> {
    /// Enabled hook backed by `engine`.
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            enabled: true,
        }
    }

    /// Runtime toggle. When disabled the hook passes everything through.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl<M, E> AgentHook<M> for PasuSecurityHook<E>
where
    M: CompletionModel,
    E: RuleEngine + Send + Sync,
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

        match self.engine.evaluate(&event) {
            Verdict::Allow => Flow::cont(),
            Verdict::Deny(reason) => Flow::skip(reason),
            // HITL not wired yet — fail-closed (deny) until an approval path lands.
            Verdict::Ask(reason) => {
                Flow::skip(format!("approval required (fail-closed): {reason}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// Run a single `net_call` tool turn under a hook with `verdict`; return how
    /// many times the tool actually executed.
    async fn tool_runs_under(verdict: Verdict) -> usize {
        let hits = Arc::new(AtomicUsize::new(0));
        let model = MockCompletionModel::new([
            MockTurn::tool_call("c1", "net_call", json!({})),
            MockTurn::text("done"),
        ]);
        let agent = AgentBuilder::new(model)
            .preamble("test agent")
            .tool(CountTool { hits: hits.clone() })
            .build();

        let hook = PasuSecurityHook::new(FixedEngine(verdict));
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
        // TP-inverse: a permitted tool executes.
        assert_eq!(tool_runs_under(Verdict::Allow).await, 1);
    }

    #[tokio::test]
    async fn deny_blocks_tool() {
        // TP: a denied tool never executes.
        assert_eq!(tool_runs_under(Verdict::Deny("nope".into())).await, 0);
    }

    #[tokio::test]
    async fn ask_is_fail_closed() {
        // Until HITL is wired, Ask must block (no bypass).
        assert_eq!(tool_runs_under(Verdict::Ask("confirm".into())).await, 0);
    }
}
