//! Turn parsed tool calls into a policy decision via the pasu-core [`Guard`].
//!
//! Each proposed tool call becomes an [`Event::ToolCall`]; the [`Guard`]
//! evaluates it (policy → audit → HITL, fail-closed). The strongest verdict
//! wins (deny > allow) so one denied call blocks the response.
//!
//! [`Guard`]: pasu_core::Guard

use pasu_core::{Approver, Event, EventKind, Guard, RuleEngine, Verdict};

use crate::parse::ToolCall;

/// Per-call verdicts plus the aggregate decision for the whole response.
#[derive(Debug)]
pub struct Inspection {
    /// `(tool name, final verdict)` for each proposed call, in order.
    pub per_call: Vec<(String, Verdict)>,
    /// Escalated verdict across all calls (deny wins). `Allow` when empty.
    pub overall: Verdict,
}

impl Inspection {
    /// Whether the response must be blocked (any call denied).
    #[must_use]
    pub fn is_blocked(&self) -> bool {
        matches!(self.overall, Verdict::Deny(_))
    }

    /// Names of the calls that were denied.
    pub fn denied_calls(&self) -> impl Iterator<Item = &str> {
        self.per_call
            .iter()
            .filter(|(_, v)| matches!(v, Verdict::Deny(_)))
            .map(|(name, _)| name.as_str())
    }
}

/// Evaluate each tool call through the guard. `Ask` is resolved by the guard's
/// approver (fail-closed). Empty input yields `Allow` (nothing to guard).
pub async fn inspect<E, A>(guard: &Guard<E, A>, calls: &[ToolCall]) -> Inspection
where
    E: RuleEngine,
    A: Approver,
{
    let mut per_call = Vec::with_capacity(calls.len());
    let mut overall = Verdict::Allow;
    for call in calls {
        let event = Event {
            kind: EventKind::ToolCall {
                name: call.name.clone(),
                input: call.arguments.clone(),
            },
        };
        let verdict = guard.decide(&event).await;
        overall = overall.escalate(verdict.clone());
        per_call.push((call.name.clone(), verdict));
    }
    Inspection { per_call, overall }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasu_rules::RulesetEngine;

    // A production-shaped ruleset: allow a safe tool, deny a destructive one,
    // everything else denied by default (fail-closed).
    const RULES: &str = r#"
rules:
  - name: allow-search
    match: { tool: web_search }
    action: allow
  - name: deny-delete
    match: { tool: delete_file }
    action: deny
    reason: destructive filesystem tool
default: deny
"#;

    fn guard() -> Guard<RulesetEngine> {
        Guard::new(
            RulesetEngine::from_yaml(RULES).expect("valid ruleset"),
            "llm-proxy",
        )
    }

    fn call(name: &str) -> ToolCall {
        ToolCall {
            name: name.to_string(),
            arguments: "{}".to_string(),
        }
    }

    #[tokio::test]
    async fn true_positive_denied_tool_blocks() {
        let r = inspect(&guard(), &[call("delete_file")]).await;
        assert!(r.is_blocked());
        assert_eq!(r.denied_calls().collect::<Vec<_>>(), ["delete_file"]);
    }

    #[tokio::test]
    async fn true_negative_allowed_tool_passes() {
        let r = inspect(&guard(), &[call("web_search")]).await;
        assert!(!r.is_blocked());
    }

    #[tokio::test]
    async fn unknown_tool_fails_closed_by_default() {
        // Not in the ruleset → default deny.
        let r = inspect(&guard(), &[call("exfiltrate")]).await;
        assert!(r.is_blocked());
    }

    #[tokio::test]
    async fn one_denied_among_many_blocks_the_whole_response() {
        let calls = [call("web_search"), call("delete_file")];
        let r = inspect(&guard(), &calls).await;
        assert!(r.is_blocked());
        assert_eq!(r.denied_calls().collect::<Vec<_>>(), ["delete_file"]);
    }

    #[tokio::test]
    async fn no_calls_is_allow() {
        let r = inspect(&guard(), &[]).await;
        assert!(!r.is_blocked());
        assert_eq!(r.overall, Verdict::Allow);
    }
}
