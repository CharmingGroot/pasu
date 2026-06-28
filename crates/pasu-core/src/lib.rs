//! pasu-core — shared types and the layer / rule-engine interfaces (traits).
//!
//! Implementations (Falco, eBPF, socket) all live behind these traits. This
//! crate depends on nothing (pure); other crates depend only on core (acyclic).
//! Design: docs/repo-structure.md

/// A policy decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Allow.
    Allow,
    /// Block, with a reason.
    Deny(String),
    /// Ask the user for confirmation, with a reason.
    Ask(String),
}

/// An action the agent wants to take. Layers evaluate this event.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    /// rig AgentHook — a tool call.
    ToolCall { name: String, input: String },
    /// rig HttpClientExt / eBPF — outbound network.
    Egress { host: String, port: u16 },
}

/// Rule engine interface. The initial implementation borrows Falco rules
/// (pasu-rules). Swappable later for OPA / a custom DSL — callers see only this trait.
pub trait RuleEngine {
    fn evaluate(&self, event: &Event) -> Verdict;
}

/// Common interface for layers (rig integration / egress / eBPF). Runtime-toggleable.
pub trait Layer {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    fn check(&self, event: &Event) -> Verdict;
}

impl Verdict {
    /// Escalate to the more restrictive verdict: deny > ask > allow.
    /// When several layers/rules match, pick the strongest block.
    pub fn escalate(self, other: Verdict) -> Verdict {
        match (&self, &other) {
            (Verdict::Deny(_), _) => self,
            (_, Verdict::Deny(_)) => other,
            (Verdict::Ask(_), _) => self,
            (_, Verdict::Ask(_)) => other,
            _ => self,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_beats_ask_and_allow_either_order() {
        assert_eq!(
            Verdict::Allow.escalate(Verdict::Deny("x".into())),
            Verdict::Deny("x".into())
        );
        assert_eq!(
            Verdict::Deny("x".into()).escalate(Verdict::Allow),
            Verdict::Deny("x".into())
        );
        assert_eq!(
            Verdict::Ask("a".into()).escalate(Verdict::Deny("d".into())),
            Verdict::Deny("d".into())
        );
    }

    #[test]
    fn ask_beats_allow_either_order() {
        assert_eq!(
            Verdict::Allow.escalate(Verdict::Ask("a".into())),
            Verdict::Ask("a".into())
        );
        assert_eq!(
            Verdict::Ask("a".into()).escalate(Verdict::Allow),
            Verdict::Ask("a".into())
        );
    }

    #[test]
    fn allow_stays_allow() {
        assert_eq!(Verdict::Allow.escalate(Verdict::Allow), Verdict::Allow);
    }
}
