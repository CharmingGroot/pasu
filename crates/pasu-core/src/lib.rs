//! pasu-core — shared types and the layer / rule-engine interfaces (traits).
//!
//! Implementations (Falco, eBPF, socket) all live behind these traits. This
//! crate depends on nothing (pure); other crates depend only on core (acyclic).
//! Design: docs/repo-structure.md

use serde::Serialize;

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

/// Human-in-the-loop approval for `Verdict::Ask`. Returns `true` to allow the
/// action, `false` to block it. **Fail-closed by contract**: on any doubt (a
/// closed channel, a timeout, an error), return false.
///
/// Lives in core so both the rig hook (pasu-rig) and UI-backed approvers
/// (pasu-ui) implement the same trait.
pub trait Approver: Send + Sync {
    fn approve(&self, reason: &str) -> impl core::future::Future<Output = bool> + Send;
}

/// Default approver: denies every `Ask` (fail-closed).
pub struct DenyAll;

impl Approver for DenyAll {
    fn approve(&self, _reason: &str) -> impl core::future::Future<Output = bool> + Send {
        core::future::ready(false)
    }
}

/// The verdict variant without its reason payload (reason is a sibling field).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VerdictKind {
    Allow,
    Deny,
    Ask,
}

/// A decision flattened for audit logging, built from an [`Event`] + [`Verdict`]
/// by the layer that made the call. Serializable (JSONL, SIEM, UI stream).
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// Which layer decided: e.g. "rig-tool", "rig-egress", "egress".
    pub layer: String,
    /// What was evaluated: a tool name, or "host:port".
    pub subject: String,
    /// The outcome.
    pub verdict: VerdictKind,
    /// Reason for deny/ask (None for allow).
    pub reason: Option<String>,
}

impl AuditRecord {
    /// Flatten an evaluated event into an audit record.
    pub fn new(layer: &str, event: &Event, verdict: &Verdict) -> Self {
        let subject = match &event.kind {
            EventKind::ToolCall { name, .. } => name.clone(),
            EventKind::Egress { host, port } => format!("{host}:{port}"),
        };
        let (verdict, reason) = match verdict {
            Verdict::Allow => (VerdictKind::Allow, None),
            Verdict::Deny(r) => (VerdictKind::Deny, Some(r.clone())),
            Verdict::Ask(r) => (VerdictKind::Ask, Some(r.clone())),
        };
        Self {
            layer: layer.to_string(),
            subject,
            verdict,
            reason,
        }
    }
}

/// Sink for audit records — stderr (JSONL), a channel, a file, etc. Kept in core
/// so any layer can emit without depending on a concrete sink implementation.
pub trait AuditSink: Send + Sync {
    fn record(&self, record: &AuditRecord);
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

    #[test]
    fn deny_over_deny_keeps_the_first_reason() {
        // Two blocks: keep the left (first-seen) reason deterministically.
        assert_eq!(
            Verdict::Deny("first".into()).escalate(Verdict::Deny("second".into())),
            Verdict::Deny("first".into())
        );
    }

    #[test]
    fn deny_beats_ask_preserves_deny_reason_either_order() {
        assert_eq!(
            Verdict::Deny("d".into()).escalate(Verdict::Ask("a".into())),
            Verdict::Deny("d".into())
        );
        assert_eq!(
            Verdict::Ask("a".into()).escalate(Verdict::Deny("d".into())),
            Verdict::Deny("d".into())
        );
    }

    #[test]
    fn ask_over_ask_keeps_the_first_reason() {
        assert_eq!(
            Verdict::Ask("first".into()).escalate(Verdict::Ask("second".into())),
            Verdict::Ask("first".into())
        );
    }

    #[test]
    fn escalate_is_associative_for_mixed_verdicts() {
        // deny must win regardless of grouping.
        let a = Verdict::Allow;
        let b = Verdict::Ask("a".into());
        let c = Verdict::Deny("d".into());
        let left = a.clone().escalate(b.clone()).escalate(c.clone());
        let right = a.escalate(b.escalate(c));
        assert_eq!(left, Verdict::Deny("d".into()));
        assert_eq!(left, right);
    }

    #[test]
    fn audit_record_flattens_tool_deny() {
        let ev = Event {
            kind: EventKind::ToolCall {
                name: "rm_rf".into(),
                input: "{}".into(),
            },
        };
        let rec = AuditRecord::new("rig-tool", &ev, &Verdict::Deny("destructive".into()));
        assert_eq!(rec.layer, "rig-tool");
        assert_eq!(rec.subject, "rm_rf");
        assert_eq!(rec.verdict, VerdictKind::Deny);
        assert_eq!(rec.reason.as_deref(), Some("destructive"));
    }

    #[test]
    fn audit_record_flattens_egress_allow() {
        let ev = Event {
            kind: EventKind::Egress {
                host: "api.openai.com".into(),
                port: 443,
            },
        };
        let rec = AuditRecord::new("egress", &ev, &Verdict::Allow);
        assert_eq!(rec.subject, "api.openai.com:443");
        assert_eq!(rec.verdict, VerdictKind::Allow);
        assert!(rec.reason.is_none());
    }
}
