//! pasu-core — shared types and the layer / rule-engine interfaces (traits).
//!
//! Implementations (Falco, eBPF, socket) all live behind these traits. This
//! crate depends on nothing (pure); other crates depend only on core (acyclic).
//! Design: docs/repo-structure.md

// 프로덕션 빌드에는 unsafe 가 필요 없다. 선언해 두면 향후 유입을 컴파일 타임에 막는다.
// 테스트에서만 예외인 이유: Approver 퓨처를 런타임 없이 폴링하려고 수동 Waker 를
// 만드는데, 여기에 unsafe 가 불가피하다. forbid 는 국소 예외를 허용하지 않으므로
// not(test) 로 범위를 좁힌다.
#![cfg_attr(not(test), forbid(unsafe_code))]
// 공개 API 문서 누락을 조용히 통과시키지 않는다(crates.io 배포 대상).
#![warn(missing_docs)]
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

pub mod redact;

/// An action the agent wants to take. Layers evaluate this event.
#[derive(Debug, Clone)]
pub struct Event {
    /// 무엇을 하려는 행동인지.
    pub kind: EventKind,
}

/// The kind of action, with the fields each layer needs to judge it.
#[derive(Debug, Clone)]
pub enum EventKind {
    /// LLM-API proxy (parsed tool_call) — a tool call.
    ToolCall {
        /// Tool name as the model asked for it.
        name: String,
        /// Raw arguments, serialized as a JSON string.
        input: String,
    },
    /// eBPF / proxy — outbound network.
    Egress {
        /// Destination host (or literal address).
        host: String,
        /// Destination port.
        port: u16,
    },
}

/// Rule engine interface. The initial implementation borrows Falco rules
/// (pasu-rules). Swappable later for OPA / a custom DSL — callers see only this trait.
pub trait RuleEngine {
    /// Judge one event against the ruleset.
    fn evaluate(&self, event: &Event) -> Verdict;
}

/// Common interface for layers (LLM-API proxy / egress / eBPF). Runtime-toggleable.
pub trait Layer {
    /// Layer name, as it appears in audit records.
    fn name(&self) -> &str;
    /// Whether this layer is active. A disabled layer allows everything.
    fn enabled(&self) -> bool;
    /// Evaluate an event in this layer.
    fn check(&self, event: &Event) -> Verdict;
}

/// One thing an [`Inspector`] found in a piece of text, and where.
///
/// **It never carries the matched value.** An inspector that reported what it
/// caught would put the secret into the block message, the audit log and the
/// operator's terminal — the leak it exists to prevent. The span is enough to
/// redact or to point a human at, and it is enough for nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// Which inspector found it, as it appears in audit records.
    pub inspector: String,
    /// The inspector's own rule or entity id — `ko-rrn`, `US_SSN`, `aws-key`.
    pub rule: String,
    /// Byte range in the text that was inspected.
    pub span: core::ops::Range<usize>,
}

/// Something that reads text on its way past a layer and says what it found.
///
/// This is the extension point for content checks — PII, secrets, whatever a
/// deployment needs — so that adding one does not mean editing a layer. A
/// Korean-PII matcher, a scanner speaking to a Presidio server, and an
/// in-house rule set are all the same shape here.
///
/// # Finding, not deciding
///
/// An inspector returns findings and stops. It does not block, mask, or judge:
/// the layer holding it decides what a finding means, and the same finding may
/// warrant a refusal on a request and a redaction on a response.
///
/// Keeping those apart is what makes masking possible later without changing
/// this trait — an inspector that had answered "allow or deny" would have
/// thrown away the spans a redactor needs.
///
/// # Contract
///
/// * **Linear time.** An inspector runs on every message through a layer.
///   Backtracking regexes belong nowhere near it.
/// * **No I/O on this call** unless the deployment chose an inspector that does
///   it knowingly — a network round trip per message is a decision, not a
///   detail.
/// * **Empty means nothing found**, never "could not tell". An inspector that
///   cannot answer must say so by failing to construct, not by returning clean.
pub trait Inspector: Send + Sync {
    /// Name, as it appears in audit records and refusal messages.
    fn name(&self) -> &str;
    /// Everything found in `text`, in the order it appears.
    fn inspect(&self, text: &str) -> Vec<Finding>;
}

/// Human-in-the-loop approval for `Verdict::Ask`. Returns `true` to allow the
/// action, `false` to block it. **Fail-closed by contract**: on any doubt (a
/// closed channel, a timeout, an error), return false.
///
/// Lives in core so both the LLM-API proxy (pasu-proxy) and UI-backed approvers
/// (pasu-ui) implement the same trait.
pub trait Approver: Send + Sync {
    /// Ask a human. `true` allows the action; anything else must deny.
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
    /// Allowed.
    Allow,
    /// Blocked.
    Deny,
    /// Held for human approval.
    Ask,
}

/// A decision flattened for audit logging, built from an [`Event`] + [`Verdict`]
/// by the layer that made the call. Serializable (JSONL, SIEM, UI stream).
#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    /// Which layer decided: e.g. "proxy-tool", "egress".
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
    /// Write one decision. Must not block the guard path.
    fn record(&self, record: &AuditRecord);
}

/// The guard core: the one place that turns an [`Event`] into a final
/// [`Verdict`] — evaluate → audit → resolve `Ask` via the [`Approver`].
///
/// This is the framework-agnostic **port** every adapter calls. The LLM-API
/// proxy, a Python client over the wire, or any future adapter maps its native event
/// onto [`Event`] and calls [`Guard::decide`]; none of them re-implement the
/// evaluate/HITL/audit orchestration. Keeping it here (not in an adapter) is
/// what makes new frameworks a thin translation layer.
pub struct Guard<E: RuleEngine, A: Approver = DenyAll> {
    engine: E,
    approver: A,
    sink: Option<std::sync::Arc<dyn AuditSink>>,
    enabled: bool,
    layer: String,
}

impl<E: RuleEngine> Guard<E, DenyAll> {
    /// A guard backed by `engine`. `Ask` is denied (fail-closed) until an
    /// approver is supplied. `layer` labels emitted audit records.
    pub fn new(engine: E, layer: impl Into<String>) -> Self {
        Self {
            engine,
            approver: DenyAll,
            sink: None,
            enabled: true,
            layer: layer.into(),
        }
    }
}

impl<E: RuleEngine, A: Approver> Guard<E, A> {
    /// A guard with a human-approval path for `Ask` verdicts.
    pub fn with_approver(engine: E, approver: A, layer: impl Into<String>) -> Self {
        Self {
            engine,
            approver,
            sink: None,
            enabled: true,
            layer: layer.into(),
        }
    }

    /// Record every decision to `sink`.
    pub fn with_sink(mut self, sink: std::sync::Arc<dyn AuditSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Runtime toggle. When disabled, `decide` allows everything.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    /// Whether the guard is active. A disabled guard allows everything.
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Decide an event: evaluate the policy, record it, and resolve `Ask`
    /// through the approver (approved → `Allow`, else fail-closed `Deny`).
    /// The returned verdict is final — callers only see `Allow` / `Deny`.
    pub async fn decide(&self, event: &Event) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        let verdict = self.engine.evaluate(event);
        if let Some(sink) = &self.sink {
            sink.record(&AuditRecord::new(&self.layer, event, &verdict));
        }
        match verdict {
            Verdict::Ask(reason) => {
                if self.approver.approve(&reason).await {
                    Verdict::Allow
                } else {
                    Verdict::Deny(format!("denied by approver (HITL): {reason}"))
                }
            }
            other => other,
        }
    }
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
        let rec = AuditRecord::new("proxy-tool", &ev, &Verdict::Deny("destructive".into()));
        assert_eq!(rec.layer, "proxy-tool");
        assert_eq!(rec.subject, "rm_rf");
        assert_eq!(rec.verdict, VerdictKind::Deny);
        assert_eq!(rec.reason.as_deref(), Some("destructive"));
    }

    struct FixedEngine(Verdict);
    impl RuleEngine for FixedEngine {
        fn evaluate(&self, _e: &Event) -> Verdict {
            self.0.clone()
        }
    }
    struct YesApprover;
    impl Approver for YesApprover {
        fn approve(&self, _r: &str) -> impl core::future::Future<Output = bool> + Send {
            core::future::ready(true)
        }
    }
    fn tool_event() -> Event {
        Event {
            kind: EventKind::ToolCall {
                name: "t".into(),
                input: "{}".into(),
            },
        }
    }
    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        // minimal executor for the async decide() in a sync test
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
        fn noop(_: *const ()) {}
        fn clone(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VT)
        }
        static VT: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VT)) };
        let mut cx = Context::from_waker(&waker);
        let mut f = core::pin::pin!(f);
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    #[test]
    fn guard_allow_passes_and_deny_blocks() {
        let g = Guard::new(FixedEngine(Verdict::Allow), "test");
        assert_eq!(block_on(g.decide(&tool_event())), Verdict::Allow);
        let g = Guard::new(FixedEngine(Verdict::Deny("no".into())), "test");
        assert_eq!(
            block_on(g.decide(&tool_event())),
            Verdict::Deny("no".into())
        );
    }

    #[test]
    fn guard_ask_fails_closed_then_opens_with_approver() {
        let g = Guard::new(FixedEngine(Verdict::Ask("c".into())), "test");
        assert!(matches!(
            block_on(g.decide(&tool_event())),
            Verdict::Deny(_)
        )); // DenyAll
        let g = Guard::with_approver(FixedEngine(Verdict::Ask("c".into())), YesApprover, "test");
        assert_eq!(block_on(g.decide(&tool_event())), Verdict::Allow);
    }

    #[test]
    fn guard_disabled_allows_everything() {
        let mut g = Guard::new(FixedEngine(Verdict::Deny("no".into())), "test");
        g.set_enabled(false);
        assert_eq!(block_on(g.decide(&tool_event())), Verdict::Allow);
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
