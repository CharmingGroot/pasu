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

/// An address range: an address plus a prefix length (`10.0.0.0/8`, `1.1.1.1`).
///
/// A bare address parses as a host route (`/32` for v4, `/128` for v6), so
/// exact entries and ranges share one type.
///
/// Lives in core because both the rule engine (which lowers policy) and the
/// egress guard (which injects into the kernel) need it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: core::net::IpAddr,
    prefix_len: u8,
}

impl Cidr {
    /// Build from an address and prefix length.
    ///
    /// # Errors
    /// The prefix length must fit the family (≤32 for v4, ≤128 for v6).
    pub fn new(addr: core::net::IpAddr, prefix_len: u8) -> Result<Self, CidrError> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix_len > max {
            return Err(CidrError::PrefixTooLong { prefix_len, max });
        }
        Ok(Self { addr, prefix_len })
    }

    /// The address, with host bits as written (not masked).
    #[must_use]
    pub fn addr(&self) -> core::net::IpAddr {
        self.addr
    }

    /// Prefix length in bits.
    #[must_use]
    pub fn prefix_len(&self) -> u8 {
        self.prefix_len
    }

    /// Is this a single host (`/32` or `/128`)?
    #[must_use]
    pub fn is_host(&self) -> bool {
        self.prefix_len == if self.addr.is_ipv4() { 32 } else { 128 }
    }

    /// The network address in **network byte order**, with host bits cleared.
    ///
    /// Kernel LPM tries compare keys byte-wise from the most significant bit,
    /// so the key must be big-endian and must not carry host bits — otherwise
    /// `10.1.2.3/8` and `10.0.0.0/8` would be different keys for the same range.
    #[must_use]
    pub fn network_bytes(&self) -> CidrBytes {
        match self.addr {
            core::net::IpAddr::V4(v4) => {
                let mut b = v4.octets();
                mask_bytes(&mut b, self.prefix_len);
                CidrBytes::V4(b)
            }
            core::net::IpAddr::V6(v6) => {
                let mut b = v6.octets();
                mask_bytes(&mut b, self.prefix_len);
                CidrBytes::V6(b)
            }
        }
    }
}

/// Network-order bytes of a [`Cidr`], per family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CidrBytes {
    /// IPv4, 4 bytes.
    V4([u8; 4]),
    /// IPv6, 16 bytes.
    V6([u8; 16]),
}

/// Clear every bit past `prefix_len`.
fn mask_bytes(bytes: &mut [u8], prefix_len: u8) {
    let keep = usize::from(prefix_len);
    for (i, b) in bytes.iter_mut().enumerate() {
        let bit_start = i * 8;
        if bit_start >= keep {
            *b = 0;
        } else if bit_start + 8 > keep {
            let keep_bits = keep - bit_start;
            *b &= 0xffu8 << (8 - keep_bits);
        }
    }
}

/// Why a CIDR string could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CidrError {
    /// The address part is not a valid IP address.
    BadAddress(String),
    /// The prefix part is not a number.
    BadPrefix(String),
    /// The prefix length exceeds what the family allows.
    PrefixTooLong {
        /// The prefix length that was given.
        prefix_len: u8,
        /// The maximum for this family (32 or 128).
        max: u8,
    },
}

impl core::fmt::Display for CidrError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CidrError::BadAddress(s) => write!(f, "not an IP address: {s:?}"),
            CidrError::BadPrefix(s) => write!(f, "not a prefix length: {s:?}"),
            CidrError::PrefixTooLong { prefix_len, max } => {
                write!(
                    f,
                    "prefix /{prefix_len} exceeds the maximum /{max} for this family"
                )
            }
        }
    }
}

impl std::error::Error for CidrError {}

impl core::str::FromStr for Cidr {
    type Err = CidrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.split_once('/') {
            Some((addr, prefix)) => {
                let addr: core::net::IpAddr = addr
                    .parse()
                    .map_err(|_| CidrError::BadAddress(addr.to_string()))?;
                let prefix_len: u8 = prefix
                    .parse()
                    .map_err(|_| CidrError::BadPrefix(prefix.to_string()))?;
                Cidr::new(addr, prefix_len)
            }
            // A bare address is a host route.
            None => {
                let addr: core::net::IpAddr = s
                    .parse()
                    .map_err(|_| CidrError::BadAddress(s.to_string()))?;
                let prefix_len = if addr.is_ipv4() { 32 } else { 128 };
                Cidr::new(addr, prefix_len)
            }
        }
    }
}

impl<'de> serde::Deserialize<'de> for Cidr {
    /// 설정 파일에서는 문자열로 쓴다("10.0.0.0/8", "1.1.1.1").
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = <String as serde::Deserialize>::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl serde::Serialize for Cidr {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl core::fmt::Display for Cidr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_host() {
            write!(f, "{}", self.addr)
        } else {
            write!(f, "{}/{}", self.addr, self.prefix_len)
        }
    }
}

#[cfg(test)]
mod cidr_tests {
    use super::*;
    use core::str::FromStr as _;

    #[test]
    fn bare_address_is_a_host_route() {
        let c = Cidr::from_str("1.1.1.1").expect("parses");
        assert_eq!(c.prefix_len(), 32);
        assert!(c.is_host());
        assert_eq!(c.to_string(), "1.1.1.1", "호스트는 접미사 없이 표시한다");

        let c6 = Cidr::from_str("2606:4700::1111").expect("parses");
        assert_eq!(c6.prefix_len(), 128);
    }

    #[test]
    fn parses_ranges_of_both_families() {
        assert_eq!(Cidr::from_str("10.0.0.0/8").unwrap().prefix_len(), 8);
        assert_eq!(Cidr::from_str("fd00::/8").unwrap().prefix_len(), 8);
        assert_eq!(
            Cidr::from_str("10.0.0.0/8").unwrap().to_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(matches!(
            Cidr::from_str("not-an-ip"),
            Err(CidrError::BadAddress(_))
        ));
        assert!(matches!(
            Cidr::from_str("10.0.0.0/x"),
            Err(CidrError::BadPrefix(_))
        ));
        assert!(matches!(
            Cidr::from_str("10.0.0.0/33"),
            Err(CidrError::PrefixTooLong { .. })
        ));
        assert!(matches!(
            Cidr::from_str("fd00::/129"),
            Err(CidrError::PrefixTooLong { .. })
        ));
    }

    // 호스트 비트가 남아 있으면 같은 대역이 서로 다른 키가 되어 LPM 조회가 어긋난다.
    #[test]
    fn host_bits_are_cleared_for_the_kernel_key() {
        let written = Cidr::from_str("10.1.2.3/8").unwrap().network_bytes();
        let canonical = Cidr::from_str("10.0.0.0/8").unwrap().network_bytes();
        assert_eq!(
            written, canonical,
            "10.1.2.3/8 과 10.0.0.0/8 은 같은 키여야 한다"
        );
        assert_eq!(written, CidrBytes::V4([10, 0, 0, 0]));
    }

    #[test]
    fn masks_inside_a_byte() {
        // /12 는 두 번째 바이트의 상위 4비트만 남긴다: 172.16.0.0/12
        assert_eq!(
            Cidr::from_str("172.31.255.255/12").unwrap().network_bytes(),
            CidrBytes::V4([172, 16, 0, 0])
        );
    }

    #[test]
    fn bytes_are_network_order() {
        // 1.2.3.4 는 바이트 순서 그대로여야 한다(호스트 오더로 뒤집히면 안 된다).
        assert_eq!(
            Cidr::from_str("1.2.3.4").unwrap().network_bytes(),
            CidrBytes::V4([1, 2, 3, 4])
        );
    }

    #[test]
    fn ipv6_masking_spans_bytes() {
        let c = Cidr::from_str("fd12:3456::/16").unwrap();
        let CidrBytes::V6(b) = c.network_bytes() else {
            panic!("v6 이어야 한다")
        };
        assert_eq!(b[0], 0xfd);
        assert_eq!(b[1], 0x12);
        assert!(b[2..].iter().all(|&x| x == 0), "16비트 뒤는 전부 0");
    }
}
