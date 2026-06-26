//! pasu-core — 공통 타입과 레이어/룰엔진 인터페이스(trait).
//!
//! 구현(Falco, eBPF, socket)은 전부 이 trait 뒤에 둔다. 이 crate는 아무것도
//! 의존하지 않는다(순수). 다른 crate는 core만 의존한다(acyclic).
//! 설계: docs/repo-structure.md

/// 정책 판정 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 허용.
    Allow,
    /// 차단 + 이유.
    Deny(String),
    /// 사용자 확인 요청 + 이유.
    Ask(String),
}

/// 에이전트가 하려는 행위. 레이어는 이 이벤트를 평가한다.
#[derive(Debug, Clone)]
pub struct Event {
    pub kind: EventKind,
}

#[derive(Debug, Clone)]
pub enum EventKind {
    /// L1 — tool call.
    ToolCall { name: String, input: String },
    /// L2/L3 — 나가는 네트워크.
    Egress { host: String, port: u16 },
}

/// 룰 엔진 인터페이스. 초기 구현은 Falco 룰 차용(pasu-rules).
/// 나중에 OPA / 자체 DSL로 교체 가능 — 호출부는 이 trait만 본다.
pub trait RuleEngine {
    fn evaluate(&self, event: &Event) -> Verdict;
}

/// 레이어(L1/L2/L3) 공통 인터페이스. 런타임에 토글 가능.
pub trait Layer {
    fn name(&self) -> &str;
    fn enabled(&self) -> bool;
    fn check(&self, event: &Event) -> Verdict;
}

impl Verdict {
    /// 더 제한적인 verdict로 에스컬레이션: deny > ask > allow.
    /// 여러 레이어/룰이 매칭될 때 가장 강한 차단을 택한다.
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
