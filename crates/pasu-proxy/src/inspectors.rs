//! Adapters that make an existing scanner usable as a [`pasu_core::Inspector`].
//!
//! The adapter lives here rather than in the scanner. `pasu-pii-kr` depends on
//! no other pasu crate by design — it is meant to be usable by an LLM gateway
//! that has never heard of pasu — and reversing that to implement a pasu trait
//! would cost it exactly the property that makes it worth having.
//!
//! So the dependency points one way: the proxy knows about the scanner, and the
//! scanner knows about nothing. Anything else plugs in the same way — a client
//! for a Presidio server, a secret scanner, an in-house matcher — by wrapping
//! it here or in its own crate. None of them requires touching a layer.

use pasu_core::{Finding, Inspector};

/// Korean PII, via [`pasu_pii_kr`].
pub struct PiiKr {
    filter: pasu_pii_kr::Filter,
}

impl PiiKr {
    /// The rules shipped with the scanner.
    #[must_use]
    pub fn builtin() -> Self {
        Self {
            filter: pasu_pii_kr::Filter::builtin(),
        }
    }

    /// A scanner an operator configured themselves.
    #[must_use]
    pub fn with_filter(filter: pasu_pii_kr::Filter) -> Self {
        Self { filter }
    }
}

impl Inspector for PiiKr {
    fn name(&self) -> &str {
        "pii-kr"
    }

    fn inspect(&self, text: &str) -> Vec<Finding> {
        // The scanner answers with the first hit rather than every one, so this
        // reports the first too. It is enough to refuse on; a redactor will want
        // all of them, and that is a change to the scanner rather than to this
        // adapter or to the trait.
        match self.filter.check(text) {
            pasu_pii_kr::Verdict::Deny(hit) => vec![Finding {
                inspector: "pii-kr".into(),
                rule: hit.rule,
                span: hit.span,
            }],
            pasu_pii_kr::Verdict::Allow => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hit_becomes_a_finding_that_names_the_rule_and_not_the_value() {
        let found = PiiKr::builtin().inspect("고객 주민번호는 900101-1234567 입니다");

        let finding = found.first().expect("a hit");
        assert_eq!(finding.rule, "ko-rrn");
        assert_eq!(finding.inspector, "pii-kr");
        assert!(!finding.span.is_empty());
    }

    #[test]
    fn ordinary_text_finds_nothing() {
        assert!(PiiKr::builtin().inspect("오늘 날씨 어때?").is_empty());
    }
}
