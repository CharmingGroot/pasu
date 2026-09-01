//! Use [`pasu_pii_kr`] as a [`pasu_core::Inspector`].
//!
//! ```
//! use pasu_core::Inspector;
//! use pasu_inspect_pii_kr::PiiKr;
//!
//! let found = PiiKr::builtin().inspect("고객 주민번호는 900101-1234567 입니다");
//! assert_eq!(found[0].rule, "ko-rrn");
//! ```
//!
//! # Why this is its own crate
//!
//! `pasu-pii-kr` deliberately depends on no pasu crate. That is what lets a
//! gateway which has never heard of pasu use the scanner, and it is worth
//! keeping — so the adapter cannot live there.
//!
//! It used to live inside `pasu-proxy`, which made the proxy the only thing that
//! could use it and made every build of the proxy compile the scanner whether or
//! not it was wanted. Here, both sides are free: the scanner stays
//! dependency-free, the proxy takes this crate only when asked, and a different
//! host — a daemon, someone else's gateway — can take the adapter without taking
//! the proxy.
#![forbid(unsafe_code)]
#![warn(missing_docs)]

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
        // Every hit, not the first. Refusing needs only one, but redacting needs
        // all of them — masking one occurrence and sending the rest is not
        // masking. `check_all` keeps the same allow-wins priority as `check`, so
        // the two never disagree about a piece of text.
        self.filter
            .check_all(text)
            .into_iter()
            .map(|hit| Finding {
                inspector: "pii-kr".into(),
                rule: hit.rule,
                span: hit.span,
            })
            .collect()
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

    /// The adapter must not narrow what the scanner reports: a redactor reading
    /// findings needs every occurrence, not the first.
    #[test]
    fn every_occurrence_becomes_a_finding() {
        let text = "첫 번째 900101-1234567, 두 번째 900101-1234567 입니다";

        let found = PiiKr::builtin().inspect(text);

        assert_eq!(found.len(), 2, "{found:?}");
    }

    #[test]
    fn ordinary_text_finds_nothing() {
        assert!(PiiKr::builtin().inspect("오늘 날씨 어때?").is_empty());
    }
}
