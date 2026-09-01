//! Replacing what an [`Inspector`] found, instead of refusing the request.
//!
//! A refusal stops the leak and the work with it. An engineer whose agent is
//! summarising a support ticket does not want the ticket blocked — they want the
//! ticket without the customer's number in it.
//!
//! Blocking stays the default. It is the right answer for a rule an operator
//! treats as a hard stop, and it is the safe answer for a rule nobody has
//! thought about yet.
//!
//! # One way, not reversible
//!
//! The value is replaced and not kept. Nothing here can restore it, and that is
//! the point: a proxy holding a map from token to original is a store of exactly
//! the data it exists to stop from moving, reachable over the network. A
//! reversible design is a different security posture and belongs to its own
//! decision rather than being inherited from whichever was easier to build.
//!
//! # The placeholder tells nothing
//!
//! `[REDACTED:ko-rrn]` is fixed. It does not preserve the length, the shape, or
//! the character classes of what it replaced — a mask that keeps those leaks the
//! value it hid, and a `\d`-shaped mask over a national ID leaks most of it.
//!
//! [`Inspector`]: pasu_core::Inspector

use std::collections::BTreeSet;

use pasu_core::Finding;

/// What to do about a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Refuse the request. The default, and the only safe answer for a rule
    /// nobody has decided about.
    Block,
    /// Replace the span and forward the rest.
    Redact,
}

/// Which findings are refused and which are replaced.
///
/// Per rule, not per filter. `ko-rrn` in a prompt is usually a mistake worth
/// stopping, while a phone number may be worth removing and carrying on; one
/// switch for the whole filter answers neither well.
#[derive(Debug, Clone, Default)]
pub struct Policy {
    redact_all: bool,
    /// Rules that are blocked whatever the default is.
    blocked: BTreeSet<String>,
    /// Rules that are redacted whatever the default is.
    redacted: BTreeSet<String>,
}

impl Policy {
    /// Refuse on every finding. What the proxy did before redaction existed.
    #[must_use]
    pub fn block_everything() -> Self {
        Self::default()
    }

    /// Redact by default, blocking only the rules named.
    #[must_use]
    pub fn redact_everything() -> Self {
        Self {
            redact_all: true,
            ..Self::default()
        }
    }

    /// Always refuse on this rule, whatever the default is.
    #[must_use]
    pub fn blocking(mut self, rule: impl Into<String>) -> Self {
        self.blocked.insert(rule.into());
        self
    }

    /// Always redact this rule, whatever the default is.
    #[must_use]
    pub fn redacting(mut self, rule: impl Into<String>) -> Self {
        self.redacted.insert(rule.into());
        self
    }

    /// What to do about one finding.
    ///
    /// An explicit block wins over an explicit redact. Where an operator has
    /// said both about the same rule they have contradicted themselves, and the
    /// safe reading of a contradiction in a security policy is the stricter one.
    #[must_use]
    pub fn action_for(&self, rule: &str) -> Action {
        if self.blocked.contains(rule) {
            return Action::Block;
        }
        if self.redacted.contains(rule) || self.redact_all {
            return Action::Redact;
        }
        Action::Block
    }
}

/// What redacting one piece of text did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Redacted {
    /// The text with every redactable span replaced.
    pub text: String,
    /// Which rules were replaced, for the audit line. Never the values.
    pub rules: Vec<String>,
}

/// Replace every finding the policy says to redact.
///
/// Returns `None` when nothing was replaced, so a caller can leave the body
/// untouched rather than re-serialising it for no reason.
///
/// Spans are applied **right to left** so that an earlier replacement cannot
/// shift the offsets of a later one, and overlapping findings — two inspectors
/// matching the same text — are merged first so they cannot cut each other's
/// bytes and leave the string invalid.
#[must_use]
pub fn redact(text: &str, findings: &[Finding], policy: &Policy) -> Option<Redacted> {
    let mut spans: Vec<(usize, usize, String)> = findings
        .iter()
        .filter(|f| policy.action_for(&f.rule) == Action::Redact)
        .filter(|f| f.span.start < f.span.end && f.span.end <= text.len())
        // A span that does not land on character boundaries would panic on
        // slicing. Dropping it is wrong-but-safe here: the finding still exists
        // and the caller still sees the rule, it simply is not replaced.
        .filter(|f| text.is_char_boundary(f.span.start) && text.is_char_boundary(f.span.end))
        .map(|f| (f.span.start, f.span.end, f.rule.clone()))
        .collect();
    if spans.is_empty() {
        return None;
    }
    spans.sort_by_key(|(start, end, _)| (*start, *end));

    // Merge overlaps, keeping every rule name that contributed.
    let mut merged: Vec<(usize, usize, Vec<String>)> = Vec::new();
    for (start, end, rule) in spans {
        match merged.last_mut() {
            Some((_, last_end, rules)) if start <= *last_end => {
                *last_end = (*last_end).max(end);
                if !rules.contains(&rule) {
                    rules.push(rule);
                }
            }
            _ => merged.push((start, end, vec![rule])),
        }
    }

    let mut rules: Vec<String> = Vec::new();
    let mut out = text.to_string();
    for (start, end, names) in merged.iter().rev() {
        out.replace_range(*start..*end, &placeholder(names));
        for name in names {
            if !rules.contains(name) {
                rules.push(name.clone());
            }
        }
    }
    rules.sort();
    Some(Redacted { text: out, rules })
}

/// `[REDACTED:ko-rrn]`, or `[REDACTED:a+b]` where findings overlapped.
///
/// Sorted, so the same text and the same rules always produce the same body.
/// Leaving it in discovery order would make the output depend on which inspector
/// ran first, which turns a diff between two runs into a question about
/// configuration order rather than about content.
fn placeholder(rules: &[String]) -> String {
    let mut sorted: Vec<&str> = rules.iter().map(String::as_str).collect();
    sorted.sort_unstable();
    format!("[REDACTED:{}]", sorted.join("+"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(rule: &str, span: std::ops::Range<usize>) -> Finding {
        Finding {
            inspector: "test".into(),
            rule: rule.into(),
            span,
        }
    }

    #[test]
    fn blocking_is_the_default_for_a_rule_nobody_decided_about() {
        let policy = Policy::block_everything();

        assert_eq!(policy.action_for("anything"), Action::Block);
        assert_eq!(
            Policy::redact_everything().action_for("anything"),
            Action::Redact
        );
    }

    /// A contradiction in a security policy reads as the stricter option.
    #[test]
    fn an_explicit_block_beats_an_explicit_redact() {
        let policy = Policy::redact_everything()
            .redacting("ko-rrn")
            .blocking("ko-rrn");

        assert_eq!(policy.action_for("ko-rrn"), Action::Block);
    }

    #[test]
    fn the_span_is_replaced_and_the_rest_is_kept() {
        let text = "id 900101-1234567 end";
        let policy = Policy::redact_everything();

        let out = redact(text, &[finding("ko-rrn", 3..17)], &policy).expect("a replacement");

        assert_eq!(out.text, "id [REDACTED:ko-rrn] end");
        assert_eq!(out.rules, vec!["ko-rrn".to_string()]);
    }

    /// The replacement must not describe what it replaced.
    #[test]
    fn the_placeholder_keeps_no_shape_of_the_value() {
        let text = "id 900101-1234567 end";

        let out = redact(
            text,
            &[finding("ko-rrn", 3..17)],
            &Policy::redact_everything(),
        )
        .expect("a replacement");

        assert!(!out.text.contains("900101"), "{}", out.text);
        assert!(
            !out.text.contains('7'),
            "no digit of the value survives: {}",
            out.text
        );
        assert_ne!(
            out.text.len() - "id  end".len(),
            14,
            "a length-preserving mask leaks the value it hid"
        );
    }

    /// Applying an earlier span first would shift every later offset.
    #[test]
    fn several_spans_do_not_shift_each_other() {
        let text = "AAA 111 BBB 222 CCC";
        let findings = [finding("a", 4..7), finding("b", 12..15)];

        let out = redact(text, &findings, &Policy::redact_everything()).expect("replacements");

        assert_eq!(out.text, "AAA [REDACTED:a] BBB [REDACTED:b] CCC");
    }

    /// Two inspectors matching the same text must not cut each other's bytes.
    #[test]
    fn overlapping_findings_are_merged_and_both_rules_are_named() {
        let text = "xx 900101-1234567 yy";
        let findings = [finding("ko-rrn", 3..17), finding("presidio-id", 3..10)];

        let out = redact(text, &findings, &Policy::redact_everything()).expect("a replacement");

        assert_eq!(
            out.text, "xx [REDACTED:ko-rrn+presidio-id] yy",
            "the names are sorted so the body does not depend on inspector order"
        );
        assert_eq!(out.rules, vec!["ko-rrn".to_string(), "presidio-id".into()]);
    }

    #[test]
    fn a_blocked_rule_is_not_redacted_and_leaves_nothing_to_do() {
        let text = "id 900101-1234567";
        let policy = Policy::redact_everything().blocking("ko-rrn");

        assert!(redact(text, &[finding("ko-rrn", 3..17)], &policy).is_none());
    }

    /// Korean text is multi-byte, so a span that is not on a character boundary
    /// would panic on slicing. It must be skipped rather than take the process
    /// down — the finding is still reported by the caller either way.
    #[test]
    fn a_span_off_a_character_boundary_is_skipped_not_panicked_on() {
        let text = "주민번호";

        assert!(redact(text, &[finding("x", 1..3)], &Policy::redact_everything()).is_none());
    }

    #[test]
    fn a_span_past_the_end_is_ignored() {
        let text = "short";

        assert!(redact(text, &[finding("x", 0..500)], &Policy::redact_everything()).is_none());
    }
}
