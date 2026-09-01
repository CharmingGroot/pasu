//! Read **Presidio recognizer YAML** and expose it as a [`pasu_core::Inspector`].
//!
//! Teams that already write PII rules down almost never have them in pasu's
//! format. They have Presidio recognizers, because Presidio's no-code YAML is
//! the closest thing this space has to a common format. Asking someone to retype
//! that is asking them not to adopt pasu, so this reads what they already have.
//!
//! There is no interchange standard to implement. This is not one either — it is
//! a reader for one popular format, and it says so.
//!
//! ```
//! use pasu_core::Inspector;
//! use pasu_inspect_presidio::Import;
//!
//! let yaml = r#"
//! recognizers:
//!   - name: "SSN Recognizer"
//!     supported_entity: "US_SSN"
//!     patterns:
//!       - name: "ssn"
//!         regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
//!         score: 0.85
//! "#;
//!
//! let rules = Import { min_score: 0.5 }.read(yaml, "presidio")?;
//! let found = rules.inspect("the number is 123-45-6789");
//! assert_eq!(found[0].rule, "US_SSN");
//! # Ok::<(), pasu_inspect_presidio::Error>(())
//! ```
//!
//! # What crosses, and what does not
//!
//! Only regex and deny-list recognizers are expressible in that YAML at all;
//! anything needing named-entity recognition is a Python class, and a per-message
//! request path could not afford to run one anyway.
//!
//! Of what is expressible, four things do not survive, and none of them is
//! dropped quietly:
//!
//! * **Score.** Presidio findings carry a confidence — the shipped example has a
//!   zip-code pattern at `0.01`. A [`pasu_core::Finding`] carries none, and the
//!   proxy refuses on any finding, so importing a `0.01` pattern as a hard block
//!   would stop agents all day. Patterns below [`Import::min_score`] are not
//!   imported, and the threshold is part of the call rather than a default
//!   hidden in here.
//! * **Context words.** Presidio raises a weak pattern's score when supporting
//!   words are nearby. With no score there is nothing to raise, so a weak
//!   pattern imported without its context is *more* false-positive-prone here
//!   than it was there. That is the reason the threshold matters, and it is why
//!   `context` is reported rather than ignored.
//! * **Regex dialect.** Presidio is Python `re`. This is the Rust `regex`
//!   crate, deliberately: no backtracking, so no ReDoS on a path that runs on
//!   every message. Backreferences and lookaround do not compile, and those
//!   recognizers cannot be imported.
//! * **Checksums.** Presidio can carry validation logic in Python. Nothing here
//!   can import that, so a pattern that had a checksum behind it arrives without
//!   one.
//!
//! # Loading is fail-closed; matching is not
//!
//! A file that contains anything unusable is an [`Error`], naming each
//! recognizer and why. A half-loaded rule set that reports success is worse than
//! a refusal, because the operator believes they are covered.
//!
//! That is about *loading*. Once loaded, matching stays default-allow, like any
//! content filter over human text — no allowlist can enumerate the sentences a
//! person may write.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::fmt;

use pasu_core::{Finding, Inspector};
use regex::Regex;
use serde::Deserialize;

/// A rule set read from Presidio recognizer YAML.
#[derive(Debug)]
pub struct PresidioRules {
    name: String,
    rules: Vec<CompiledRule>,
    skipped: Vec<Skipped>,
}

#[derive(Debug)]
struct CompiledRule {
    /// The Presidio `supported_entity`, which is what an operator recognises —
    /// `US_SSN`, `ZIP` — so it is what a refusal names.
    entity: String,
    regex: Regex,
}

/// One recognizer that was left out, and why. Kept so a caller can report it.
#[derive(Debug, Clone, PartialEq)]
pub struct Skipped {
    /// The recognizer's `name` as written in the file.
    pub recognizer: String,
    /// Why it did not cross.
    pub reason: SkipReason,
}

/// Why a recognizer did not import.
#[derive(Debug, Clone, PartialEq)]
pub enum SkipReason {
    /// Every pattern scored below the threshold.
    BelowScore {
        /// The best score the recognizer offered.
        best: f64,
        /// The threshold it had to clear.
        threshold: f64,
    },
    /// The pattern is valid Python `re` but not valid here — a backreference or
    /// lookaround, which this engine does not have and will not grow.
    UnsupportedRegex(String),
    /// Neither `patterns` nor `deny_list`: an NER recognizer, or an empty entry.
    NothingToMatch,
}

impl fmt::Display for SkipReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BelowScore { best, threshold } => write!(
                f,
                "its best pattern scores {best}, below the {threshold} threshold; \
                 Presidio would have leaned on context words that do not cross"
            ),
            Self::UnsupportedRegex(why) => write!(
                f,
                "its pattern does not compile without backtracking ({why}); \
                 backreferences and lookaround are not available here"
            ),
            Self::NothingToMatch => write!(
                f,
                "it carries neither patterns nor a deny list, so it needs \
                 named-entity recognition rather than a regex"
            ),
        }
    }
}

/// What went wrong reading a file.
#[derive(Debug)]
pub enum Error {
    /// The document is not the shape Presidio writes.
    Malformed(String),
    /// Some recognizers could not be imported. Never a partial success.
    Incomplete(Vec<Skipped>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(why) => write!(f, "this is not a Presidio recognizer file: {why}"),
            Self::Incomplete(skipped) => {
                writeln!(
                    f,
                    "{} recognizer(s) could not be imported, so this rule set is \
                     not what the file describes:",
                    skipped.len()
                )?;
                for item in skipped {
                    writeln!(f, "  {} — {}", item.recognizer, item.reason)?;
                }
                // No remedy is named here on purpose. This type is read by a
                // library caller and by an operator holding a CLI, and the two
                // have different moves available: one can call `read_lossy`, the
                // other can only change a flag or the file. Naming either would
                // be advice the other cannot take, so each caller adds its own.
                Ok(())
            }
        }
    }
}

impl std::error::Error for Error {}

/// How to read a file.
pub struct Import {
    /// The lowest Presidio score to accept.
    ///
    /// There is no correct default, which is why there is no default. Presidio
    /// ships patterns as weak as `0.01` on the understanding that context words
    /// will raise them; nothing raises them here, so a low threshold imports
    /// patterns that will fire on ordinary text.
    pub min_score: f64,
}

impl Import {
    /// Read a document, refusing if anything in it could not be imported.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the document is not Presidio's shape, and
    /// [`Error::Incomplete`] if any recognizer did not cross — naming each one.
    pub fn read(&self, yaml: &str, name: impl Into<String>) -> Result<PresidioRules, Error> {
        let rules = self.read_lossy(yaml, name)?;
        if rules.skipped.is_empty() {
            return Ok(rules);
        }
        Err(Error::Incomplete(rules.skipped))
    }

    /// Read a document, keeping what crossed and recording what did not.
    ///
    /// For a caller that means to inspect [`PresidioRules::skipped`] and decide
    /// for itself. Everything else should use [`Import::read`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if the document is not Presidio's shape.
    pub fn read_lossy(&self, yaml: &str, name: impl Into<String>) -> Result<PresidioRules, Error> {
        let file: RecognizerFile =
            serde_yaml::from_str(yaml).map_err(|e| Error::Malformed(e.to_string()))?;
        let mut rules = Vec::new();
        let mut skipped = Vec::new();

        for recognizer in file.recognizers {
            let entity = recognizer
                .supported_entity
                .clone()
                .unwrap_or_else(|| recognizer.name.clone());

            if let Some(list) = &recognizer.deny_list {
                if !list.is_empty() {
                    // A deny list is a set of literals. Escaping each one is what
                    // keeps a stray `.` in "Mr." from matching any character.
                    let alternation = list
                        .iter()
                        .map(|term| regex::escape(term))
                        .collect::<Vec<_>>()
                        .join("|");
                    match Regex::new(&alternation) {
                        Ok(regex) => rules.push(CompiledRule {
                            entity: entity.clone(),
                            regex,
                        }),
                        Err(e) => skipped.push(Skipped {
                            recognizer: recognizer.name.clone(),
                            reason: SkipReason::UnsupportedRegex(e.to_string()),
                        }),
                    }
                    continue;
                }
            }

            let Some(patterns) = recognizer.patterns.as_ref().filter(|p| !p.is_empty()) else {
                skipped.push(Skipped {
                    recognizer: recognizer.name.clone(),
                    reason: SkipReason::NothingToMatch,
                });
                continue;
            };

            let best = patterns.iter().map(|p| p.score).fold(f64::MIN, f64::max);
            let strong: Vec<&Pattern> = patterns
                .iter()
                .filter(|p| p.score >= self.min_score)
                .collect();
            if strong.is_empty() {
                skipped.push(Skipped {
                    recognizer: recognizer.name.clone(),
                    reason: SkipReason::BelowScore {
                        best,
                        threshold: self.min_score,
                    },
                });
                continue;
            }

            for pattern in strong {
                match Regex::new(&pattern.regex) {
                    Ok(regex) => rules.push(CompiledRule {
                        entity: entity.clone(),
                        regex,
                    }),
                    Err(e) => skipped.push(Skipped {
                        recognizer: recognizer.name.clone(),
                        reason: SkipReason::UnsupportedRegex(e.to_string()),
                    }),
                }
            }
        }

        Ok(PresidioRules {
            name: name.into(),
            rules,
            skipped,
        })
    }
}

impl PresidioRules {
    /// The recognizers that did not cross. Empty after [`Import::read`].
    #[must_use]
    pub fn skipped(&self) -> &[Skipped] {
        &self.skipped
    }

    /// How many patterns are live.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether this rule set matches nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

impl Inspector for PresidioRules {
    fn name(&self) -> &str {
        &self.name
    }

    fn inspect(&self, text: &str) -> Vec<Finding> {
        let mut found = Vec::new();
        for rule in &self.rules {
            if let Some(m) = rule.regex.find(text) {
                found.push(Finding {
                    inspector: self.name.clone(),
                    // The entity, never the matched text. Reporting the value
                    // would put it in the block message and the audit log.
                    rule: rule.entity.clone(),
                    span: m.start()..m.end(),
                });
            }
        }
        found
    }
}

#[derive(Debug, Deserialize)]
struct RecognizerFile {
    recognizers: Vec<Recognizer>,
}

#[derive(Debug, Deserialize)]
struct Recognizer {
    name: String,
    supported_entity: Option<String>,
    patterns: Option<Vec<Pattern>>,
    deny_list: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Pattern {
    regex: String,
    score: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    const STRONG: &str = r#"
recognizers:
  - name: "SSN Recognizer"
    supported_entity: "US_SSN"
    patterns:
      - name: "ssn"
        regex: "\\b\\d{3}-\\d{2}-\\d{4}\\b"
        score: 0.85
"#;

    fn import() -> Import {
        Import { min_score: 0.5 }
    }

    #[test]
    fn a_regex_recognizer_imports_and_matches_under_its_entity_name() {
        let rules = import().read(STRONG, "presidio").expect("a clean file");

        let found = rules.inspect("the number is 123-45-6789 apparently");

        let finding = found.first().expect("a hit");
        assert_eq!(
            finding.rule, "US_SSN",
            "the entity is what an operator knows"
        );
        assert_eq!(finding.inspector, "presidio");
    }

    #[test]
    fn a_deny_list_recognizer_imports_and_its_literals_stay_literal() {
        let yaml = r#"
recognizers:
  - name: "Titles recognizer"
    supported_entity: "TITLE"
    deny_list: ["Mr.", "Dr."]
"#;
        let rules = import().read(yaml, "presidio").expect("a clean file");

        assert!(!rules.inspect("Dr. Kim called").is_empty());
        assert!(
            rules.inspect("Drx Kim called").is_empty(),
            "the dot in 'Dr.' must be a dot, not any character"
        );
    }

    /// Presidio ships patterns as weak as 0.01 because context words will raise
    /// them. Nothing raises them here, so importing one as a hard block would
    /// fire on ordinary text.
    #[test]
    fn a_pattern_below_the_threshold_is_refused_and_says_what_it_scored() {
        let yaml = r#"
recognizers:
  - name: "Zip code Recognizer"
    supported_entity: "ZIP"
    patterns:
      - name: "zip code (weak)"
        regex: "(\\b\\d{5}(?:\\-\\d{4})?\\b)"
        score: 0.01
    context: [zip, code]
"#;
        let error = import()
            .read(yaml, "presidio")
            .expect_err("0.01 is not a block");

        let said = error.to_string();
        assert!(said.contains("Zip code Recognizer"), "{said}");
        assert!(
            said.contains("0.01"),
            "the score belongs in the reason: {said}"
        );
        assert!(said.contains("context words"), "{said}");
    }

    /// The trade this crate makes on purpose: no backtracking, so no ReDoS on a
    /// path that runs per message — and so some Presidio patterns cannot cross.
    #[test]
    fn a_python_only_pattern_is_named_rather_than_silently_lost() {
        let yaml = r#"
recognizers:
  - name: "Lookahead Recognizer"
    supported_entity: "THING"
    patterns:
      - name: "lookahead"
        regex: "foo(?=bar)"
        score: 0.9
"#;
        let error = import()
            .read(yaml, "presidio")
            .expect_err("this cannot compile");

        let said = error.to_string();
        assert!(said.contains("Lookahead Recognizer"), "{said}");
        assert!(said.contains("backreferences and lookaround"), "{said}");
    }

    /// The property that matters most: a file with anything unusable does not
    /// load as though it were whole. An operator who believes they are covered
    /// and is not is worse off than one who got an error.
    #[test]
    fn one_bad_recognizer_fails_the_whole_import() {
        let yaml = format!("{STRONG}\n  - name: \"NER only\"\n    supported_entity: \"PERSON\"\n");

        let error = import()
            .read(&yaml, "presidio")
            .expect_err("not a partial success");

        assert!(error.to_string().contains("NER only"));
    }

    /// And the escape hatch, for a caller that means to look at the gap.
    #[test]
    fn a_lossy_import_keeps_what_crossed_and_reports_the_rest() {
        let yaml = format!("{STRONG}\n  - name: \"NER only\"\n    supported_entity: \"PERSON\"\n");

        let rules = import().read_lossy(&yaml, "presidio").expect("well formed");

        assert_eq!(rules.len(), 1);
        assert_eq!(rules.skipped().len(), 1);
        assert!(!rules.inspect("123-45-6789").is_empty());
    }

    #[test]
    fn a_document_that_is_not_presidios_shape_says_so() {
        assert!(matches!(
            import().read("nothing: here", "presidio"),
            Err(Error::Malformed(_))
        ));
    }
}
