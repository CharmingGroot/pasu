//! The importer against the file Presidio actually ships.
//!
//! `fixtures/presidio_example_recognizers.yaml` is
//! `presidio-analyzer/presidio_analyzer/conf/example_recognizers.yaml` from
//! microsoft/presidio, verbatim. A test over a document written here proves the
//! parser reads what this crate imagines Presidio writes; this one proves it
//! reads what Presidio writes.

use pasu_core::Inspector;
use pasu_inspect_presidio::{Import, SkipReason};

const REAL: &str = include_str!("fixtures/presidio_example_recognizers.yaml");

fn import() -> Import {
    Import { min_score: 0.5 }
}

/// The shipped file contains a zip-code pattern at score `0.01`, which exists
/// there because context words raise it. Nothing raises it here, so a strict
/// read must refuse the file and say which recognizer and why.
#[test]
fn the_shipped_example_is_refused_for_its_weak_pattern_and_names_it() {
    let error = import()
        .read(REAL, "presidio")
        .expect_err("0.01 must not become a hard block");

    let said = error.to_string();
    assert!(said.contains("Zip code Recognizer"), "{said}");
    assert!(said.contains("0.01"), "{said}");
}

/// And what does cross, crosses: the deny-list recognizer in the same file.
#[test]
fn the_deny_list_recognizer_in_the_shipped_file_imports_and_matches() {
    let rules = import().read_lossy(REAL, "presidio").expect("well formed");

    assert_eq!(
        rules.len(),
        1,
        "one usable recognizer in the shipped example"
    );
    assert_eq!(rules.skipped().len(), 1);
    assert!(matches!(
        rules.skipped()[0].reason,
        SkipReason::BelowScore { .. }
    ));

    let found = rules.inspect("Dr. Kim will see you");
    assert_eq!(found.first().expect("a hit").rule, "TITLE");
}

/// Lowering the threshold is allowed, and it is the operator's call rather than
/// this crate's — but it must actually change the outcome, or the knob is a lie.
#[test]
fn a_lower_threshold_admits_the_weak_pattern() {
    let permissive = Import { min_score: 0.0 };

    let rules = permissive
        .read(REAL, "presidio")
        .expect("nothing is refused now");

    assert_eq!(rules.len(), 2);
    assert!(!rules.inspect("my zip is 12345").is_empty());
}
