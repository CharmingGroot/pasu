//! The importer against a whole file rather than a one-recognizer snippet.
//!
//! `fixtures/recognizers.yaml` is written here, from the published shape of a
//! recognizer file. Nothing is copied in from another project: this repository
//! vendors no external rule set, and a test fixture is not an exception to that.
//!
//! What it buys over the unit tests is the mixture — a weak pattern, a deny
//! list and an ordinary pattern in one document, where a partial failure has
//! somewhere to hide.

use pasu_core::Inspector;
use pasu_inspect_presidio::{Import, SkipReason};

const REAL: &str = include_str!("fixtures/recognizers.yaml");

fn import() -> Import {
    Import { min_score: 0.5 }
}

/// The file holds a zip-code pattern at score `0.01`. Scores that low are
/// ordinary where context words raise them; nothing raises anything here, so a
/// strict read must refuse the file and say which recognizer and why.
#[test]
fn a_file_is_refused_for_its_weak_pattern_and_names_it() {
    let error = import()
        .read(REAL, "presidio")
        .expect_err("0.01 must not become a hard block");

    let said = error.to_string();
    assert!(said.contains("Zip code Recognizer"), "{said}");
    assert!(said.contains("0.01"), "{said}");
}

/// And what does cross, crosses. Refusing the file is not the same as failing
/// to read the rest of it.
#[test]
fn the_usable_recognizers_in_the_same_file_import_and_match() {
    let rules = import().read_lossy(REAL, "presidio").expect("well formed");

    assert_eq!(
        rules.len(),
        2,
        "the deny list and the ordinary pattern both cross"
    );
    assert_eq!(rules.skipped().len(), 1);
    assert!(matches!(
        rules.skipped()[0].reason,
        SkipReason::BelowScore { .. }
    ));

    let found = rules.inspect("Dr. Kim will see you");
    assert_eq!(found.first().expect("a hit").rule, "TITLE");

    let found = rules.inspect("ssn 123-45-6789");
    assert_eq!(found.first().expect("a hit").rule, "US_SSN");
}

/// Lowering the threshold is allowed, and it is the operator's call rather than
/// this crate's — but it must actually change the outcome, or the knob is a lie.
#[test]
fn a_lower_threshold_admits_the_weak_pattern() {
    let permissive = Import { min_score: 0.0 };

    let rules = permissive
        .read(REAL, "presidio")
        .expect("nothing is refused now");

    assert_eq!(
        rules.len(),
        3,
        "the weak one joins the two that already crossed"
    );
    assert!(!rules.inspect("my zip is 12345").is_empty());
}
