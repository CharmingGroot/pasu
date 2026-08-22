//! 언어 중립 코퍼스(`tests/corpus/*.yaml`)를 그대로 돌린다.
//!
//! 다른 언어 구현이 생기면 같은 파일을 읽어 같은 결과를 내야 한다.
//! 구현이 갈라지는 것을 구조적으로 막기 위한 장치다.

use std::path::PathBuf;

use pasu_pii_kr::{Filter, Verdict};
use serde::Deserialize;

#[derive(Deserialize)]
struct Corpus {
    name: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    text: String,
    expect: String,
    #[serde(default)]
    rule: Option<String>,
}

fn crate_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

#[test]
fn corpus_matches_expectations() {
    let filter = Filter::builtin();
    let mut checked = 0;

    let mut files: Vec<_> = std::fs::read_dir(crate_root().join("tests/corpus"))
        .expect("코퍼스 디렉터리")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "yaml"))
        .collect();
    files.sort();
    assert!(!files.is_empty(), "코퍼스가 비어 있다");

    for path in files {
        let text = std::fs::read_to_string(&path).expect("코퍼스 읽기");
        let corpus: Corpus = serde_yml::from_str(&text).expect("코퍼스 해석");

        for case in corpus.cases {
            let verdict = filter.check(&case.text);
            match (case.expect.as_str(), &verdict) {
                ("deny", Verdict::Deny(hit)) => {
                    if let Some(expected) = &case.rule {
                        assert_eq!(
                            &hit.rule, expected,
                            "[{}] 규칙이 다르다: {:?}",
                            corpus.name, case.text
                        );
                    }
                }
                ("allow", Verdict::Allow) => {}
                (want, got) => panic!(
                    "[{}] 기대 {want}, 실제 {got:?} — 입력: {:?}",
                    corpus.name, case.text
                ),
            }
            checked += 1;
        }
    }
    assert!(checked >= 15, "코퍼스가 너무 작다: {checked}건");
}

#[test]
fn builtin_and_yaml_rules_agree() {
    // 내장 규칙과 rules/default/*.yaml 이 같은 판정을 내려야 한다.
    let builtin = Filter::builtin();
    let from_files = Filter::from_dir(&crate_root().join("rules")).expect("규칙 디렉터리 로딩");

    for text in [
        "주민번호 900101-1234567",
        "사업자 220-81-62517",
        "카드 4242-4242-4242-4242",
        "평범한 문장입니다",
        "901301-1234567",
    ] {
        assert_eq!(
            builtin.check(text).is_deny(),
            from_files.check(text).is_deny(),
            "내장 규칙과 파일 규칙의 판정이 다르다: {text:?}"
        );
    }
}

#[test]
fn user_rules_override_defaults() {
    // user/ 규칙이 먼저 평가되므로 allow 예외가 default deny를 이긴다.
    let filter = Filter::from_yaml(
        r#"
rules:
  - id: allow-fixture
    pattern: '900101-1234567'
    action: allow
  - id: ko-rrn
    pattern: '\b\d{6}[-\s]?[1-8]\d{6}\b'
    validator: ko_rrn
    action: deny
"#,
    )
    .expect("규칙 로딩");

    assert!(
        !filter.check("픽스처 900101-1234567").is_deny(),
        "예외가 우선해야 한다"
    );
    assert!(
        filter.check("다른 번호 800505-2345678").is_deny(),
        "예외 밖은 여전히 차단"
    );
}

#[test]
fn unknown_validator_is_an_error() {
    // 알 수 없는 검증기를 조용히 통과시키면 규칙이 무력화된다 — 반드시 오류여야 한다.
    let err = Filter::from_yaml(
        r#"
rules:
  - id: bogus
    pattern: 'x'
    validator: does_not_exist
"#,
    );
    assert!(err.is_err(), "알 수 없는 검증기는 오류여야 한다");
}
