//! 규칙 표현.

/// 규칙에 걸렸을 때 취할 동작.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[cfg_attr(feature = "yaml", derive(serde::Deserialize))]
#[cfg_attr(feature = "yaml", serde(rename_all = "lowercase"))]
pub enum Action {
    /// 차단한다.
    #[default]
    Deny,
    /// 통과시킨다. 먼저 선언된 규칙이 이기므로, 예외를 만들 때 `deny` 규칙보다 위에 둔다.
    Allow,
}

/// 규칙 하나.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "yaml", derive(serde::Deserialize))]
pub struct Rule {
    /// 규칙 식별자. 판정 결과와 로그에 실린다.
    pub id: String,
    /// 후보를 뽑는 정규식.
    pub pattern: String,
    /// 후보를 걸러낼 검증기 이름(`ko_rrn`·`ko_brn`·`luhn` 등). 없으면 정규식만으로 판정한다.
    #[cfg_attr(feature = "yaml", serde(default))]
    pub validator: Option<String>,
    /// 매치 시 동작.
    #[cfg_attr(feature = "yaml", serde(default))]
    pub action: Action,
}

/// 크레이트에 내장된 기본 규칙.
///
/// 규칙 파일은 `rules/default/*.yaml`에 사람이 읽는 형태로도 함께 둔다.
pub(crate) fn builtin() -> Vec<Rule> {
    let mut rules = Vec::new();

    #[cfg(feature = "ko")]
    {
        rules.push(Rule {
            id: "ko-rrn".into(),
            // 6자리 생년월일 + 구분자 + 성별코드(1-8) + 6자리.
            // (?-u): 유니코드를 끈다. 켜져 있으면 한글이 단어문자로 취급되어
            // "주민번호900101-1234567" 처럼 붙여 쓴 경우 \b 가 성립하지 않아 놓친다.
            // 부수 효과로 DFA가 작아져 스캔도 빨라진다.
            pattern: r"(?-u)\b[0-9]{6}[-\s]?[1-8][0-9]{6}\b".into(),
            // 체크섬이 아니라 형식·날짜만 본다 — 2020-10 이후 발급분은 체크섬이 없다.
            validator: Some("ko_rrn".into()),
            action: Action::Deny,
        });
        rules.push(Rule {
            id: "ko-brn".into(),
            pattern: r"(?-u)\b[0-9]{3}-?[0-9]{2}-?[0-9]{5}\b".into(),
            validator: Some("ko_brn".into()),
            action: Action::Deny,
        });
        rules.push(Rule {
            id: "ko-phone".into(),
            pattern: r"(?-u)\b01[016789][-\s]?[0-9]{3,4}[-\s]?[0-9]{4}\b".into(),
            validator: None,
            action: Action::Deny,
        });
    }

    rules.push(Rule {
        id: "card".into(),
        pattern: r"(?-u)\b(?:[0-9]{4}[-\s]?){3}[0-9]{4}\b".into(),
        validator: Some("luhn".into()),
        action: Action::Deny,
    });
    rules
}
