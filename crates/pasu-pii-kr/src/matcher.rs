//! 규칙을 컴파일하고 스캔한다.
//!
//! 모든 패턴을 하나의 [`RegexSet`]으로 묶어 **한 번의 선형 스캔**으로 후보 규칙을
//! 추린 뒤, 걸린 규칙만 개별 정규식으로 위치를 찾는다. 규칙이 늘어도 입력을
//! 여러 번 훑지 않는다.

use regex::{Regex, RegexSet};

use crate::rule::{Action, Rule};
use crate::{validators, Error, Hit, Verdict};

#[derive(Debug)]
pub(crate) struct Compiled {
    set: RegexSet,
    each: Vec<Entry>,
}

#[derive(Debug)]
struct Entry {
    id: String,
    re: Regex,
    action: Action,
    validator: Option<fn(&str) -> bool>,
}

impl Compiled {
    pub(crate) fn new(rules: Vec<Rule>) -> Result<Self, Error> {
        let mut each = Vec::with_capacity(rules.len());
        for r in rules {
            let validator = match &r.validator {
                Some(name) => {
                    Some(
                        validators::by_name(name).ok_or_else(|| Error::UnknownValidator {
                            rule: r.id.clone(),
                            validator: name.clone(),
                        })?,
                    )
                }
                None => None,
            };
            each.push(Entry {
                re: Regex::new(&r.pattern)?,
                id: r.id,
                action: r.action,
                validator,
            });
        }
        let set = RegexSet::new(each.iter().map(|e| e.re.as_str()))?;
        Ok(Self { set, each })
    }

    pub(crate) fn len(&self) -> usize {
        self.each.len()
    }

    pub(crate) fn check(&self, text: &str) -> Verdict {
        // 1차: 한 번의 스캔으로 어떤 규칙이 걸릴 수 있는지만 본다.
        let candidates = self.set.matches(text);
        if !candidates.matched_any() {
            return Verdict::Allow;
        }

        // 2차: 선언 순서대로 확인한다(먼저 선언된 규칙이 이긴다).
        for idx in candidates.iter() {
            let entry = &self.each[idx];
            for m in entry.re.find_iter(text) {
                // 검증기가 있으면 통과한 후보만 인정한다.
                if let Some(v) = entry.validator {
                    if !v(m.as_str()) {
                        continue;
                    }
                }
                return match entry.action {
                    // allow 규칙에 걸리면 이 텍스트는 예외로 본다.
                    Action::Allow => Verdict::Allow,
                    Action::Deny => Verdict::Deny(Hit {
                        rule: entry.id.clone(),
                        span: m.range(),
                    }),
                };
            }
        }
        Verdict::Allow
    }

    /// 걸린 것을 **전부** 돌려준다.
    ///
    /// [`Compiled::check`]는 첫 매치에서 멈춘다. 차단 판정에는 그걸로 충분하지만
    /// 마스킹에는 부족하다 — 하나만 가리고 나머지를 보내면 가리지 않은 것과 같다.
    ///
    /// 우선순위 규칙은 그대로다. 선언 순서로 처음 걸린 규칙이 `allow`면 이 텍스트는
    /// 예외이고 결과는 비어 있다. `deny`면 그 지점부터 모든 `deny` 규칙의 매치를
    /// 모은다. `check`가 이미 반환한 뒤라 닿지 않던 뒤쪽 `allow`는 여기서도 닿지
    /// 않는다 — 두 함수가 같은 텍스트에 대해 다르게 판단하면 안 되기 때문이다.
    pub(crate) fn check_all(&self, text: &str) -> Vec<Hit> {
        let candidates = self.set.matches(text);
        if !candidates.matched_any() {
            return Vec::new();
        }

        let mut hits = Vec::new();
        let mut decided = false;
        for idx in candidates.iter() {
            let entry = &self.each[idx];
            for m in entry.re.find_iter(text) {
                if let Some(v) = entry.validator {
                    if !v(m.as_str()) {
                        continue;
                    }
                }
                match entry.action {
                    Action::Allow => {
                        // 아직 아무 규칙도 결정하지 않았을 때만 예외가 성립한다.
                        // `check`에서 deny 가 먼저 반환했을 상황이면 여기서도 무시한다.
                        if !decided {
                            return Vec::new();
                        }
                    }
                    Action::Deny => {
                        decided = true;
                        hits.push(Hit {
                            rule: entry.id.clone(),
                            span: m.range(),
                        });
                    }
                }
            }
        }
        hits
    }
}
