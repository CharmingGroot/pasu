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
}
