//! 한국 개인식별정보(PII)를 탐지해 **통과/차단** 판정을 내리는 경량 필터.
//!
//! LLM 게이트웨이나 에이전트 서버의 프로세스 안에서 직접 호출하도록 만들었다.
//! I/O도 async도 없고, [`Filter`]는 빌드 후 불변이라 `Arc`로 공유하면 된다.
//!
//! ```
//! use pasu_pii_kr::{Filter, Verdict};
//!
//! let filter = Filter::builtin();
//! match filter.check("고객 주민번호는 900101-1234567 입니다") {
//!     Verdict::Deny(hit) => assert_eq!(hit.rule, "ko-rrn"),
//!     Verdict::Allow => panic!("탐지했어야 한다"),
//! }
//! assert!(matches!(filter.check("오늘 날씨 어때?"), Verdict::Allow));
//! ```
//!
//! # 설계 원칙
//!
//! - **정규식 + 검증기.** 정규식으로 후보를 뽑고 체크섬·날짜로 걸러 오탐을 줄인다.
//! - **선형 시간.** 백트래킹 없는 `regex` 크레이트만 쓴다. 사용자가 규칙을 추가해도
//!   ReDoS로 프로세스가 멈추지 않는다.
//! - **기본은 통과(default-allow).** 사람의 문장 전체를 allowlist로 정의할 수는 없다.
//!   커널에서 default-deny를 쓰는 pasu와 반대이며, 이는 의도된 차이다.
//! - **값을 담지 않는다.** [`Hit`]은 규칙 이름과 위치만 알려준다. 탐지된 값 자체를
//!   실어 나르면 로그로 유출되어 본말이 전도된다.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod matcher;
mod rule;
pub mod validators;

#[cfg(feature = "yaml")]
mod config;

use std::ops::Range;
use std::sync::Arc;

pub use rule::{Action, Rule};

/// 규칙 위반 지점.
///
/// 탐지된 문자열 자체는 담지 않는다(로그 유출 방지).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    /// 걸린 규칙의 id. 예: `"ko-rrn"`.
    pub rule: String,
    /// 입력 문자열에서의 바이트 범위.
    pub span: Range<usize>,
}

/// 검사 결과.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// 위반 없음.
    Allow,
    /// 차단 규칙에 걸렸다.
    Deny(Hit),
}

impl Verdict {
    /// 차단 판정인가.
    #[must_use]
    pub fn is_deny(&self) -> bool {
        matches!(self, Verdict::Deny(_))
    }
}

/// 규칙 로딩·컴파일 중 발생하는 오류.
#[derive(Debug)]
pub enum Error {
    /// 정규식을 컴파일할 수 없다.
    Regex(Box<regex::Error>),
    /// 규칙이 알 수 없는 검증기를 가리킨다. 조용히 넘기면 규칙이 무력화되므로 오류로 처리한다.
    UnknownValidator {
        /// 문제가 된 규칙의 id.
        rule: String,
        /// 참조된 검증기 이름.
        validator: String,
    },
    /// 규칙 파일을 해석할 수 없다.
    Config(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Regex(e) => write!(f, "정규식 컴파일 실패: {e}"),
            Error::UnknownValidator { rule, validator } => {
                write!(
                    f,
                    "규칙 {rule:?}가 알 수 없는 검증기 {validator:?}를 참조한다"
                )
            }
            Error::Config(m) => write!(f, "규칙 해석 실패: {m}"),
        }
    }
}

impl std::error::Error for Error {}

impl From<regex::Error> for Error {
    fn from(e: regex::Error) -> Self {
        Error::Regex(Box::new(e))
    }
}

/// 컴파일된 규칙 집합. 빌드 후 불변이며 스레드 간 공유해도 된다.
#[derive(Debug, Clone)]
pub struct Filter {
    inner: Arc<matcher::Compiled>,
}

impl Filter {
    /// 크레이트에 내장된 기본 규칙으로 만든다. 설정 파일이 필요 없다.
    ///
    /// # Panics
    /// 내장 규칙은 빌드 시점에 검증되므로 실패하지 않는다.
    #[must_use]
    pub fn builtin() -> Self {
        Self::from_rules(rule::builtin()).expect("내장 규칙은 항상 유효하다")
    }

    /// 규칙 목록을 직접 넘겨 만든다.
    ///
    /// # Errors
    /// 정규식이 잘못되었거나 알 수 없는 검증기를 참조하면 오류.
    pub fn from_rules(rules: Vec<Rule>) -> Result<Self, Error> {
        Ok(Self {
            inner: Arc::new(matcher::Compiled::new(rules)?),
        })
    }

    /// 검사한다. 첫 매치에서 즉시 반환한다(차단 판정에는 그것으로 충분하다).
    #[must_use]
    pub fn check(&self, text: &str) -> Verdict {
        self.inner.check(text)
    }

    /// 컴파일된 규칙 수.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// 규칙이 하나도 없는가.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.len() == 0
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::builtin()
    }
}
