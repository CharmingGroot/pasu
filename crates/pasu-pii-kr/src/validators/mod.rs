//! 후보 문자열이 실제로 유효한 식별번호인지 검증한다.
//!
//! 정규식만으로는 `123456-7890123` 같은 무작위 숫자열까지 전부 걸린다.
//! 검증기를 통과해야 최종 매치로 인정하므로 오탐이 크게 줄어든다.

#[cfg(feature = "ko")]
pub mod ko_brn;
#[cfg(feature = "ko")]
pub mod ko_rrn;
pub mod luhn;

/// 규칙 파일의 `validator:` 값에 대응하는 검증 함수.
///
/// 이름이 없으면 `None` — 알 수 없는 검증기를 조용히 통과시키면
/// 규칙이 무력화되므로, 호출부에서 오류로 처리한다.
#[must_use]
pub fn by_name(name: &str) -> Option<fn(&str) -> bool> {
    match name {
        #[cfg(feature = "ko")]
        "ko_rrn" => Some(ko_rrn::is_plausible),
        #[cfg(feature = "ko")]
        "ko_rrn_strict" => Some(ko_rrn::is_valid_strict),
        #[cfg(feature = "ko")]
        "ko_brn" => Some(ko_brn::is_valid),
        "luhn" => Some(luhn::is_valid),
        _ => None,
    }
}

/// 문자열에서 숫자만 뽑는다(하이픈·공백 무시).
pub(crate) fn digits(s: &str) -> Vec<u8> {
    s.bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| b - b'0')
        .collect()
}
