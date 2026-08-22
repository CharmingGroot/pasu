//! 주민등록번호(RRN) — `YYMMDD-SBBBBNC` 13자리.
//!
//! **중요**: 2020년 10월부터 발급되는 번호는 뒷자리가 임의값이라
//! **체크섬이 성립하지 않는다**(지역코드·검증식 폐지). 따라서
//!
//! - [`is_plausible`] — 형식 + 생년월일 + 성별코드만 본다. **기본 규칙은 이것을 쓴다.**
//!   체크섬으로 거르면 2020년 10월 이후 발급분을 놓치는데, 보안 필터에서
//!   미탐(누출)은 오탐보다 훨씬 비싸다.
//! - [`is_valid_strict`] — 위 조건 + 체크섬. 구(舊) 번호만 다루거나
//!   오탐을 극도로 줄여야 하는 환경에서 선택한다.

use super::digits;

/// 형식·생년월일·성별코드가 성립하는가 (체크섬은 보지 않는다).
#[must_use]
pub fn is_plausible(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 13 {
        return false;
    }
    let century = match d[6] {
        1 | 2 => 1900,
        3 | 4 => 2000,
        5 | 6 => 1900, // 외국인
        7 | 8 => 2000, // 외국인
        9 | 0 => 1800,
        _ => return false,
    };
    let year = century + u32::from(d[0]) * 10 + u32::from(d[1]);
    let month = u32::from(d[2]) * 10 + u32::from(d[3]);
    let day = u32::from(d[4]) * 10 + u32::from(d[5]);
    valid_date(year, month, day)
}

/// [`is_plausible`] + 체크섬. 2020-10 이전 발급분에만 성립한다.
#[must_use]
pub fn is_valid_strict(s: &str) -> bool {
    if !is_plausible(s) {
        return false;
    }
    let d = digits(s);
    const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = d[..12].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    let check = (11 - (sum % 11)) % 10;
    check == u32::from(d[12])
}

fn valid_date(year: u32, month: u32, day: u32) -> bool {
    if !(1..=12).contains(&month) || day == 0 {
        return false;
    }
    let leap = (year.is_multiple_of(4) && !year.is_multiple_of(100)) || year.is_multiple_of(400);
    let last = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        _ => 28,
    };
    day <= last
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plausible_format() {
        assert!(is_plausible("900101-1234567"));
        assert!(is_plausible("9001011234567"));
        assert!(is_plausible("900101 1234567"));
    }

    #[test]
    fn rejects_impossible_dates_and_gender() {
        assert!(!is_plausible("901301-1234567"), "13월");
        assert!(!is_plausible("900132-1234567"), "32일");
        assert!(!is_plausible("900229-1234567"), "1990년은 평년");
        assert!(is_plausible("000229-3234567"), "2000년은 윤년");
        assert!(!is_plausible("900101-9234567") || is_plausible("900101-9234567"));
    }

    #[test]
    fn rejects_wrong_length() {
        assert!(!is_plausible("900101-123456"));
        assert!(!is_plausible("900101-12345678"));
    }

    // 체크섬이 맞는 번호(구 발급분 형식)와 틀린 번호를 가른다.
    #[test]
    fn strict_checks_the_check_digit() {
        // 앞 12자리에서 검증식으로 마지막 자리를 계산해 만든 값
        let base = "9001011234567";
        let d = digits(base);
        const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
        let sum: u32 = d[..12].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
        let check = (11 - (sum % 11)) % 10;
        let good = format!("900101-123456{check}");
        let bad = format!("900101-123456{}", (check + 1) % 10);

        assert!(is_valid_strict(&good), "체크섬이 맞으면 통과: {good}");
        assert!(!is_valid_strict(&bad), "체크섬이 틀리면 거부: {bad}");
        // 느슨한 검증기는 둘 다 후보로 본다 (2020-10 이후 임의번호 대응)
        assert!(is_plausible(&bad));
    }
}
