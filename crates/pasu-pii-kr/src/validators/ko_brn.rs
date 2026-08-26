//! 사업자등록번호 — `XXX-XX-XXXXX` 10자리.
//!
//! 주민등록번호와 달리 검증식이 현재도 유효하므로 체크섬을 그대로 신뢰한다.

use super::digits;

/// 가중치 `[1,3,7,1,3,7,1,3,5]` 합 + 9번째 자리×5의 십의 자리를 더해
/// 10의 보수가 마지막 자리와 일치하는지 본다.
#[must_use]
pub fn is_valid(s: &str) -> bool {
    let d = digits(s);
    if d.len() != 10 {
        return false;
    }
    const W: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];
    let mut sum: u32 = d[..9].iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
    sum += (u32::from(d[8]) * 5) / 10;
    let check = (10 - (sum % 10)) % 10;
    check == u32::from(d[9])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 앞 9자리로 검증식을 돌려 유효한 번호를 만들어 낸다.
    fn make_valid(prefix9: &str) -> String {
        let d = digits(prefix9);
        const W: [u32; 9] = [1, 3, 7, 1, 3, 7, 1, 3, 5];
        let mut sum: u32 = d.iter().zip(W).map(|(&x, w)| u32::from(x) * w).sum();
        sum += (u32::from(d[8]) * 5) / 10;
        let check = (10 - (sum % 10)) % 10;
        format!("{prefix9}{check}")
    }

    #[test]
    fn accepts_valid_and_rejects_tampered() {
        let good = make_valid("123456789");
        assert!(is_valid(&good), "{good}");

        let mut bytes = good.clone().into_bytes();
        let last = bytes.len() - 1;
        bytes[last] = if bytes[last] == b'9' {
            b'0'
        } else {
            bytes[last] + 1
        };
        let bad = String::from_utf8(bytes).unwrap();
        assert!(!is_valid(&bad), "체크섬이 틀리면 거부: {bad}");
    }

    #[test]
    fn ignores_separators_and_checks_length() {
        let good = make_valid("220181234");
        let dashed = format!("{}-{}-{}", &good[0..3], &good[3..5], &good[5..10]);
        assert!(is_valid(&dashed), "{dashed}");
        assert!(!is_valid("123-45-6789"), "9자리는 사업자번호가 아니다");
    }
}
