//! 신용카드 번호 — Luhn 검증(ISO/IEC 7812).

use super::digits;

/// Luhn 검증을 통과하는 12~19자리 숫자인가.
#[must_use]
pub fn is_valid(s: &str) -> bool {
    let d = digits(s);
    if !(12..=19).contains(&d.len()) {
        return false;
    }
    let sum: u32 = d
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &x)| {
            let mut v = u32::from(x);
            if i % 2 == 1 {
                v *= 2;
                if v > 9 {
                    v -= 9;
                }
            }
            v
        })
        .sum();
    // is_multiple_of 는 MSRV(1.86)에 없다.
    #[allow(clippy::manual_is_multiple_of)]
    {
        sum % 10 == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_known_test_numbers() {
        // 카드사 공개 테스트 번호 (실제 계정 아님)
        assert!(is_valid("4242424242424242"));
        assert!(is_valid("4242-4242-4242-4242"));
        assert!(is_valid("5555555555554444"));
    }

    #[test]
    fn rejects_tampered_and_short() {
        assert!(!is_valid("4242424242424243"));
        assert!(!is_valid("42424242"));
    }
}
