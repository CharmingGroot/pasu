//! `check_all` 이 `check` 와 같은 판단을 하는가.
//!
//! 두 함수가 같은 텍스트를 다르게 보면 차단과 마스킹이 어긋난다. 하나는 통과시키고
//! 다른 하나는 가리는 상태가 되는데, 그건 둘 중 하나가 틀렸다는 뜻이다.

use pasu_pii_kr::{Filter, Verdict};

const RRN: &str = "900101-1234567";

/// 마스킹의 전제. 하나만 가리고 나머지를 보내면 가리지 않은 것과 다르지 않다.
#[test]
fn 한_문장에_여러_건이_있으면_전부_돌려준다() {
    let filter = Filter::builtin();
    let text = format!("첫 번째 {RRN}, 두 번째 {RRN} 입니다");

    let all = filter.check_all(&text);

    assert_eq!(all.len(), 2, "{all:?}");
    assert!(all.iter().all(|h| h.rule == "ko-rrn"));
    assert_ne!(all[0].span, all[1].span, "같은 자리를 두 번 세면 안 된다");
}

/// 첫 매치만 보는 `check` 와 어긋나지 않는다.
#[test]
fn check_가_차단하면_check_all_도_반드시_무언가를_찾는다() {
    let filter = Filter::builtin();
    let text = format!("주민번호 {RRN}");

    assert!(matches!(filter.check(&text), Verdict::Deny(_)));
    assert!(!filter.check_all(&text).is_empty());
}

/// 그리고 그 역도 성립해야 한다.
#[test]
fn check_가_통과시키면_check_all_은_비어_있다() {
    let filter = Filter::builtin();

    for text in ["오늘 날씨 어때?", "숫자 12345 는 그냥 숫자다", ""] {
        assert!(matches!(filter.check(text), Verdict::Allow), "{text}");
        assert!(
            filter.check_all(text).is_empty(),
            "check 가 통과시킨 텍스트를 check_all 이 잡으면 마스킹과 차단이 어긋난다: {text}"
        );
    }
}

/// 값을 싣지 않는다는 성질은 개수와 무관하게 유지된다.
#[test]
fn 여러_건이어도_값은_실리지_않는다() {
    let filter = Filter::builtin();
    let text = format!("{RRN} 그리고 {RRN}");

    for hit in filter.check_all(&text) {
        assert!(!format!("{hit:?}").contains(RRN), "{hit:?}");
    }
}
