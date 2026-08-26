//! 대략적인 처리량 측정. `cargo run --release --example bench`
//!
//! 정밀 측정은 criterion으로 별도 구성한다. 여기서는 자릿수만 확인한다.

use std::time::Instant;

use pasu_pii_kr::Filter;

fn main() {
    let filter = Filter::builtin();

    let clean_short = "오늘 회의 내용을 세 줄로 요약해줘.";
    let clean_long = "회사의 분기 실적 보고서를 요약하고 핵심 지표를 뽑아줘. ".repeat(200); // ~20KB
    let hit = "고객 문의: 주민번호 900101-1234567 로 조회 부탁드립니다.";

    for (label, text) in [
        ("짧은 프롬프트(위반 없음)", clean_short),
        ("긴 컨텍스트 ~20KB(위반 없음)", clean_long.as_str()),
        ("위반 포함(첫 매치에서 반환)", hit),
    ] {
        // 워밍업
        for _ in 0..1_000 {
            std::hint::black_box(filter.check(text));
        }
        let n = 20_000;
        let t = Instant::now();
        for _ in 0..n {
            std::hint::black_box(filter.check(text));
        }
        let per = t.elapsed().as_nanos() as f64 / f64::from(n);
        println!(
            "{label:32} {:>9.2} µs/회   ({:.1} MB/s)",
            per / 1000.0,
            (text.len() as f64) / (per / 1e9) / 1e6
        );
    }
}
