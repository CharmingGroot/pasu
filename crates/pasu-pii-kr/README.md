# pasu-pii-kr

한국 개인식별정보(PII)를 탐지해 **통과 / 차단** 판정을 내리는 경량 Rust 라이브러리.
LLM 게이트웨이나 에이전트 서버의 프로세스 안에서 직접 호출하도록 만들었다.

```rust
use pasu_pii_kr::{Filter, Verdict};

let filter = Filter::builtin();               // 기동 시 한 번. 이후 불변이라 Arc로 공유

match filter.check(&prompt) {
    Verdict::Deny(hit) => return Err(format!("차단: 규칙 {}", hit.rule)),
    Verdict::Allow => upstream.send(&prompt),
}
```

> `pasu` 계열이지만 **pasu에 의존하지 않는다.** 이 크레이트 하나만 넣으면 되고,
> eBPF나 프록시가 딸려오지 않는다.

## 왜 또 만드나

PII 탐지 도구는 이미 있다([Presidio](https://github.com/microsoft/presidio),
LLM Guard 등). 이 크레이트는 세 가지가 다르다.

**1. 한국 식별번호를 '검증'한다.** 정규식만 쓰면 `123456-7890123` 같은 무작위
숫자열까지 전부 걸려 오탐이 쏟아진다. 여기서는 정규식으로 후보를 뽑은 뒤
체크섬·생년월일로 걸러낸다.

| 대상 | 검증 방식 |
|---|---|
| 주민등록번호 | 형식 + 생년월일 유효성 + 성별코드 (`ko_rrn_strict`는 체크섬까지) |
| 사업자등록번호 | 가중치 체크섬 |
| 카드번호 | Luhn |
| 휴대전화 | 형식 |

**2. 규칙을 추가해도 멈추지 않는다.** 백트래킹이 없는
[`regex`](https://docs.rs/regex) 크레이트만 쓴다. 입력 길이에 대해 선형 시간이
보장되므로, 사용자가 넣은 규칙 때문에 ReDoS로 프로세스가 굳는 일이 없다.
(백트래킹 엔진을 쓰는 Python `re`·JS `RegExp`에서는 실제로 가능한 사고다.)

**3. 가볍다.** 최소 구성의 직접 의존성은 `regex` 하나다.

```
$ cargo tree --no-default-features --features ko
pasu-pii-kr
└── regex
    ├── aho-corasick → memchr
    ├── regex-automata
    └── regex-syntax
```

## 성능

Apple M4, `cargo run --release --example bench` 기준.

| 입력 | 처리 시간 |
|---|---|
| 짧은 프롬프트 | **0.14 µs** |
| 20 KB 컨텍스트 | **15.6 µs** (~1 GB/s) |
| 위반 포함(첫 매치에서 반환) | **0.45 µs** |

LLM 왕복이 보통 1초 이상인 것을 감안하면 호출 비용은 사실상 0이다.
모든 패턴을 하나의 `RegexSet`으로 묶어 한 번만 훑고, 걸린 규칙만 개별로 확인한다.

## 규칙

기본 규칙은 크레이트에 내장되어 있어 설정 없이도 동작한다(`Filter::builtin()`).
바꾸고 싶으면 YAML로 관리한다.

```yaml
rules:
  - id: ko-rrn
    pattern: '(?-u)\b[0-9]{6}[-\s]?[1-8][0-9]{6}\b'
    validator: ko_rrn        # 없으면 정규식만으로 판정
    action: deny             # deny | allow
```

```rust
let filter = Filter::from_dir(Path::new("rules"))?;
```

`rules/user/*.yaml`이 `rules/default/*.yaml`보다 **먼저** 평가된다.
먼저 선언된 규칙이 이기므로, 예외는 `action: allow`로 만든다.

```yaml
rules:
  - id: allow-test-fixture
    pattern: '000000-0000000'
    action: allow
```

### 패턴은 ASCII 모드로 쓴다

기본 규칙의 `(?-u)`는 실수가 아니다. 유니코드 모드에서는 한글이 단어문자라
`\b`가 성립하지 않아 **`주민번호900101-1234567`처럼 붙여 쓰면 놓친다.**
덤으로 DFA가 작아져 20 KB 기준 1494 µs → 15.6 µs가 됐다.

## 알아둘 것 (한계)

- **주민등록번호 체크섬은 2020년 10월부터 폐지됐다.** 그 이후 발급분은 뒷자리가
  임의값이라 검증식이 성립하지 않는다. 기본 규칙이 체크섬 대신 형식·생년월일만
  보는 이유다 — 보안 필터에서 미탐(누출)은 오탐보다 비싸다. 구 번호만 다루는
  환경이라면 `ko_rrn_strict`로 바꿔 오탐을 더 줄일 수 있다.
- **검증기는 오탐을 줄이지만 없애지 못한다.** 예컨대 16자리 숫자가 우연히 Luhn을
  통과하면 카드로 잡힌다(`1111 2222 3333 4444`가 실제로 그렇다). 그런 값이
  업무상 자주 나오면 `user/` 규칙으로 예외를 만든다.
- **이름·주소는 다루지 않는다.** 규칙 기반으로는 한계가 명확하다. NER은 별개 문제다.
- **차단만 한다.** 마스킹·복원은 없다. `Hit.span`이 위치를 알려주므로 필요하면
  호출자가 직접 가릴 수 있다.
- 이 도구는 **탐지를 돕는 장치**일 뿐, 어떤 법령의 준수를 보장하지 않는다.

## 값을 로그에 남기지 않는다

`Hit`은 **규칙 id와 위치만** 담는다. 탐지된 문자열 자체는 담지 않는다 —
그걸 실어 나르면 PII를 막으려다 로그로 유출하는 셈이 된다.

## 개발

```bash
cargo test        # 검증기 단위 + 코퍼스
cargo clippy --all-targets -- -D warnings
cargo run --release --example bench
```

`tests/corpus/*.yaml`은 **언어 중립 명세**다. 나중에 다른 언어 구현이 생기면
같은 코퍼스를 통과해야 한다. 구현이 갈라지는 것을 구조적으로 막기 위한 장치이며,
보안 라이브러리에서 "A 언어에선 막혔는데 B 언어에선 통과"는 곧 취약점이다.

## 로드맵

- v0.1 — 라이브러리 (현재)
- v0.2 — 사이드카 프록시. 에이전트의 `base_url`만 바꾸면 게이트웨이 밖에서 검사한다
- v0.3 — PyO3 바인딩 (`pip install`)

## 라이선스

Apache-2.0
