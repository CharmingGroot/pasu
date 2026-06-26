# CLAUDE.md — Pasu 개발 작업 룰

이 파일은 Pasu에서 작업하는 Claude(및 기여자)가 **반드시 지켜야 하는** 룰이다.
이 룰은 기본 동작보다 우선한다.

## 프로젝트

Pasu = Rust 기반 AI 에이전트 보안 가드. 에이전트의 **tool call(L1) + egress(L2 proxy, L3 eBPF)** 를 다층으로 **강제 차단**한다. cooperative(선언만 봄)가 아니라 **enforcing**(실제 차단)이 핵심 차별화.

상세 설계는 `docs/`에 정리한다 (architecture · repo-structure · rules · testing; 작성 중).
**작업 전 관련 설계 문서를 먼저 읽는다.**

---

## 절대 작업 룰 (위반 시 멈추고 보고)

### 1. 아키텍처 — 분리/추상화 유지

- **crate 분리 유지**: 레이어(`pasu-l1/l2/l3`)·룰엔진(`pasu-rules`)은 독립 crate. **서로 직접 의존 금지.** `pasu-core`만 의존한다(의존 그래프 acyclic).
- **구현은 trait 뒤에**: `RuleEngine`/`Layer`/`Transport`. Falco·eBPF·socket 같은 구체 구현을 trait 뒤에 격리해 **교체 가능**하게 둔다. 호출부는 trait만 본다.
- **토글 ≠ 분리**: 런타임 토글(config `lN.enabled`)과 빌드 분리(crate/feature)를 **둘 다** 유지한다.
- 새 기능이 crate 경계나 trait 추상화를 깨야 한다면 — **멈추고 재설계를 제안**한다. 임의로 결합하지 않는다.

### 2. 룰

- 룰은 **Falco 문법 차용**하되 `RuleEngine` trait 뒤에 둔다. Falco 의존은 `pasu-rules` 한 crate에만 격리.
- `default/`(프로젝트 관리, 업그레이드 시 덮어씀) vs `user/`(사용자 커스텀, 보존) 분리.

### 3. 테스트 — 보안 도구라 필수

- **룰/로직 변경엔 회귀 테스트.** fix 전 fail / 후 pass (mutation 관점). 커버리지 채우기용 빈 테스트 금지.
- **E2E는 production 룰셋을 검증**한다. 테스트용 미니룰만 검증하지 않는다.
- **TP + TN 쌍**: 위험 차단(true positive) + 정상 통과(true negative, false positive 회귀) 둘 다.
- **우회(적대적) 테스트**: enforcing > cooperative를 증명한다 (예: L2 프록시 우회 → L3가 차단).
- **테스트 없는 룰/로직 변경 금지.**

### 4. fail-safe

- 보안 도구다. **fail-closed**: 가드가 동작 불능이면 deny. 편의를 위한 우회 경로(fail-open 디폴트 등)를 만들지 않는다.

### 5. 커밋 / PR

- **Conventional Commits** (`type(scope): 설명`). scope는 area(l1/l2/l3/rules/ci/docs)와 정렬.
- **DCO sign-off 필수**: `git commit -s`.
- **AI attribution 금지**: `Co-Authored-By: Claude` 등 넣지 않는다. 본인 명의 기여.
- **scope 격리**: 한 PR = 한 문제.
- 커밋/푸시/PR은 **사용자 확인 후** (외부로 나가는 작업).

### 6. 코드 스타일 (Rust)

- early return(no deep nesting), 불필요한 mutation 금지, fully typed(coarse type 지양), 상속보다 composition.
- 주석은 최소 — 자명한 코드 지향. 매직넘버/문자열은 `constants`로.
- `unwrap`/`expect`/`panic`을 사용자·네트워크 입력 경로에 두지 않는다. 실패는 값으로(`Result`).

### 7. 플랫폼

- **Linux first.** L3(eBPF)는 Linux 전용 — mac/win은 L1+L2만 동작하고, 그 사실을 명시한다.
- eBPF 변경은 커널 권한(CAP_BPF)·커널 버전 의존성에 주의.

---

## 빌드 / 테스트 명령

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## Think first

요청이 여러 해석 가능하면 임의로 고르지 말고 옵션을 제시한다. 더 단순한 길이 있으면 말한다. 불명확하면 멈추고 무엇이 불명확한지 짚는다.
