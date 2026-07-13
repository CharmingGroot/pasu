<p align="center">
  <img src="docs/logo.svg" width="112" alt="pasu — 허용된 흐름만 통과시키는 관문">
</p>

<h1 align="center">pasu &nbsp;<sub><sup>把守</sup></sub></h1>

<p align="center">
  <b>AI 에이전트를 위한 셀프호스티드 보안 가드 — 온프렘·망분리(air-gapped)·규제 환경을 위해.</b><br>
  계층 방어 — 트레이싱 → tool 호출 가드 → 커널 강제 egress — 를 단일 Linux 호스트에서. 쿠버네티스도, 클라우드도 필요 없고, 네트워크 밖으로 아무것도 나가지 않습니다.
</p>

<p align="center">
  <a href="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml"><img src="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/rust-edition%202021-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux%20first-lightgrey.svg" alt="Platform: Linux first">
  <img src="https://img.shields.io/badge/deploy-self--hosted%20%C2%B7%20air--gapped-2b6cb0.svg" alt="Self-hosted / air-gapped">
  <img src="https://img.shields.io/badge/Kubernetes-not%20required-555.svg" alt="No Kubernetes required">
</p>

<p align="center"><a href="README.en.md">English</a></p>

> **에이전트를 신뢰하지 않고도 egress를 통제한다 — 우리 네트워크 안에서.**
> 인프로세스 훅은 에이전트가 *선언한 것*만 봅니다. 자체 소켓을 여는 도구는 그냥 지나가죠.
> pasu는 그 협조적 계층을 **에이전트가 우회할 수 없는 커널 eBPF 가드**로 받치고, 모든 결정을 감사용으로 기록합니다.
> 전부 호스트 안에서 동작 — SaaS로 보내는 것 없음. **enforcing > cooperative.**

---

## 왜 pasu인가

AI 에이전트는 프롬프트 인젝션(prompt injection)을 당하고, 침해된 에이전트는 기꺼이 데이터를 유출합니다. 에이전트를 **온프렘·망분리·컴플라이언스** 환경에서 돌린다면 두 가지가 따라옵니다 — 에이전트 트래픽을 클라우드/SaaS 가드로 보낼 수 *없고*, 단일 협조적 검사 하나가 아니라 **다층 방어 + 감사 증거**가 필요합니다.

pasu는 그 환경을 위해 만들어졌습니다. 단일 Linux 호스트에서 전부 동작하고, **쿠버네티스도 외부 서비스도 필요 없으며**, **정책 하나로 3계층**을 적용합니다:

<p align="center">
  <img src="docs/flow.svg" width="760" alt="pasu 계층 egress 방어: 정책 하나가 협조적 rig 훅과 강제적 커널 eBPF 가드를 구동; 훅을 우회한 egress도 커널이 drop, 모든 결정은 감사 기록">
</p>

- **① 트레이싱 / 감사** (`pasu-audit`): 모든 결정을 기록 — 파일/SIEM으로 JSONL, 또는 *당신의* 스택으로 OpenTelemetry(OTLP) 스팬. 네트워크 밖으로 나가는 것 없이 감사 증거 확보.
- **② tool 호출 가드 — 협조적, 인프로세스** (`pasu-rig`): 선언된 tool 호출 게이팅 + 사람 승인(HITL), 정책 기반 LLM egress. 맥락은 풍부하나 단독으론 우회 가능.
- **③ egress 강제 — 커널** (`pasu-egress` / `pasu-ebpf`): 커널 cgroup egress 기본 차단(default-deny). 언어 무관하며 **우회 불가** — ②를 빠져나간 것을 최종적으로 막습니다.

E2E로 증명: 훅을 우회해 자체 `reqwest`로 나가는 도구도 **커널이 drop**합니다.

## 온프렘·규제 적합성

드문 지점은 이 *조합*을, 단일 셀프호스티드 서버에서 제공한다는 것입니다:

- **쿠버네티스·클라우드 불필요.** Linux 호스트 하나 — `pasu run`으로 아무 에이전트나 감쌈. K8s 네이티브 네트워크 정책엔진은 강력하지만 단일 온프렘 서버엔 무겁고, SaaS 에이전트 가드는 망분리 내부망에서 아예 못 돕니다.
- **망분리에서 동작.** 런타임 call-home 없음. 텔레메트리 export는 opt-in이고 *당신의* collector를 가리킴.
- **커널 인라인 egress + 에이전트 의도 + 감사**를 함께 — 대부분의 도구는 셋 중 하나만 줍니다.
- **Apache-2.0**, 감사 가능한 Rust, 모든 crate는 trait 뒤.

> 정직한 범위: pasu는 MVP이며 **보안 인증을 받지 않았고 프로덕션 레퍼런스가 없습니다.** 이 니치를 위한, 작동하는 셀프호스팅 레퍼런스이지 — 턴키 인증 어플라이언스가 아닙니다.

## 비교

전역 우위 주장이 아니라, 대안이 더 무겁거나 아예 못 도는 **온프렘/규제** 축에서의 적합성입니다.

| | **pasu** | 프레임워크/SDK 가드 | K8s 네이티브 정책엔진 | SaaS 에이전트 가드 |
|---|:---:|:---:|:---:|:---:|
| 단일 호스트, **쿠버네티스 불필요** | ✅ | ✅ | ❌ (K8s 필요) | ✅ |
| **망분리** 동작 (외부 서비스 無) | ✅ | ✅ | ✅ | ❌ |
| 커널 강제 egress (우회 불가) | ✅ eBPF | ❌ 협조적 | ✅ | ~ |
| 에이전트 의도 맥락 (tool 호출·HITL) | ✅ | ✅ | ❌ | ✅ |
| 감사 로그 (JSONL / OTLP, 내 스택) | ✅ | 일부 | ~ | ✅ (그들 클라우드) |
| 언어/프레임워크 무관 | ✅ | ❌ | ✅ | ~ |

## 정책 (Falco 영향 YAML)

```yaml
rules:
  - name: allow-llm
    match: { host: ".openai.com" }   # 도메인 + 서브도메인
    action: allow
  - name: confirm-transfer
    match: { tool: transfer_funds }
    action: ask                      # 사람 승인(HITL)
default: deny                        # fail-closed
```

## 빠른 시작

### 아무 에이전트나 감싸기 — 코드 변경 없이

pasu는 **에이전트가 아니라 가드**입니다. 어떤 프레임워크를 쓰든 상관하지 않아요. `pasu run`은 명령을 전용 cgroup에 넣고, 첫 명령 실행 전에 커널 가드를 붙입니다:

```bash
sudo pasu run --policy rules.yaml -- python crew.py        # CrewAI / LangChain / 무엇이든
sudo pasu run --policy rules.yaml -- npx some-agent "task"  # 언어 무관
```

정책이 허용하지 않은 것은 전부 커널이 drop합니다 — 에이전트(또는 인젝션된 도구)가 자체 소켓을 열어도.

### 더 깊게: 인프로세스 훅 (선택)

rig 에이전트를 가드(tool 게이트 + HITL + LLM egress) + 감사:

```rust
use pasu_rig::PasuSecurityHook;
use pasu_rules::RulesetEngine;

let engine = RulesetEngine::from_yaml(policy_yaml)?;
let hook = PasuSecurityHook::new(engine).with_sink(audit_sink);   // + .with_approver(ui)
agent.prompt("do the task").add_hook(hook).await?;
```

Linux 커널 egress 가드 — **같은 YAML**을 커널 allowlist로 낮춤 (전용 cgroup, 루트 cgroup 금지):

```bash
sudo pasu-daemon --policy rules.yaml --cgroup-path /sys/fs/cgroup/my-agent
# 정책 파일 없이 플래그/TOML로 직접:
sudo pasu-egress --cgroup-path /sys/fs/cgroup/my-agent --allow-domain api.openai.com
```

IPv4 allow는 정적 엔트리, 정확 호스트명은 해석(재해석)되고, 접미 패턴(`.openai.com`)은 리포트됩니다 — DNS 응답 스니핑 전까지는 훅 계층에서만 적용. 커널은 default-deny라 낮추기는 정책보다 *좁아질* 뿐입니다.

`--admin-socket /run/pasu.sock`을 붙이면 재시작 없이 라이브 가드를 조회·수정할 수 있어요 (UI가 이걸 씁니다):

```bash
echo status        | socat - UNIX-CONNECT:/run/pasu.sock   # {"cgroup_path":…,"allow_ips":[…]}
echo 'allow 1.2.3.4' | socat - UNIX-CONNECT:/run/pasu.sock  # 지금 커널 allowlist에 추가
echo 'deny 1.2.3.4'  | socat - UNIX-CONNECT:/run/pasu.sock  # 지금 제거
```

웹 UI — 승인(`/`), 감사(`/audit`), 라이브 **egress 대시보드**(`/egress`: 커널 필터 커버리지, allowlist 추가/삭제, 룰별 verdict·tool 가드 읽기전용 뷰):

```rust
use pasu_ui::dashboard::{EgressAdmin, EgressUi};
let egress = EgressUi::new(EgressAdmin::new("/run/pasu.sock"), Some("rules.yaml".into()));
pasu_ui::serve_all(addr, approvals, feed, Some(egress)).await?;   // + /egress
```

커널 없이 체험 (mock 가드 소켓):

```bash
cargo run -p pasu-ui --example ui_demo   # http://127.0.0.1:8787/egress
```

## 컨테이너로 실행

커널 가드는 여느 eBPF 도구처럼 컨테이너화됩니다 — `CAP_BPF` + `CAP_NET_ADMIN`과 cgroup v2 마운트. 빠른 증명(`1.1.1.1`만 허용; 나머진 앱이 뭘 하든 커널이 drop):

```bash
docker build -f deploy/Dockerfile -t pasu-egress:latest .
./deploy/demo.sh    # allowed -> reachable · blocked -> dropped · RESULT: PASS
```

사이드카([`deploy/docker-compose.yml`](deploy/docker-compose.yml))·쿠버네티스([`deploy/k8s/`](deploy/k8s)) 배치와 cgroup 타겟팅 규칙은 **[docs/deployment.md](docs/deployment.md)**에 있습니다.

## 크레이트

<p align="center">
  <img src="docs/ia.svg" width="700" alt="pasu 크레이트 지도: 모든 크레이트는 pasu-core에만 의존">
</p>

| crate | 역할 |
|-------|------|
| `pasu-core` | 공유 타입(`Event` / `Verdict`) + trait(`RuleEngine` · `Layer` · `Approver` · `AuditSink`) + `Guard` 파사드 |
| `pasu-rules` | `RuleEngine` — Falco 영향 YAML 룰셋(allow/deny/ask, 기본 fail-closed) |
| `pasu-rig` | rig 통합 — `AgentHook`(tool 게이트 + HITL), `HttpClientExt`(LLM egress) |
| `pasu-ui` | 경량 웹 UI — HITL 승인(`/`) + 감사·egress 대시보드(`/audit`, `/egress`) |
| `pasu-audit` | 감사 sink — JSONL(stderr/파일/SIEM), 인메모리, OpenTelemetry(OTLP 스팬, `otel` feature) |
| `pasu-egress` · `pasu-ebpf` · `pasu-ebpf-common` | 커널 eBPF cgroup egress — default-deny allowlist, DNS-aware (Linux) |
| `pasu-daemon` | composition root — 정책 YAML을 커널 가드로 낮춤(정책 하나, 양 계층) |
| `pasu-cli` | `pasu` 명령 — `pasu run`으로 아무 에이전트나 가드된 cgroup에 감쌈 |

모든 crate는 `pasu-core`에만 의존(acyclic); 룰 포맷과 프레임워크 통합은 trait 뒤에서 교체 가능.

## 의존성

핵심 의존성은 재현성을 위해 핀 고정:

| 의존성 | 버전 | 라이선스 | 이유 |
|---|---|---|---|
| [rig](https://github.com/0xPlaygrounds/rig) (`rig-core`) | git `747b95a6` | MIT | `AgentHook`이 upstream 머지됐으나 아직 릴리스 전; rig 다음 릴리스에 crates.io로 |
| [aya](https://github.com/aya-rs/aya) (+ `aya-log`, `aya-build`) | git `773ca715` | MIT / Apache-2.0 | aya 다음 릴리스 전까지 핀 — 미핀 git 의존이 CI를 깨뜨린 적 있음(upstream API drift) |
| [Falco](https://github.com/falcosecurity/falco) | — | — | **의존성 아님** — 룰 포맷 *아이디어*만 차용, Falco 코드 없음 |

## 지표

- **10개 crate**, acyclic 코어 하나 (모든 crate는 `pasu-core`에만 의존)
- **테스트**: 워크스페이스 전반 unit + 실제 커널 eBPF E2E (GitHub 러너 + Lima VM)
- **CI**: 4잡 그린 — `check`(stable) · `eBPF build+unit`(nightly + bpf-linker) · `eBPF E2E`(privileged) · `cargo-deny`(advisories/licenses/sources)
- **정책 평가**: ~0.11–0.12 µs/decision (criterion) — tool 호출 옆에선 사실상 공짜
- **default-deny allowlist**, **DNS-aware**, **HITL**, **JSONL / OTLP 감사**, **쿠버네티스 불필요**, **망분리 동작**

## 상태

MVP — 엔진·정책·HITL·감사·배포·벤치가 갖춰짐.

| 기능 | crate | 상태 |
|---|---|:---:|
| 커널 default-deny allowlist (DNS-aware) | egress/ebpf | ✅ |
| 정책 언어 (YAML) | rules | ✅ |
| tool 게이트 · HITL · LLM egress | rig | ✅ |
| 승인 + 감사 UI | ui | ✅ |
| 감사 sink (JSONL / OTLP) | audit | ✅ |
| config 기반 daemon + systemd | egress + packaging | ✅ |
| **정책 파일 하나 → 양 계층** | daemon | ✅ |

다음: 정밀 DNS 응답 스니핑(toFQDN — 커널서 접미 호스트 해금), eBPF 계층 감사 emit, 컨트롤 플레인 API + 리치 UI, crates.io 릴리스(rig 현재 git-pin).

## 개발

```bash
cargo test              # 포터블 크레이트: core, rig, rules, ui, audit (stable)
cargo build -p pasu-egress   # eBPF 스택 — Linux 전용, nightly + bpf-linker
```

## 플랫폼

Linux first, **셀프호스티드·망분리 친화** — eBPF 커널 강제는 Linux 전용, 단일 호스트, 쿠버네티스·런타임 call-home 없음. 텔레메트리 export(OTLP/JSONL)는 opt-in이고 당신의 collector를 가리킵니다. macOS/Windows는 개발용으로 rig 통합 + UI(협조적)만, 커널 강제는 없음.

## 기여

기여 환영 — [CONTRIBUTING.md](CONTRIBUTING.md) 참고. 요약: Conventional Commits, DCO sign-off(`git commit -s`), feature branch → PR → CI green.

## 보안

pasu는 커널에서 도는 보안 도구입니다. 취약점은 비공개로 제보해 주세요 — [SECURITY.md](SECURITY.md).

## 감사의 글

- [rig](https://github.com/0xPlaygrounds/rig)(`rig-core`, MIT)로 구축.
- 정책 문법은 [Falco](https://github.com/falcosecurity/falco)의 룰 포맷에서 영향받음. pasu는 Falco 프로젝트/CNCF와 제휴·보증 관계가 아닙니다.

## 라이선스

[Apache-2.0](LICENSE).
