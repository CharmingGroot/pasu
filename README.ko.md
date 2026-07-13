<p align="center">
  <img src="docs/logo.svg" width="112" alt="pasu — 허용된 흐름만 통과시키는 관문">
</p>

<h1 align="center">pasu &nbsp;<sub><sup>把守</sup></sub></h1>

<p align="center">
  <b>AI 에이전트를 위한 셀프호스티드 보안 가드 — 온프렘·망분리(air-gapped)·규제 환경을 위해.</b><br>
  계층 방어 — 트레이싱 → tool 호출 가드 → 커널 강제 egress — 를 단일 Linux 호스트에서. 쿠버네티스도, 클라우드도 필요 없고, 네트워크 밖으로 아무것도 나가지 않습니다.
</p>

<p align="center"><a href="README.md">English</a></p>

> **에이전트를 신뢰하지 않고도 egress를 통제한다 — 우리 네트워크 안에서.**
> 인프로세스 훅은 에이전트가 *선언한 것*만 봅니다. 자체 소켓을 여는 도구는 그냥 지나가죠.
> pasu는 그 협조적 계층을 **에이전트가 우회할 수 없는 커널 eBPF 가드**로 받치고, 모든 결정을 감사용으로 기록합니다.
> 전부 호스트 안에서 동작 — SaaS로 보내는 것 없음. **enforcing > cooperative.**

---

## 왜 pasu인가

AI 에이전트는 프롬프트 인젝션(prompt injection)을 당하고, 침해된 에이전트는 기꺼이 데이터를 유출합니다. 에이전트를 **온프렘·망분리·컴플라이언스** 환경에서 돌린다면 두 가지가 따라옵니다 — 에이전트 트래픽을 클라우드/SaaS 가드로 보낼 수 *없고*, 단일 협조적 검사 하나가 아니라 **다층 방어 + 감사 증거**가 필요합니다.

pasu는 그 환경을 위해 만들어졌습니다. 단일 Linux 호스트에서 전부 동작하고, **쿠버네티스도 외부 서비스도 필요 없으며**, **정책 하나로 3계층**을 적용합니다:

- **① 트레이싱 / 감사** (`pasu-audit`): 모든 결정을 기록 — 파일/SIEM으로 JSONL, 또는 *당신의* 스택으로 OpenTelemetry(OTLP) 스팬. 네트워크 밖으로 나가는 것 없이 감사 증거 확보.
- **② tool 호출 가드 — 협조적, 인프로세스** (`pasu-rig`): 선언된 tool 호출 게이팅 + 사람 승인(HITL), 정책 기반 LLM egress. 맥락은 풍부하나 단독으론 우회 가능.
- **③ egress 강제 — 커널** (`pasu-egress` / `pasu-ebpf`): 커널 cgroup egress 기본 차단(default-deny). 언어 무관하며 **우회 불가** — ②를 빠져나간 것을 최종적으로 막습니다.

E2E로 증명: 훅을 우회해 자체 `reqwest`로 나가는 도구도 **커널이 drop**합니다.

## 온프렘·규제 적합성

드문 지점은 이 *조합*을, 단일 셀프호스티드 서버에서 제공한다는 것입니다:

- **쿠버네티스·클라우드 불필요.** Linux 호스트 하나. `pasu run`으로 아무 에이전트나 감쌈.
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

## 빠른 시작

### 아무 에이전트나 감싸기 — 코드 변경 없이

```bash
sudo pasu run --policy rules.yaml -- python crew.py        # CrewAI / LangChain / 무엇이든
sudo pasu run --policy rules.yaml -- npx some-agent "task"  # 언어 무관
```

정책이 허용하지 않은 것은 전부 커널이 drop합니다 — 에이전트(또는 인젝션된 도구)가 자체 소켓을 열어도.

### 정책 (Falco 영향 YAML)

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

배포(Docker/compose/Helm/k8s)·컨트롤 플레인·UI 등 상세는 영어 [README](README.md)와 [docs/deployment.md](docs/deployment.md)를 참고하세요.

## 라이선스

[Apache-2.0](LICENSE).
