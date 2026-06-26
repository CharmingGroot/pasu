# Pasu

Rust 기반 AI 에이전트 보안 가드. 에이전트의 **tool call + egress(나가는 네트워크)** 를 다층으로 **강제 차단**한다.

egress 차단을 OSI 스택을 따라 쌓고, 그 위에 tool call 게이트를 더한 다층 방어:

```
tool call ──▶ [tool gate]      tool call 사전 차단 (애플리케이션 레벨)
HTTP/소켓 ──▶ [egress proxy]   L7 도메인·URL·DLP
                 │
                 ▼
              [eBPF]           커널서 connect() 강제 차단 (OSI L3/L4, 우회 불가)
```

| 레이어 | OSI | 역할 | crate |
|--------|-----|------|-------|
| **eBPF** | L3/L4 (커널) | connect() 강제 차단 — 가장 깊은, 우회 불가 | `pasu-ebpf` |
| **egress proxy** | L7 (응용) | HTTP 도메인·URL·DLP | `pasu-egress` |
| **tool gate** | 앱 (OSI 위) | tool call 사전 차단 (사용자 정의 룰) | `pasu-toolgate` |

cooperative(선언만 봄)를 넘어 **enforcing**(실제 차단). 셋 다 토글 가능.

- **라이선스**: Apache 2.0
- **플랫폼**: Linux first (eBPF 전용; mac/win은 egress proxy + tool gate)
- **상태**: MVP 부트스트랩

## 설계 문서

상세 설계는 `docs/`에 정리한다 (architecture · repo-structure · rules · testing; 작성 중).

## 개발

```bash
cargo build --workspace
cargo test --workspace
```

> **개발 작업 룰: [CLAUDE.md](CLAUDE.md) — 반드시 준수** (분리/추상화 유지, 테스트 필수, fail-closed 등)
