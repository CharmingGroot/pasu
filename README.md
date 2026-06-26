# Pasu

Rust 기반 AI 에이전트 보안 가드. 에이전트의 **tool call + egress(나가는 네트워크)** 를 다층(L1/L2/L3)으로 **강제 차단**한다.

```
L1  tool call gate   사전 차단 (사용자 정의 룰)
L2  egress proxy      L7 도메인·URL·DLP
L3  eBPF              커널서 connect() 강제 차단 (우회 불가)
```

cooperative(선언만 봄)를 넘어 **enforcing**(실제 차단). 셋 다 토글 가능.

- **라이선스**: Apache 2.0
- **플랫폼**: Linux first (L3 eBPF 전용; mac/win은 L1+L2)
- **상태**: MVP 부트스트랩 (L1부터)

## 설계 문서

상세 설계는 `docs/`에 정리한다 (architecture · repo-structure · rules · testing; 작성 중).

## 개발

```bash
cargo build --workspace
cargo test --workspace
```

> **개발 작업 룰: [CLAUDE.md](CLAUDE.md) — 반드시 준수** (분리/추상화 유지, 테스트 필수, fail-closed 등)
