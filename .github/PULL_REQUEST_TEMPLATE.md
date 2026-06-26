<!--
PR 가이드 (CLAUDE.md 작업 룰 준수):
- /kind, /area 라벨 (아래 주석 해제)
- DCO sign-off 필수 (git commit -s)
- scope 격리: 한 PR = 한 문제
- 룰/로직 변경엔 회귀 테스트 동반 (TP+TN, 우회)
- 미완성이면 제목 앞에 wip:
-->

**Type** (uncomment):
> /kind bug
> /kind feature
> /kind cleanup
> /kind docs
> /kind failing-test

**Area** (uncomment):
> /area l1-toolgate
> /area l2-proxy
> /area l3-ebpf
> /area rules
> /area ci
> /area docs

**What this PR does / why**:

**Which issue(s) this PR fixes**: Refs #

**Tests** (보안 도구 — 필수):
- [ ] 회귀 테스트 추가 (fix 전 fail / 후 pass)
- [ ] TP(차단) + TN(통과) 쌍
- [ ] (해당 시) 우회 테스트

```release-note

```
