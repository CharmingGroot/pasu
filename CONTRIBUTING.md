# Contributing to pasu

Thanks for helping build pasu. It's a security tool, so a few rules keep it
trustworthy. (Maintainer/AI working rules live in [CLAUDE.md](CLAUDE.md); this is
the short version for contributors.)

## Ground rules

- **Conventional Commits**: `type(scope): description`. Scope aligns with area —
  `rig` / `egress` / `ebpf` / `rules` / `ui` / `audit` / `core` / `ci` / `docs`.
- **DCO sign-off**: commit with `git commit -s` (you certify you wrote it).
  Contribute under your own name — no AI-authorship attribution.
- **Branch → PR → CI green → merge.** No direct pushes to `main`.
- **One PR = one problem.** Keep changes isolated and reviewable.

## Tests are mandatory (this is a security tool)

- Rule/logic changes need regression tests: **fail before the fix, pass after.**
- **TP + TN pairs**: prove a dangerous action is blocked *and* a legitimate one
  still passes (no over-blocking / false-positive regressions).
- **Bypass tests**: prove *enforcing > cooperative* — e.g. a tool that bypasses
  the in-process hook with its own egress is still dropped by the kernel.
- **fail-closed**: if the guard cannot operate, deny. Don't add fail-open paths
  for convenience.

## Building

| target | toolchain | command |
|--------|-----------|---------|
| portable crates (core, rig, rules, ui, audit) | stable | `cargo test` |
| eBPF stack (egress, ebpf) | Linux + nightly + `bpf-linker` | `cargo build -p pasu-egress` |

The eBPF stack is kept out of `default-members`, so `cargo test` and the stable
CI job stay green without a bpf toolchain.

## Architecture rules

- Keep crates separate; everything depends only on `pasu-core` (acyclic graph).
- Implementations live behind traits (`RuleEngine`, `Layer`, `Approver`,
  `AuditSink`) so they stay swappable.
- If a change would break a crate boundary or a trait abstraction — **stop and
  propose a redesign** rather than coupling things ad hoc.

## Getting help

- **Bugs / features** → open a GitHub Issue.
- **Design / questions** → open a GitHub Discussion.
- **Security vulnerabilities** → **do not** open a public issue; see
  [SECURITY.md](SECURITY.md).
