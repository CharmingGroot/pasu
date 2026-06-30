# CLAUDE.md — Pasu Development Rules

This file defines rules that Claude (and contributors) **must follow** when working in Pasu.
These rules take precedence over default behavior.

## Project

Pasu is a Rust security guard for AI agents. Its core is a kernel **eBPF egress guard** (language-agnostic, enforcing), extended by a **rig integration** (a secure-by-default agent SDK). The differentiator is **enforcing** (the kernel actually blocks egress, unbypassable) rather than cooperative (only sees what is declared).

Two layers:

| Layer | Where | Role | crate |
|-------|-------|------|-------|
| rig integration | in-process (cooperative) | tool-call gate + HITL (`AgentHook`), LLM egress (`HttpClientExt`) | `pasu-rig` |
| eBPF egress | kernel (enforcing) | `connect()` / cgroup egress block — unbypassable | `pasu-egress` + `pasu-ebpf` |

The cooperative layer filters first; egress that bypasses it (e.g. a tool's own network code) is stopped at the kernel.

Detailed design lives in `docs/` (positioning · architecture · repo-structure · rig-integration · rules · testing; in progress).
**Read the relevant design doc before starting work.**

---

## Hard Rules (stop and report if violated)

### 1. Architecture — keep separation/abstraction

- **Keep crates separate**: the rig integration (`pasu-rig`), egress layers (`pasu-egress` / `pasu-ebpf`), and the rule engine (`pasu-rules`) are independent crates. **No direct dependency between them.** They depend only on `pasu-core` (acyclic dependency graph). The `rig` dependency is isolated to `pasu-rig` so `pasu-core` stays pure (other framework adapters can be added beside it).
- **Implementations behind traits**: `RuleEngine` / `Layer` / `Transport`. Concrete implementations (Falco, eBPF, socket) stay behind traits so they are **replaceable**. Callers see only the trait.
- **Toggle ≠ split**: keep both runtime toggle (config `<layer>.enabled`) and build-time separation (crate/feature).
- If a feature would break a crate boundary or trait abstraction — **stop and propose a redesign.** Do not couple things ad hoc.

### 2. Rules

- Rules **borrow Falco syntax** but stay behind the `RuleEngine` trait. The Falco dependency is isolated to the single `pasu-rules` crate.
- Separate `default/` (project-managed, overwritten on upgrade) from `user/` (user customization, preserved).

### 3. Tests — mandatory (this is a security tool)

- **Rule/logic changes need regression tests.** Fail before the fix / pass after (mutation sense). No empty coverage-filler tests.
- **E2E validates the production ruleset**, not a test-only mini ruleset.
- **TP + TN pairs**: both true positive (dangerous action blocked) and true negative (legitimate action passes — false-positive regression).
- **Bypass (adversarial) tests**: prove enforcing > cooperative (e.g. a tool bypasses `AgentHook` with its own egress → eBPF blocks it).
- **No rule/logic change without tests.**

### 4. fail-safe

- This is a security tool. **fail-closed**: if the guard cannot operate, deny. Do not add bypass paths (e.g. fail-open defaults) for convenience.

### 5. Commits / PRs

- **Conventional Commits** (`type(scope): description`). Scope aligns with area (`rig` / `egress` / `ebpf` / `rules` / `core` / `ci` / `docs`).
- **DCO sign-off required**: `git commit -s`.
- **No AI attribution**: do not add `Co-Authored-By: Claude` or similar. Contributions under your own name.
- **Isolated scope**: one PR = one problem.
- **All changes go feature branch → PR → CI green → merge.** No direct push to main. Commits/pushes/PRs go out externally, so confirm with the user first.

### 6. Code style (Rust)

- Early returns (no deep nesting), no needless mutation, fully typed (avoid coarse types), composition over inheritance.
- Minimal comments — aim for self-evident code. Magic numbers/strings go in `constants`.
- No `unwrap` / `expect` / `panic` on user/network input paths. Model failures as values (`Result`).

### 7. Platform

- **Linux first.** eBPF is Linux-only — macOS/Windows run only the rig integration (cooperative; no kernel egress enforcement), and that must be stated.
- eBPF changes need care around kernel privileges (CAP_BPF) and kernel version dependencies.

---

## Build / Test

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --check
```

## Think first

If a request has multiple interpretations, present options instead of guessing. If a simpler path exists, say so. If something is unclear, stop and name what is unclear.
