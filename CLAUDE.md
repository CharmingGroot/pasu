# CLAUDE.md — Pasu Development Rules

This file defines rules that Claude (and contributors) **must follow** when working in Pasu.
These rules take precedence over default behavior.

## Project

Pasu is a Rust security guard for AI agents. It enforces hard blocks on an agent's **tool calls and egress** across multiple layers. The differentiator is **enforcing** (actually blocks) rather than cooperative (only sees what is declared).

Layers follow OSI convention (deeper = lower OSI level):

| Layer | OSI | crate |
|-------|-----|-------|
| eBPF | L3/L4 (kernel) | `pasu-ebpf` |
| egress proxy | L7 (application) | `pasu-egress` |
| tool gate | app (above OSI) | `pasu-toolgate` |

Detailed design lives in `docs/` (architecture · repo-structure · rules · testing; in progress).
**Read the relevant design doc before starting work.**

---

## Hard Rules (stop and report if violated)

### 1. Architecture — keep separation/abstraction

- **Keep crates separate**: layers (`pasu-ebpf` / `pasu-egress` / `pasu-toolgate`) and the rule engine (`pasu-rules`) are independent crates. **No direct dependency between them.** They depend only on `pasu-core` (acyclic dependency graph).
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
- **Bypass (adversarial) tests**: prove enforcing > cooperative (e.g. egress-proxy bypass → eBPF blocks it).
- **No rule/logic change without tests.**

### 4. fail-safe

- This is a security tool. **fail-closed**: if the guard cannot operate, deny. Do not add bypass paths (e.g. fail-open defaults) for convenience.

### 5. Commits / PRs

- **Conventional Commits** (`type(scope): description`). Scope aligns with area (`toolgate` / `egress` / `ebpf` / `rules` / `ci` / `docs`).
- **DCO sign-off required**: `git commit -s`.
- **No AI attribution**: do not add `Co-Authored-By: Claude` or similar. Contributions under your own name.
- **Isolated scope**: one PR = one problem.
- **All changes go feature branch → PR → CI green → merge.** No direct push to main. Commits/pushes/PRs go out externally, so confirm with the user first.

### 6. Code style (Rust)

- Early returns (no deep nesting), no needless mutation, fully typed (avoid coarse types), composition over inheritance.
- Minimal comments — aim for self-evident code. Magic numbers/strings go in `constants`.
- No `unwrap` / `expect` / `panic` on user/network input paths. Model failures as values (`Result`).

### 7. Platform

- **Linux first.** eBPF is Linux-only — macOS/Windows run only egress proxy + tool gate, and that must be stated.
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
