# CLAUDE.md — Pasu Development Rules

This file defines rules that Claude (and contributors) **must follow** when working in Pasu.
These rules take precedence over default behavior.

## Project

Pasu is a Rust security guard for AI agents. Its core is a kernel **eBPF egress guard** (language-agnostic, enforcing), extended by an **LLM-API proxy** that guards tool calls by parsing provider responses (framework-agnostic — any SDK, `base_url` only). The differentiator is **enforcing** (the kernel actually blocks egress, unbypassable) rather than cooperative (only sees what is declared).

**Concept (decided 2026-07-10): pasu is a GUARD APPLIANCE, not an agent.**
- pasu never performs agent work; it wraps/controls agents. Do not add agent
  capabilities (LLM calling, task execution) to pasu itself.
- Adoption UX is **`pasu run -- <any agent command>`** (kernel egress) or
  pointing the agent's `base_url` at **`pasu-proxy`** (tool-call guard): wrap any
  framework (LangChain, CrewAI, CLI agents) with zero code changes — both layers
  are framework/language-agnostic by construction.
- Framework-specific in-process SDK hooks are intentionally NOT the path. Tool
  intent is captured at the provider-API boundary (`pasu-proxy`, ~3 provider
  formats cover every SDK), never via a per-SDK adapter.
- Positioning line: *"Don't trust your agent. Jail it."*

Two layers:

| Layer | Where | Role | crate |
|-------|-------|------|-------|
| LLM-API proxy | provider-API boundary (cooperative) | tool-call gate + HITL by parsing provider responses; framework-agnostic | `pasu-proxy` |
| eBPF egress | kernel (enforcing) | `connect()` / cgroup egress block — unbypassable | `pasu-egress` + `pasu-ebpf` |

The proxy filters tool-call intent first; egress that bypasses it (e.g. a tool's own network code) is stopped at the kernel.

Detailed design lives in `docs/` (positioning · architecture · repo-structure · rules · testing; in progress).
**Read the relevant design doc before starting work.**

---

## Hard Rules (stop and report if violated)

### 1. Architecture — keep separation/abstraction

- **Keep crates separate**: the LLM-API proxy (`pasu-proxy`), egress layers (`pasu-egress` / `pasu-ebpf`), and the rule engine (`pasu-rules`) are independent crates. **No direct dependency between them.** They depend only on `pasu-core` (acyclic dependency graph). App-level binaries (`pasu-proxy`, `pasu-daemon`) may wire a concrete engine (`pasu-rules`); the library crates stay pure behind `pasu-core`.
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

- **Conventional Commits** (`type(scope): description`). Scope aligns with area (`proxy` / `egress` / `ebpf` / `rules` / `core` / `ci` / `docs`).
- **DCO sign-off required**: `git commit -s`.
- **No AI attribution**: do not add `Co-Authored-By: Claude` or similar. Contributions under your own name.
- **Isolated scope**: one PR = one problem.
- Commits/pushes/PRs go out externally, so **confirm with the user first**.

### 5a. Branching model — `main` → release → feature

Three tiers. Never commit directly to `main` or a release branch.

- **`main`** — always releasable, protected. **Only the user merges a release
  branch into `main`, manually, at a release point.** The agent never merges to
  `main`.
- **release branch** (`release/vX.Y`) — the integration branch for the next
  release. Feature branches target it; it accumulates finished features until
  the user cuts the release.
- **feature branch** (`type/short-topic`, e.g. `feat/dns-sniffing`) — branch
  **off the current release branch**, one problem each, PR **back into that
  release branch** (not `main`).

Flow for a feature:
1. `git switch <release/vX.Y>` → `git switch -c feat/<topic>`.
2. Implement + **tests** (see rule 3) until coverage is met — TP/TN pairs,
   bypass test, fail-closed; the eBPF paths validated on a real kernel.
3. Open a PR into `release/vX.Y`; CI must be green before merge.
4. **The user decides release timing** and merges `release/vX.Y` → `main`.

Stacked features: if B depends on A, base B on A's branch and note it in the PR;
merge A first. Do **not** `--delete-branch` a branch another PR is based on.

### 6. Code style (Rust)

- Early returns (no deep nesting), no needless mutation, fully typed (avoid coarse types), composition over inheritance.
- Minimal comments — aim for self-evident code. Magic numbers/strings go in `constants`.
- No `unwrap` / `expect` / `panic` on user/network input paths. Model failures as values (`Result`).

### 7. Platform

- **Linux first.** eBPF is Linux-only — macOS/Windows run only the LLM-API proxy (cooperative; no kernel egress enforcement), and that must be stated.
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
