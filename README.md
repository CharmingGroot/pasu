# Pasu

A Rust security guard for AI agents. Pasu enforces hard blocks on an agent's **tool calls and egress (outbound network)** across multiple layers.

Egress control is layered along the OSI stack, with a tool-call gate on top:

```
tool call ──▶ [tool gate]      pre-execution block on tool calls (application level)
HTTP/socket ─▶ [egress proxy]  L7 domain / URL / DLP
                 │
                 ▼
              [eBPF]           kernel-level connect() block (OSI L3/L4, unbypassable)
```

| Layer | OSI | Role | crate |
|-------|-----|------|-------|
| **eBPF** | L3/L4 (kernel) | `connect()` hard block — deepest, unbypassable | `pasu-ebpf` |
| **egress proxy** | L7 (application) | HTTP domain / URL / DLP | `pasu-egress` |
| **tool gate** | app (above OSI) | pre-execution tool-call block (user-defined rules) | `pasu-toolgate` |

Beyond cooperative (sees only what is declared) — **enforcing** (actually blocks). All three layers are toggleable.

- **License**: Apache 2.0
- **Platform**: Linux first (eBPF only; macOS/Windows get egress proxy + tool gate)
- **Status**: MVP bootstrap

## Design docs

Detailed design lives in `docs/` (architecture · repo-structure · rules · testing; in progress).

## Development

```bash
cargo build --workspace
cargo test --workspace
```

> **Dev rules: [CLAUDE.md](CLAUDE.md) — must follow** (keep separation/abstraction, tests required, fail-closed, etc.)
