# Pasu

A Rust security guard for AI agents. Pasu's core is a kernel **eBPF egress guard** (language-agnostic, enforcing), extended by a **rig integration** that makes a rig agent secure by default.

Two layers — a cooperative in-process layer, backed by an enforcing kernel layer:

```
              rig agent
                 │
 tool call ─▶ [pasu-rig · AgentHook]       tool-call gate + HITL approval   ┐ cooperative
 LLM call  ─▶ [pasu-rig · HttpClientExt]   LLM provider egress by policy    ┘ (in-process)
                 │
 any egress ▶ [eBPF cgroup egress]         kernel connect()/egress block     ← enforcing
                                           (unbypassable, language-agnostic)    (kernel)
```

| Layer | Where | Role | crate |
|-------|-------|------|-------|
| **rig integration** | in-process (cooperative) | tool-call gate + HITL (`AgentHook`), LLM egress (`HttpClientExt`) | `pasu-rig` |
| **eBPF egress** | kernel (enforcing) | `connect()` / cgroup egress block — unbypassable | `pasu-egress` + `pasu-ebpf` |

The cooperative layer sees only declared tool calls and egress. A tool that runs its own network code bypasses it — so the kernel eBPF guard is the enforcing backstop. **enforcing > cooperative.** Both layers are toggleable.

- **License**: Apache 2.0
- **Platform**: Linux first (eBPF kernel enforcement; macOS/Windows get the rig integration only)
- **Status**: MVP bootstrap

## Design docs

Detailed design lives in `docs/` (positioning · architecture · repo-structure · rig-integration · rules · testing; in progress).

## Development

```bash
cargo build --workspace
cargo test --workspace
```

> **Dev rules: [CLAUDE.md](CLAUDE.md) — must follow** (keep separation/abstraction, tests required, fail-closed, etc.)
