# Pasu

A Rust security guard for AI agents. Pasu's core is a kernel **eBPF egress guard**
(language-agnostic, enforcing), extended by a **rig integration** that makes a rig
agent secure by default.

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

The cooperative layer sees only declared tool calls and egress. A tool that runs its
own network code bypasses it — so the kernel eBPF guard is the enforcing backstop.
**enforcing > cooperative.** Both layers are toggleable, and both evaluate the same
`Event → RuleEngine → Verdict` policy.

## Crates

| crate | role |
|-------|------|
| `pasu-core` | shared types: `Event` / `Verdict`; `RuleEngine` · `Layer` · `Approver` · `AuditSink` traits |
| `pasu-rules` | `RuleEngine` impl — Falco-inspired YAML ruleset (allow/deny/ask, default fail-closed) |
| `pasu-rig` | rig integration: `AgentHook` (tool gate + HITL) + `HttpClientExt` (LLM egress) |
| `pasu-ui` | lightweight web UI: HITL approval queue (`/`) + audit dashboard (`/audit`) |
| `pasu-audit` | audit sinks: JSONL (stderr / file / SIEM) and in-memory |
| `pasu-egress` · `pasu-ebpf` · `pasu-ebpf-common` | kernel eBPF cgroup egress guard — default-deny allowlist, DNS-aware (Linux) |

## Policy (Falco-inspired YAML)

```yaml
rules:
  - name: allow-llm
    match: { host: ".openai.com" }   # domain + subdomains
    action: allow
  - name: confirm-transfer
    match: { tool: transfer_funds }
    action: ask                      # human-in-the-loop
default: deny                        # fail-closed
```

## Quickstart (sketch)

Guard a rig agent (tool gate + HITL + LLM egress), emitting audit records:

```rust
use pasu_rig::PasuSecurityHook;
use pasu_rules::RulesetEngine;

let engine = RulesetEngine::from_yaml(policy_yaml)?;
let hook = PasuSecurityHook::new(engine).with_sink(audit_sink);   // + .with_approver(ui)
agent.prompt("do the task").add_hook(hook).await?;
```

Kernel egress guard on Linux (a **dedicated** cgroup — never the root cgroup):

```bash
sudo pasu-egress --cgroup-path /sys/fs/cgroup/my-agent --allow-domain api.openai.com
```

Approval + audit web UI:

```rust
pasu_ui::serve(addr, approvals, feed).await?;   // "/" = approvals, "/audit" = decisions
```

- **License**: Apache 2.0
- **Platform**: Linux first (eBPF kernel enforcement; macOS/Windows get the rig integration + UI, no kernel enforcement)
- **Status**: MVP — engine, policy, HITL, and audit are in place; daemon packaging (systemd) is next.

## Design docs

Detailed design (positioning · architecture · repo-structure · rig-integration · rules · testing) lives in the project vault; `docs/` in the repo is in progress.

## Development

```bash
cargo test              # portable crates: core, rig, rules, ui, audit (stable)
# eBPF stack (Linux only, nightly + bpf-linker):
cargo build -p pasu-egress
```

> **Dev rules: [CLAUDE.md](CLAUDE.md) — must follow** (keep separation/abstraction, tests required, fail-closed, etc.)
