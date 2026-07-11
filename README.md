<p align="center">
  <img src="docs/logo.svg" width="112" alt="pasu — a gate that lets only the allowed flow through">
</p>

<h1 align="center">pasu &nbsp;<sub><sup>把守</sup></sub></h1>

<p align="center">
  <b>A security guard for AI agents — trust the policy, not the agent.</b><br>
  Kernel-enforced egress control (eBPF) + a secure-by-default <a href="https://github.com/0xPlaygrounds/rig">rig</a> integration.
</p>

<p align="center">
  <a href="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml"><img src="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/rust-edition%202021-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux%20first-lightgrey.svg" alt="Platform: Linux first">
</p>

> **Control an agent's egress without trusting the agent.**
> An in-process hook only sees what the agent *declares* — a tool that opens its
> own socket walks right past it. pasu backs that cooperative layer with a
> **kernel eBPF guard the agent cannot bypass**. **enforcing > cooperative.**

---

## Why pasu

AI agents get prompt-injected, and a compromised agent will happily exfiltrate
your data. Framework-level guards are *cooperative*: they inspect declared tool
calls and egress, but a tool running its own network code slips past them.

pasu runs **two layers that share one policy**:

<p align="center">
  <img src="docs/flow.svg" width="760" alt="pasu two-layer egress defense: one policy drives a cooperative rig hook and an enforcing kernel eBPF guard; a rogue egress that bypasses the hook is still dropped by the kernel">
</p>

- **① Cooperative — in-process (`pasu-rig`)**: tool-call gate + HITL approval, LLM egress by policy. Rich context; bypassable.
- **② Enforcing — kernel (`pasu-egress` / `pasu-ebpf`)**: cgroup egress in the kernel. Language-agnostic, **unbypassable**.

Proven end-to-end: a tool that bypasses the hook with its own `reqwest` is still
**dropped by the kernel** (the eBPF + rig combo demo).

## How pasu compares

| | **pasu** | framework wrappers | general policy engines |
|---|:---:|:---:|:---:|
| Kernel enforcing (unbypassable) | ✅ eBPF | ❌ cooperative | ~ (Falco = observe) |
| Agent-SDK integration | ✅ rig | ✅ | ❌ |
| Human-in-the-loop approval | ✅ | partial | ❌ |
| Language-agnostic protection | ✅ | ❌ | ✅ |
| Policy as code | ✅ YAML | partial | ✅ |
| Rust · ~0.12 µs/decision | ✅ | — | — |

The uncommon combination: **agent-SDK + kernel enforcing + HITL + audit, in Rust.**

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

## Quickstart

### Wrap any agent — no code changes

pasu is a **guard, not an agent**: it doesn't care what framework your agent
uses. `pasu run` puts the command in a dedicated cgroup with the kernel guard
attached before its first instruction:

```bash
sudo pasu run --policy rules.yaml -- python crew.py        # CrewAI / LangChain / anything
sudo pasu run --policy rules.yaml -- npx some-agent "task" # language-agnostic
```

Everything the policy doesn't allow is dropped by the kernel — even if the
agent (or a prompt-injected tool) opens its own sockets.

### Deeper: in-process hooks (optional)

Guard a rig agent (tool gate + HITL + LLM egress) with audit:

```rust
use pasu_rig::PasuSecurityHook;
use pasu_rules::RulesetEngine;

let engine = RulesetEngine::from_yaml(policy_yaml)?;
let hook = PasuSecurityHook::new(engine).with_sink(audit_sink);   // + .with_approver(ui)
agent.prompt("do the task").add_hook(hook).await?;
```

Kernel egress guard on Linux — **the same YAML**, lowered to the kernel
allowlist (a **dedicated** cgroup; never the root cgroup):

```bash
sudo pasu-daemon --policy rules.yaml --cgroup-path /sys/fs/cgroup/my-agent
# lower-level loader (flags / TOML) if you don't want the policy file:
sudo pasu-egress --cgroup-path /sys/fs/cgroup/my-agent --allow-domain api.openai.com
```

Allow rules with an IPv4 become static entries, exact hostnames are resolved
(and re-resolved), and suffix patterns (`.openai.com`) are reported — they stay
hook-layer-only until DNS-response sniffing lands. The kernel side is
default-deny, so lowering is only ever *narrower* than the policy.

Add `--admin-socket /run/pasu.sock` to inspect and edit the live guard without a
restart (this is what the UI talks to):

```bash
echo status        | socat - UNIX-CONNECT:/run/pasu.sock   # {"cgroup_path":…,"allow_ips":[…]}
echo 'allow 1.2.3.4' | socat - UNIX-CONNECT:/run/pasu.sock  # add to the kernel allowlist now
echo 'deny 1.2.3.4'  | socat - UNIX-CONNECT:/run/pasu.sock  # remove it now
```

Web UI — approvals (`/`), audit (`/audit`), and a live **egress dashboard**
(`/egress`: kernel filter coverage, add/remove allowlist entries, read-only
policy view with each rule's verdict + tool guard):

```rust
use pasu_ui::dashboard::{EgressAdmin, EgressUi};
let egress = EgressUi::new(EgressAdmin::new("/run/pasu.sock"), Some("rules.yaml".into()));
pasu_ui::serve_all(addr, approvals, feed, Some(egress)).await?;   // + /egress
```

Try it without a kernel (mock guard socket):

```bash
cargo run -p pasu-ui --example ui_demo   # http://127.0.0.1:8787/egress
```

## Run in a container

The kernel guard containerizes like any eBPF tool — `CAP_BPF` + `CAP_NET_ADMIN`
and a cgroup v2 mount. Quick proof (only `1.1.1.1` allowed; the kernel drops
everything else, whatever the app does):

```bash
docker build -f deploy/Dockerfile -t pasu-egress:latest .
./deploy/demo.sh    # allowed -> reachable · blocked -> dropped · RESULT: PASS
```

Sidecar ([`deploy/docker-compose.yml`](deploy/docker-compose.yml)) and Kubernetes
([`deploy/k8s/`](deploy/k8s)) layouts, and the cgroup-targeting rules, are in
**[docs/deployment.md](docs/deployment.md)**.

## Crates

<p align="center">
  <img src="docs/ia.svg" width="700" alt="pasu crate map: every crate depends only on pasu-core">
</p>

| crate | role |
|-------|------|
| `pasu-core` | shared types (`Event` / `Verdict`) + traits (`RuleEngine` · `Layer` · `Approver` · `AuditSink`) |
| `pasu-rules` | `RuleEngine` — Falco-inspired YAML ruleset (allow/deny/ask, default fail-closed) |
| `pasu-rig` | rig integration — `AgentHook` (tool gate + HITL), `HttpClientExt` (LLM egress) |
| `pasu-ui` | lightweight web UI — HITL approvals (`/`) + audit dashboard (`/audit`) |
| `pasu-audit` | audit sinks — JSONL (stderr / file / SIEM) and in-memory |
| `pasu-egress` · `pasu-ebpf` · `pasu-ebpf-common` | kernel eBPF cgroup egress — default-deny allowlist, DNS-aware (Linux) |
| `pasu-daemon` | composition root — lowers the policy YAML to the kernel guard (one policy, both layers) |
| `pasu-cli` | the `pasu` command — `pasu run` wraps any agent command in a guarded cgroup |

Every crate depends only on `pasu-core` (acyclic); the rule format and framework
integration are swappable behind traits.

## Numbers

- **9 crates**, one acyclic core
- **Tests**: 48 unit + eBPF end-to-end on a real kernel (GitHub runner + Lima VM)
- **CI**: 3 jobs green — `check` (stable) · `eBPF build+unit` (nightly + bpf-linker) · `eBPF E2E` (privileged)
- **Policy evaluation**: ~0.11–0.12 µs/decision (criterion) — effectively free next to a tool call
- **default-deny allowlist**, **DNS-aware**, **HITL**, **JSONL audit**

## Status

MVP — the engine, policy, HITL, audit, deployment, and benchmarks are in place.

| capability | crate | state |
|---|---|:---:|
| kernel default-deny allowlist (DNS-aware) | egress/ebpf | ✅ |
| policy language (YAML) | rules | ✅ |
| tool gate · HITL · LLM egress | rig | ✅ |
| approval + audit UI | ui | ✅ |
| audit sinks (JSONL) | audit | ✅ |
| config-driven daemon + systemd | egress + packaging | ✅ |
| **one policy file → both layers** | daemon | ✅ |

Next: precise DNS-response sniffing (toFQDN — unlocks suffix hosts in the
kernel), eBPF-layer audit emission, a control-plane API + richer UI, and a
crates.io release (rig is currently git-pinned).

## Development

```bash
cargo test              # portable crates: core, rig, rules, ui, audit (stable)
cargo build -p pasu-egress   # eBPF stack — Linux only, nightly + bpf-linker
```

## Platform

Linux first — eBPF kernel enforcement is Linux-only. macOS/Windows get the rig
integration + UI (cooperative), without kernel enforcement.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). In short:
Conventional Commits, DCO sign-off (`git commit -s`), feature branch → PR → CI green.

## Security

pasu is a security tool that runs in the kernel. Please report vulnerabilities
privately — see [SECURITY.md](SECURITY.md).

## Acknowledgements

- Built with [rig](https://github.com/0xPlaygrounds/rig) (`rig-core`), licensed under MIT.
- The policy syntax is inspired by [Falco](https://github.com/falcosecurity/falco)'s rule
  format. pasu is not affiliated with or endorsed by the Falco project or the CNCF.

## License

[Apache-2.0](LICENSE).
