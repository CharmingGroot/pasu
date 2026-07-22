<p align="center">
  <img src="docs/logo.svg" width="112" alt="pasu — a gate that lets only the allowed flow through">
</p>

<h1 align="center">pasu &nbsp;<sub><sup>把守</sup></sub></h1>

<p align="center">
  <b>A self-hosted security guard for AI agents — built for on-premises, air-gapped, and regulated environments.</b><br>
  Layered defense — trace → tool-call guard → kernel-enforced egress — on a single Linux host. No Kubernetes, no cloud, nothing leaves your network.
</p>

<p align="center">
  <a href="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml"><img src="https://github.com/CharmingGroot/pasu/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue.svg" alt="License: Apache-2.0">
  <img src="https://img.shields.io/badge/rust-edition%202021-orange.svg" alt="Rust">
  <img src="https://img.shields.io/badge/platform-Linux%20first-lightgrey.svg" alt="Platform: Linux first">
  <img src="https://img.shields.io/badge/deploy-self--hosted%20%C2%B7%20air--gapped-2b6cb0.svg" alt="Self-hosted / air-gapped">
  <img src="https://img.shields.io/badge/Kubernetes-not%20required-555.svg" alt="No Kubernetes required">
</p>

<p align="center"><a href="README.md">한국어</a></p>

> **Control an agent's egress without trusting the agent.**
> A cooperative guard only sees what the agent *declares*; a tool that opens its own
> socket walks right past it. pasu backs that layer with a **kernel eBPF guard the
> agent cannot bypass**, and records every decision for audit. It runs entirely
> on-host — nothing leaves your network. **enforcing > cooperative.**

---

## Why pasu

AI agents get prompt-injected, and a compromised agent becomes an exfiltration
channel. If you run agents **on-premises, air-gapped, or under compliance
requirements**, two more constraints apply: you *cannot* route agent traffic to
a cloud/SaaS guard, and you need **layered defense plus audit evidence** — not a
single cooperative check that a rogue tool slips past.

pasu is built to work within those constraints: it runs entirely on one Linux
host, needs **no Kubernetes and no external service**, and applies **three
layers, one policy**:

<p align="center">
  <img src="docs/flow.svg" width="760" alt="pasu layered egress defense: one policy drives a cooperative proxy and an enforcing kernel eBPF guard; a rogue egress that bypasses the proxy is still dropped by the kernel, and every decision is recorded for audit">
</p>

- **① Trace / audit** (`pasu-audit`): every decision is recorded — JSONL to a
  file/SIEM, or OpenTelemetry (OTLP) spans to *your own* stack. Audit evidence
  without anything leaving your network.
- **② Tool-call guard — cooperative** (`pasu-proxy` LLM-API proxy): point the
  agent's `base_url` at the proxy; it parses the tool calls in the provider
  response, gates them, and asks for human-in-the-loop approval when needed.
  **Framework-agnostic** — any SDK, `base_url` only. Rich context; bypassable
  on its own.
- **③ Egress enforcement — kernel** (`pasu-egress` / `pasu-ebpf`): default-deny
  cgroup egress in the kernel. Language-agnostic and **unbypassable** — it
  catches whatever slips past layer ②.

That last layer is the point: even if a tool bypasses layer ② and opens its own
`reqwest` connection, the kernel drops the egress — the exact case a
declared-only cooperative guard misses.

## On-prem & regulated fit

Tool-call guard, kernel egress, and audit on a single self-hosted box:

<p align="center">
  <img src="docs/onprem.svg" width="820" alt="On-prem AI agent before and after pasu: without pasu there is no guard point for the agent's tool calls and egress (cloud/SaaS guards can't run air-gapped, a firewall is all-or-nothing), so exfiltration and misuse can't be controlled per action; with pasu, one host runs pasu-proxy (layer 2 tool gate), eBPF kernel egress (layer 3 default-deny enforcement) and audit (layer 1) together, so only the allowed internal LLM passes and a bypass egress is dropped by the kernel">
</p>

- **No Kubernetes, no cloud.** One Linux host; wrap any agent with `pasu run`.
- **Runs air-gapped.** No runtime call-home; telemetry export is opt-in and points
  at your own collector.
- **Kernel-inline egress + agent intent + audit**, together on one host.
- **Apache-2.0**, auditable Rust, every crate behind traits.

## Limitations

- **Linux only** — eBPF kernel enforcement runs on Linux. macOS/Windows support the cooperative layer (the LLM-API proxy) only, with no kernel egress enforcement.
- **Requires kernel privileges** — the eBPF layer needs root or CAP_BPF (the proxy layer runs unprivileged).
- **Proxy layer is bypassable on its own** — a tool that opens its own socket is invisible to the proxy; the kernel layer covers that case.
- **L3/L4 egress control** — IP/domain level, with no TLS-payload or L7 content (DLP) inspection. Exfiltration to an already-allowed domain is not stopped by the allowlist.
- **Streaming is buffered** — SSE tool calls are reassembled and inspected, but the full stream is buffered and relayed at once (no incremental relay). DNS-awareness is best-effort.
- **Not an input-layer defense** — prompt injection and model misbehavior are out of scope. pasu is a last line of defense over egress and tool intent.
- **Early stage (MVP)** — no security certification, no production references.

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

### Guard tool calls for any SDK — the LLM-API proxy

Point your agent's `base_url` at `pasu-proxy`. It forwards to the real provider,
parses the tool calls the model returns, and blocks any the policy denies
(fail-closed) before the agent runs them. The tool-call decision rides in the
provider response, so parsing the provider format covers every SDK — no
per-framework adapter:

```rust
use pasu_core::Guard;
use pasu_proxy::{router, Provider, ProxyState};
use pasu_rules::RulesetEngine;
use std::sync::Arc;

let state = Arc::new(ProxyState {
    guard: Guard::new(RulesetEngine::from_yaml(policy_yaml)?, "llm-proxy"),
    client: reqwest::Client::new(),
    upstream_base: "https://api.openai.com".into(),
    provider: Provider::OpenAi,
});
let app = router(state);   // axum Router — serve it, then point the agent's base_url at it
```

Supports OpenAI-compatible, Anthropic, and Gemini (the three formats cover
effectively every SDK), for both non-streaming and streaming (SSE) responses —
SSE deltas are reassembled and judged by the same policy, with the full stream
buffered before relay.

Run the binary with `--ui <addr>` to attach human-in-the-loop approval — a web
queue (`/`) for pending `Ask` verdicts plus an audit view (`/audit`). Without
it, `Ask` fails closed.

Deploy it as a sidecar — a slim, **unprivileged** image
([`deploy/proxy/Dockerfile`](deploy/proxy/Dockerfile)) and an agent + proxy pod
([`deploy/proxy/k8s-sidecar.yaml`](deploy/proxy/k8s-sidecar.yaml), the agent's
`base_url` → `localhost`).

<p align="center">
  <img src="docs/sidecar.svg" width="820" alt="pasu-proxy as a sidecar: one pod holds the agent and the unprivileged pasu-proxy; only the agent's base_url changes (localhost). The proxy forwards to the provider, inspects tool calls in responses (deny 403, ask HITL) and writes stderr JSONL audit. On the node, the privileged pasu-egress kernel guard is optional defense-in-depth — a direct socket that bypasses the proxy is dropped in the kernel">
</p>

The simplest attach: one proxy container, and **one env var** on the agent side:

```bash
docker build -f deploy/proxy/Dockerfile -t pasu-proxy .
docker run -d -p 8788:8788 -v "$PWD/rules.yaml:/etc/pasu/rules.yaml:ro" pasu-proxy
export OPENAI_BASE_URL=http://127.0.0.1:8788/v1   # that's it (OpenAI-SDK family)
```

The default CMD forwards to `api.openai.com` with the mounted policy; for an
internal vLLM etc., append args (`--upstream http://vllm:8000 --provider openai`).
Runnable without a container too:

```bash
pasu-proxy --policy rules.yaml --listen 127.0.0.1:8788 --upstream https://api.openai.com
```

### Deeper: kernel egress guard (Linux)

Kernel egress guard on Linux — **the same YAML**, lowered to the kernel
allowlist (a **dedicated** cgroup; never the root cgroup):

```bash
sudo pasu-daemon --policy rules.yaml --cgroup-path /sys/fs/cgroup/my-agent
# lower-level loader (flags / TOML) if you don't want the policy file:
sudo pasu-egress --cgroup-path /sys/fs/cgroup/my-agent --allow-domain api.openai.com
```

Allow rules with an IPv4/IPv6 literal become static entries, and exact hostnames
are resolved (and re-resolved, both families). Suffix patterns (`.openai.com`)
can't be lowered to the kernel yet and are only reported — DNS-response sniffing
will close that. The kernel side is default-deny for **both v4 and v6**, so
lowering is only ever *narrower* than the policy.

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
| `pasu-proxy` | LLM-API reverse proxy — parses tool calls from provider responses (OpenAI…) and guards them via the same `Guard`; framework-agnostic (`base_url` only) |
| `pasu-ui` | lightweight web UI — HITL approvals (`/`) + audit dashboard (`/audit`) |
| `pasu-audit` | audit sinks — JSONL (stderr / file / SIEM), in-memory, and OpenTelemetry (OTLP spans, `otel` feature) |
| `pasu-egress` · `pasu-ebpf` · `pasu-ebpf-common` | kernel eBPF cgroup egress — default-deny allowlist, DNS-aware (Linux) |
| `pasu-daemon` | composition root — lowers the policy YAML to the kernel guard (one policy, both layers) |
| `pasu-cli` | the `pasu` command — `pasu run` wraps any agent command in a guarded cgroup |

Every crate depends only on `pasu-core` (acyclic); the rule format and framework
integration are swappable behind traits.

## Dependencies

Key dependencies are pinned for reproducibility:

| dependency | version | license | why this version |
|---|---|---|---|
| [aya](https://github.com/aya-rs/aya) (+ `aya-log`, `aya-build`) | git `773ca715` | MIT / Apache-2.0 | pinned until aya's next crates.io release — unpinned git deps broke our CI once (upstream API drift) |
| [Falco](https://github.com/falcosecurity/falco) | — | — | **not a dependency** — pasu borrows the *rule-format idea* only; no Falco code |

## Numbers

<p align="center">
  <img src="docs/metrics.svg" width="880" alt="pasu measured overhead and verification map: criterion benchmarks (Apple M4) — policy decision 0.06µs, response parse 0.7µs, SSE reassembly 4.5µs, 5–7 orders of magnitude below a typical ~1s LLM roundtrip on a log scale. Claims-to-evidence matrix: kernel default-deny drop, live allow/deny and domain allowlist proven by real-kernel E2E in CI; denied tool call 403 and SSE guarding by unit + wire E2E; ask fail-closed by unit tests; pasu run wrapping by real-kernel E2E. 82 tests total, 4 CI jobs">
</p>

- **Guard cost per response** (measured, criterion, Apple M4): policy decision ~0.06 µs · response parse ~0.7 µs · SSE reassembly (40 chunks) ~4.5 µs. Reproduce: `cargo bench -p pasu-rules -p pasu-proxy`
- **82 tests**: 62 portable (core · rules · ui · audit · proxy, incl. wire E2E) + 20 Linux (14 unit · **6 real-kernel E2E** — egress 4 + `pasu run` 2)
- **4 CI jobs on every push** — `fmt·clippy·test` (stable) · `eBPF build+unit` (nightly + bpf-linker) · `eBPF E2E` (privileged, real Ubuntu kernel) · `cargo-deny` (advisories/licenses/sources)
- **10 crates**, one acyclic core (every crate depends only on `pasu-core`)

## Status

MVP — the engine, policy, HITL, audit, deployment, and benchmarks are in place.

| capability | crate | state |
|---|---|:---:|
| kernel default-deny allowlist (DNS-aware) | egress/ebpf | ✅ |
| policy language (YAML) | rules | ✅ |
| LLM-API proxy — tool-call guard · HITL (any SDK) | proxy | ✅ OpenAI · Anthropic · Gemini · SSE reassembly |
| approval + audit UI | ui | ✅ |
| audit sinks (JSONL) | audit | ✅ |
| config-driven daemon + systemd | egress + packaging | ✅ |
| **one policy file → both layers** | daemon | ✅ |

Next: incremental SSE relay (currently buffered) and eBPF
force-routing of LLM traffic through the proxy; precise DNS-response sniffing
(toFQDN — unlocks suffix hosts in the kernel), eBPF-layer audit emission, a
control-plane API + richer UI, and a crates.io release (aya is currently
git-pinned).

## Development

```bash
cargo test              # portable crates: core, rules, ui, audit, proxy (stable)
cargo build -p pasu-egress   # eBPF stack — Linux only, nightly + bpf-linker
```

## Platform

Linux first, **self-hosted, air-gapped-friendly** — eBPF kernel enforcement is
Linux-only, on a single host, with no Kubernetes and no runtime call-home.
Telemetry export (OTLP/JSONL) is opt-in and points at your own collector.
macOS/Windows get the LLM-API proxy + UI (cooperative) for development, without
kernel enforcement.

## Contributing

Contributions welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). In short:
Conventional Commits, DCO sign-off (`git commit -s`), feature branch → PR → CI green.

## Security

pasu is a security tool that runs in the kernel. Please report vulnerabilities
privately — see [SECURITY.md](SECURITY.md).

## Acknowledgements
- The policy syntax is inspired by [Falco](https://github.com/falcosecurity/falco)'s rule
  format. pasu is not affiliated with or endorsed by the Falco project or the CNCF.

## License

[Apache-2.0](LICENSE).
