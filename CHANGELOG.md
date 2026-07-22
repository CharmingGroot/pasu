# Changelog

All notable changes to pasu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims
for [Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches
its first tagged release.

## [Unreleased]

### Added
- **Podman deployment notes (verified)** — `docs/deployment.md` documents running
  the eBPF egress guard under Podman (cgroup-v2-native, daemonless), **verified on
  Lima** (Ubuntu 24.04, kernel 6.8, Podman 4.9.3): rootful/privileged self-guard
  (default cgroupns) and sidecar (`--cgroupns host` + the target's dedicated cgroup
  path) both enforce the allowlist in the kernel with host egress intact. Documents
  the anti-pattern proven along the way — `--cgroupns host` on a `/sys/fs/cgroup`
  attach cuts the *host's* egress — and why rootless Podman only fits the
  cooperative proxy layer.
- **`AGENTS.md` + `.github/skills/`** — a vendor-neutral orientation guide for
  coding agents and new contributors (build/test, crate map, working rules,
  deferring to CLAUDE.md as the binding authority), plus step-by-step task
  recipes for repeatable changes (`add-llm-provider`, `add-audit-sink`).
- **Layered policy: `default/` + `user/`** — `pasu-rules` gains `Ruleset::from_dir`
  (loads `*.yaml` in a directory, sorted by filename — the `rules.d`/`sudoers.d`
  convention) and `Ruleset::layered` (a user overlay whose rules take precedence,
  default merged deny-wins). `pasu-daemon --policy-dir <dir>` loads
  `<dir>/default/` (project-shipped, overwritten on upgrade) under `<dir>/user/`
  (customization, preserved) so upgrades never clobber user rules. `--policy
  <file>` still works; the two are mutually exclusive.
- **IPv6 kernel egress filtering** — the eBPF guard now enforces default-deny on
  IPv6 too (new `ALLOW6` map, v6 destination parsing), closing the bypass where
  a tool could exfiltrate over IPv6. Loopback (`::1`) and infrastructure prefixes
  (link-local `fe80::/10`, multicast `ff00::/8`) always pass. `allow`/`allow-domain`,
  the admin socket, and policy lowering all accept v4 and v6.
- **Proxy parse benchmarks + evidence-backed metrics** — criterion
  micro-benchmarks for the per-response guard cost (`extract` per provider +
  SSE reassembly) alongside the existing policy bench; the README metrics
  section now embeds `docs/metrics.svg` (measured overhead on a log scale +
  a claims↔evidence matrix mapping every README claim to its test tier).
- **HITL approval UI wired into `pasu-proxy`** — run the proxy with `--ui <addr>`
  to serve the pasu-ui approval queue (`/`) and audit view (`/audit`); a
  `Verdict::Ask` now awaits a browser approve/deny instead of failing closed.
  Decisions fan out to both stderr JSONL and the UI feed.
- **Anthropic & Gemini response parsing in `pasu-proxy`** — the tool-call guard
  now understands all three provider wire formats (OpenAI Chat Completions,
  Anthropic Messages, Gemini `generateContent`), covering effectively every SDK.
  Select with `--provider {openai,anthropic,gemini}`.
- **Streaming (SSE) tool-call inspection** — tool calls split across SSE deltas
  (OpenAI `delta.tool_calls`, Anthropic `input_json_delta`, Gemini per-chunk
  `functionCall`) are reassembled and judged by the same policy. The full stream
  is buffered before relay (incremental relay is future work), closing the gap
  where streaming responses passed through unguarded.
- **One policy file for both layers** — `pasu-daemon --policy rules.yaml` lowers
  the same ruleset the proxy evaluates into the kernel egress allowlist
  (IPv4 → static, exact host → DNS-resolved, `.suffix` → reported as
  cooperative-layer-only, `default: allow` → refused fail-closed).
- **Control-plane admin socket** — `pasu-egress --admin-socket` exposes
  `status` / `allow <ip>` / `deny <ip>` for live inspection and edits.
- **Egress dashboard UI** (`/egress`) — kernel filter coverage, live allowlist
  add/remove, and a read-only policy view (per-rule verdict + tool/host guard).
- **Containerization** — `deploy/Dockerfile`, a self-guard demo, a sidecar
  `docker-compose.yml`, Kubernetes sidecar/DaemonSet examples, and a **Helm
  chart** (`deploy/helm/pasu-egress`).
- **Release pipeline** — multi-arch (amd64 + arm64) GHCR image on version tags.
- **Supply-chain gate** — `cargo-deny` CI (advisories · licenses · sources).
- `examples/ui_demo` to run the UI against a mock guard with no kernel.
- README: dependency-pin table, container/Helm quickstart.

### Fixed
- **Container builds now work on Podman** (surfaced verifying the Podman notes):
  the `deploy/Dockerfile` and `deploy/proxy/Dockerfile` base images and the
  compose `curl` image are now fully-qualified (`docker.io/library/...`), so they
  resolve under Podman's stricter short-name policy (Docker is unaffected); and a
  `.dockerignore` excludes `target/` etc. so the build context is no longer the
  whole 6.6 GB tree.
- `pasu-ebpf` was missing a `license` field; `pasu-egress` was missing the
  `io-util`/`sync` tokio features (surfaced by a clean build).
