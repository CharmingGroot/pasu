# Changelog

All notable changes to pasu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **CIDR ranges in the kernel allowlist** (#66). The eBPF maps are now
  longest-prefix-match tries, so a rule can name a range (`10.0.0.0/8`,
  `fd00::/8`) instead of enumerating addresses. A bare address stays valid and
  becomes a host route (`/32`, `/128`), so existing policies are unaffected.
  Keys are the raw address bytes in network order — an LPM key is walked bit by
  bit from the most significant, so a host-order integer would match the wrong
  prefixes on a little-endian machine.
- **`Cidr` in `pasu-core`** — one type for both families, shared by the rule
  engine (which lowers policy) and the egress guard (which injects into the
  kernel). Host bits are cleared when building the kernel key, so `10.1.2.3/8`
  and `10.0.0.0/8` are the same entry.
- **WireGuard deployment notes**, verified on a real kernel. With kernel
  WireGuard the guard sees the **inner** destination (the `cgroup_skb` hook runs
  before routing, and therefore before encapsulation), so a policy can name what
  the agent reaches through the tunnel. Because `AllowedIPs` is a routing rule
  rather than a firewall, pasu's default-deny is what actually stops the agent
  from going around the VPN. Userspace WireGuard does not work this way — the
  note says so.

### Breaking
- `GuardConfig.allow` is now `Vec<Cidr>` and `allow6` is gone; both families
  live in one list. `EgressAllowlist.ips`/`ips6` likewise became `nets`.

## [0.2.0] - 2026-08-26

Hardening release. A cross-cutting audit — walking each concern across every
crate rather than each crate on its own — found that the enforcing layer kept no
audit trail, that the proxy had no upstream timeout, and that none of the
binaries handled SIGTERM. Those are fixed here, along with the metadata that was
blocking a crates.io publish. One new crate, `pasu-pii-kr`, also lands.

### Breaking

- `GuardConfig` gained an `audit` field. Struct-literal construction needs the
  new field (pass `None` to keep the previous behaviour, where the kernel blocks
  silently).
- **MSRV is now 1.86**, declared and checked in CI.

### Changed
- **SIGTERM is handled, and the HTTP servers shut down gracefully.** Containers
  and systemd send SIGTERM, then SIGKILL after a grace period; waiting only on
  SIGINT meant the eBPF program was never detached through the normal path. The
  proxy and UI servers now finish in-flight requests before closing instead of
  cutting them off.
- **Lints hold the line that discipline used to.** `forbid(unsafe_code)` on every
  crate that does not need it (the eBPF stack and one documented `pre_exec` call
  in `pasu-cli` are the exceptions), `warn(missing_docs)` on the public
  libraries, and an MSRV job that builds with the declared toolchain. Each of
  these caught something real while being added.
- **Release images build on native runners.** Each architecture is built on its
  own runner (`ubuntu-latest` for amd64, `ubuntu-24.04-arm` for arm64) and the
  results are stitched into one multi-arch tag by digest. Previously arm64 was
  emulated with QEMU, which was slow enough to matter — the v0.1.0 release took
  31 minutes for `pasu-proxy` and 39 for `pasu-egress`, most of it spent
  compiling `bpf-linker` from source under emulation.

### Added
- **The kernel layer now records what it blocks.** Until now the enforcing layer
  blocked silently while the cooperative layer (the proxy) kept a full audit
  trail — an operator could not answer "why did that not go out?" from the logs.
  The eBPF program publishes each drop (destination, protocol, port) through a
  ring buffer, and the control plane turns it into the same `AuditRecord` the
  proxy emits. Drops happen per packet, so repeats are **suppressed in the
  kernel**: an LRU map holds the last report time per destination and only one
  event per five-second window is published, carrying the count of the ones it
  swallowed. `pasu-egress`, `pasu-daemon` and `pasu-cli` all write through
  `pasu-audit`'s `JsonlSink`, so the format matches the proxy's.
- **Upstream timeouts on the proxy.** Without them an unresponsive provider held
  a request open forever and connections piled up. A *total* timeout would cut
  off long generations, so the limits are split: `--connect-timeout-secs`
  (default 10) for the handshake and `--read-timeout-secs` (default 120) as an
  idle timeout between reads — a stream that keeps sending never trips it.
- **A round-trip test for human-in-the-loop approval.** The proxy and the UI each
  had their own tests, but nothing covered the seam: `ask` → the UI queue → a
  person decides → the request proceeds or is blocked. Four cases now do,
  including "nobody decides" (fails closed) and "an allowed tool never reaches
  the queue".
- **`pasu-pii-kr` — Korean PII blocking filter** (new crate). Detects resident
  registration numbers, business registration numbers, card numbers and mobile
  numbers in text bound for an LLM, and returns an allow/deny verdict. Regex
  finds candidates; **checksums and date validity confirm them**, which removes
  the false positives a regex-only approach produces. Only the backtracking-free
  `regex` crate is used, so user-supplied rules cannot stall the process (ReDoS).
  Default rules are embedded (works with no config) and can be replaced or
  extended with YAML — `rules/user/` is evaluated before `rules/default/`, so
  exceptions are just `action: allow`. The crate depends on no other pasu crate
  and is usable standalone; its minimal build has exactly one direct dependency
  and CI enforces that budget. Checked by a dedicated pipeline
  (`.github/workflows/pii.yml`), separate from the eBPF jobs.
  Measured (Apple M4): 0.14 µs for a short prompt, 15.6 µs for 20 KB.

## [0.1.0] - 2026-07-22

First tagged release — the two-layer guard (LLM-API proxy + eBPF kernel egress)
with policy, HITL UI, audit, containers, and verified deploy paths.

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
