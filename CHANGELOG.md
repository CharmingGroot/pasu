# Changelog

All notable changes to pasu are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **The proxy inspects requests, not only responses.** It forwarded every
  request untouched, so a prompt carrying whatever an agent had just read out of
  a file or a database row reached the provider unexamined. The kernel layer
  cannot cover that path — it must permit the provider's address or the agent
  cannot work, and past the handshake the payload is TLS — which makes the
  request body the only place the content is readable.
  ([#107](https://github.com/CharmingGroot/pasu/issues/107))
- **`pasu_core::Inspector`**, the plugin point for content checks. A scanner
  attaches without a layer changing. It returns **findings rather than
  verdicts**: what was found and where, leaving the layer to decide whether that
  means a refusal or, later, a redaction. An inspector that answered
  allow-or-deny would already have discarded the spans a redactor needs.
  `Finding` never carries the matched value.
- **`pasu-inspect-presidio`** — reads Presidio recognizer YAML as an
  `Inspector`. There is no interchange standard for PII rules, and this is not
  one; it reads the format people have already exported. Score, context words,
  Python-only regex and checksums do not survive the trip, and each is reported
  by name with its reason rather than dropped. Loading is fail-closed: a file
  containing anything unusable is an error, because an operator holding half a
  rule set and believing it whole is worse off than one who got an error.
  ([#96](https://github.com/CharmingGroot/pasu/issues/96))
- `pasu-pii-kr` is now reachable from the proxy behind `--block-pii-kr`. It
  existed, was tested, shipped rules — and was called by nothing.
- **Redaction** (`--redact`, `--block-rule`, `--redact-rule`): replace what was
  found and forward the rest, per rule rather than per filter. Blocking stays
  the default, because stopping is the safe answer for a rule nobody has decided
  about, and an explicit block beats an explicit redact — a contradiction in a
  security policy reads as the stricter option.

  **One-way.** No original is kept, so nothing can restore it and the proxy never
  becomes a store of the data it exists to stop from moving. Reversible
  substitution is a different security posture and deserves its own decision.
  The placeholder preserves neither length nor shape; a mask that did would leak
  the value it hid. ([#102](https://github.com/CharmingGroot/pasu/issues/102))

### Security

- **The approval UI answers only to whoever started it.** Any process that could
  reach its port could approve a pending `Ask` with one form post, and ids are
  sequential. The guarded agent can reach it: the kernel layer always passes
  loopback, so an allowed shell tool was enough to approve the agent's own
  calls, and on the dashboard to add an address to the kernel allowlist. Any web
  page the operator had open could do the same cross-site. Every UI request now
  needs a token generated at startup; the printed URL carries it once, after
  which it lives in a `SameSite=Strict`, `HttpOnly` cookie, and a state change
  whose `Origin` names another host is refused. `pasu_ui::router`, `serve` and
  `serve_all` take an `Access`; there is no unauthenticated form.

- **Tool calls in the OpenAI Responses API were not guarded at all.** The
  parser read Chat Completions only, and every field of that shape defaulted, so
  a Responses body parsed as "a completion with no tool calls". An agent on the
  Responses API — the default for OpenAI's own agent tooling — ran a
  `function_call`, `local_shell_call` or `custom_tool_call` under a `default:
  deny` policy. `output[]` items are now read, streamed and not; any `*_call`
  item the provider does not execute itself is a tool call, including types
  newer than this code. The same gap covered the deprecated `function_call`
  field of Chat Completions and Gemini's `streamGenerateContent` answered as a
  JSON array; both are read now.
- **A stream event the parser did not understand was skipped, and a tool call
  with it.** Several `data:` lines in one event — valid SSE — were read as
  separate JSON documents and dropped. Events are now framed as the SSE spec
  frames them, and data that is not JSON, or argument fragments that belong to
  no named call, make the stream unreadable instead of silently shorter.
- **OpenAI tool arguments reach the guard decoded.** They arrive as a JSON
  string the model wrote, escapes included; `\u002fetc` is `/etc` to the agent
  but not to a rule reading the raw string. Arguments that parse are
  re-serialized before the guard sees them, as Anthropic and Gemini arguments
  already were.

- **The proxy forwards only endpoints it can guard, and refuses what it cannot
  read.** Every path went upstream, and a completion response that did not parse
  was relayed unchecked — so a body in a shape the parser did not know carried
  its tool calls straight to the agent, and `/v1/files` or `/v1/embeddings`
  carried a prompt past every inspector. `WireFormat::route` now names each
  endpoint: a completion's response must parse or it is refused; token counting
  is screened but not parsed; model listing passes; anything else is refused
  before it leaves, unless the operator names it with `--passthrough-path`,
  which is announced at every start. With an inspector on, a prompt that cannot
  be read is refused rather than sent unread, and Responses API prompts
  (`input`, `instructions`, tool output) are read. Provider errors are relayed
  with their status and headers instead of being judged. The default `route`
  treats every path as a completion, so an out-of-tree format gets the strict
  reading.
- **The upstream is asked for an uncompressed body.** Client headers went
  upstream as sent, `Accept-Encoding: gzip` included, and a compressed response
  is bytes the parser cannot read. The proxy now sends `Accept-Encoding:
  identity`, drops hop-by-hop headers (including those a `Connection` header
  lists), and refuses a completion the provider compressed anyway: what was
  checked must be what the agent decodes.
- **Both directions are bounded.** axum's 2 MiB request default refused vision
  payloads and long contexts, and the response was buffered without limit — the
  read timeout is idle-only, so a stream that kept sending was buffered forever.
  `--max-request-bytes` (32 MiB) and `--max-response-bytes` (64 MiB) set both; a
  response over the cap is refused, not truncated.

### Fixed

- **A redacted request no longer overwrites text in other messages.** Findings
  from every message were pooled and each message was redacted with all of
  them, so a span found in one message replaced the bytes at the same offset in
  every other. Each text is now redacted with its own findings.
- **No binary could print its own help.** `--help` answered `error: unexpected
  argument found`. clap's `help` and `usage` are default features and the
  workspace turns defaults off, naming only `std`, so `--help` was not a flag at
  all. Every flag these binaries have is documented only there, which made the
  answer to "what can this do" be "read the source". `error-context` came with
  the fix, so a missing required argument now names which one. All three
  binaries carry a test for it.
  ([#97](https://github.com/CharmingGroot/pasu/issues/97))

### Known gaps
- **Detection is regex and checksums.** No NER model runs — a path executing per
  message cannot afford one — so PII without a pattern, such as a person's name,
  is not caught.
- Content inspection sees only request shapes the proxy parses. With an
  inspector on, a body that does not parse is refused; a path named with
  `--passthrough-path` is forwarded uninspected by the operator's choice.

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
