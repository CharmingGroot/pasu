# AGENTS.md

Orientation for coding agents (and new contributors) working in **pasu**. This
is the vendor-neutral entry point; the binding rules live in
[CLAUDE.md](CLAUDE.md) and the contributor summary in
[CONTRIBUTING.md](CONTRIBUTING.md). When those conflict with this file,
**CLAUDE.md wins**.

## What pasu is (one paragraph)

pasu is a Rust security guard for AI agents. Two layers, one policy: an
**LLM-API proxy** (`pasu-proxy`, cooperative) parses provider responses and
gates tool calls for any SDK; a **kernel eBPF egress guard** (`pasu-egress` /
`pasu-ebpf`, enforcing) drops egress the policy doesn't allow — unbypassable.
See [README.md](README.md) for the full picture.

## Prime directive

**This is a security tool. Fail-closed.** If the guard cannot operate, it must
deny — never add a fail-open path for convenience. Every rule/logic change needs
tests (TP + TN pairs, and a bypass test where relevant). No exceptions; see
CLAUDE.md §3–4.

## Setup, build, test

```bash
cargo test                                   # portable crates (stable): core, rules, ui, audit, proxy
cargo clippy --all-targets -- -D warnings    # lint (warnings are errors)
cargo fmt --check                            # formatting

# eBPF stack — Linux + nightly + bpf-linker (kept out of default-members):
cargo build -p pasu-egress
```

`cargo test` / the stable CI job never touch the eBPF stack, so you don't need a
bpf toolchain to work on the portable crates. The kernel paths are validated by
the privileged **eBPF E2E** CI job on a real Ubuntu kernel — you generally
**cannot build the eBPF crates on macOS**, so lean on CI for those.

CI is 4 jobs (all must be green): `fmt·clippy·test`, `eBPF build+unit`,
`eBPF E2E` (privileged), `cargo-deny`.

## Crate map (acyclic — everything depends only on `pasu-core`)

| crate | role |
|-------|------|
| `pasu-core` | shared `Event`/`Verdict` types + traits (`RuleEngine`, `Layer`, `Approver`, `AuditSink`) + the `Guard` facade |
| `pasu-rules` | the `RuleEngine` — Falco-inspired YAML ruleset; also lowers policy to the kernel allowlist |
| `pasu-proxy` | LLM-API reverse proxy: parses tool calls from provider responses (OpenAI/Anthropic/Gemini, streaming + not) |
| `pasu-ui` | lightweight web UI: HITL approval, audit, egress dashboard |
| `pasu-audit` | `AuditSink` backends: JSONL, in-memory, OpenTelemetry (`otel` feature) |
| `pasu-egress` · `pasu-ebpf` · `pasu-ebpf-common` | kernel eBPF cgroup egress (Linux) |
| `pasu-daemon` | composition root: policy YAML → kernel guard |
| `pasu-cli` | the `pasu` command (`pasu run -- <agent>`) |

**Rule:** library crates stay pure behind `pasu-core`. Only app-level binaries
(`pasu-proxy`, `pasu-daemon`, `pasu-cli`) may wire concrete crates (e.g.
`pasu-rules`, `pasu-ui`). Never add a dependency between two library crates.

## Working rules (essentials — full text in CLAUDE.md)

- **Conventional Commits**: `type(scope): description` (scope = `proxy`/`egress`/`ebpf`/`rules`/`ui`/`audit`/`core`/`ci`/`docs`).
- **DCO sign-off**: `git commit -s`. **No AI-authorship attribution** (no `Co-Authored-By: Claude`).
- **Branch → PR → CI green → merge.** Feature branches off `release/vX.Y`, never commit to `main` or a release branch directly. The user merges to `main`.
- **One PR = one problem.**
- Rust style: early returns, no needless mutation, no `unwrap`/`expect`/`panic` on user/network input.

## Common tasks (recipes)

Repeatable changes have step-by-step skills under [`.github/skills/`](.github/skills/):

- **Add an LLM provider to the proxy** → [`.github/skills/add-llm-provider.md`](.github/skills/add-llm-provider.md)
- **Add an audit sink backend** → [`.github/skills/add-audit-sink.md`](.github/skills/add-audit-sink.md)

Follow the matching skill when your change fits one; it encodes the file set,
the tests to add, and the fail-closed/boundary rules for that task.
