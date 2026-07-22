# Skill: add an LLM provider to `pasu-proxy`

Add support for a new provider wire format so the tool-call guard covers another
SDK family. The guard/inspect/policy path is **provider-agnostic** — only the
parse layer changes. (Done three times already: OpenAI, Anthropic, Gemini.)

**Prerequisite reading:** [AGENTS.md](../../AGENTS.md), [CLAUDE.md](../../CLAUDE.md) §1, §3.

## The one insight

A model's tool-call decision (name + arguments) rides in the **provider response
body** (function calling). So a provider is "supported" once we can extract
`ToolCall { name, arguments }` from both its non-streaming and streaming (SSE)
responses. Everything downstream (`inspect` → `Guard` → 403 / passthrough) is
already generic.

## Steps

1. **`crates/pasu-proxy/src/parse.rs`**
   - Add a variant to `enum Provider`.
   - Add it to the `match` in `extract(body, provider)`.
   - Write `extract_<provider>(body) -> Option<Vec<ToolCall>>`: deserialize the
     non-streaming response, pull out each proposed tool call. Return `None` when
     the body isn't parseable as that provider (the proxy passes it through);
     `Some(vec![])` when it parsed but proposed no tools. Serialize object-shaped
     arguments to a JSON string so every provider yields the same `ToolCall`.

2. **`crates/pasu-proxy/src/stream.rs`**
   - Add the variant to the `match` in `extract_stream(body, provider)`.
   - Write `reassemble_<provider>(datas)`: reassemble tool calls from the SSE
     `data:` chunks (providers fragment differently — e.g. OpenAI concatenates
     `arguments` per index, Anthropic pairs `content_block_start` with
     `input_json_delta`). Keep it deny-safe: a partial/garbled stream should not
     silently produce an empty allowlisted result if a tool call was intended.

3. **`crates/pasu-proxy/src/main.rs`** — add the provider string to
   `parse_provider` (the `--provider` flag), and to its error message.

4. **Docs** — update the README (both `README.md` and `README.en.md`) status
   line and the `--provider` list; add a CHANGELOG entry.

## Tests (mandatory — this is a security tool)

- **`parse.rs` unit tests**: TP (a response with a tool call → extracted with the
  right name/args) **and** TN (a text-only response → no tool calls). Add both.
- **`stream.rs` unit tests**: reassembly across chunks (args split), and a
  text-only stream → no tool calls.
- **`tests/proxy_e2e.rs`** (over the wire): if you extend the mock upstream,
  keep the denied→403 / allowed→200 assertions holding for the new format.
- Run: `cargo test -p pasu-proxy` · `cargo clippy -p pasu-proxy --all-targets -- -D warnings` · `cargo fmt`.

## Boundaries

- **Don't** add provider-specific logic outside `parse.rs`/`stream.rs`. If the
  verdict path needs to change, stop — that's a redesign, not a provider add.
- Arguments are always a **string** in `ToolCall` (serialize objects); the guard
  treats them opaquely.
- Streaming stays **buffered** (the proxy reads the whole body, then reassembles)
  unless/until incremental relay lands — don't half-implement streaming here.
