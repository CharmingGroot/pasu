# Integrations

pasu decides; something else may carry the traffic. Every front-end answers
with the same judge — one policy, one audit stream — so a tool call denied
through LiteLLM is denied through Envoy and through pasu's own reverse proxy.

| You run | Attach pasu as | Start pasu with |
|---|---|---|
| nothing yet | the reverse proxy (`base_url` → pasu) | `--frontend reverse --upstream <provider>` |
| [Envoy](envoy/) · Envoy Gateway · [agentgateway](agentgateway/) | an **ext_proc** server | `--frontend ext-proc` |
| [LiteLLM](litellm/) proxy | a **guardrail** | `--frontend litellm` |

## What each one covers

| | reverse | Envoy ext_proc | LiteLLM `generic_guardrail_api` | LiteLLM `PasuGuardrail` |
|---|---|---|---|---|
| Prompt screening (block) | ✓ | ✓ | ✓ | ✓ |
| Prompt redaction | ✓ | ✓ | ✓ | ✓ |
| Tool calls, non-streamed | ✓ | ✓ | ✓ | ✓ |
| Tool calls, **streamed** | ✓ before any byte | ✓ before any byte | ✗ chunks reach the client first | ✓ before any chunk |
| Unknown endpoints refused | ✓ | ✓ | LiteLLM's routing | LiteLLM's routing |
| pasu unreachable | — | 500 (`failure_mode_allow: false`) | refused (`unreachable_fallback: fail_closed`) | same |

Streamed tool calls are the reason `PasuGuardrail` exists: LiteLLM consults a
guardrail *while* it streams, so with the built-in integration a denied call is
already on the wire when the block arrives. Measured with LiteLLM 1.91:

<p align="center">
  <img src="../docs/litellm-streaming.svg" width="860" alt="A streamed tool call through LiteLLM. With generic_guardrail_api the client receives the tool_call, arguments and finish chunks, and only after the stream ends is pasu asked; its block arrives as an error event after the call was already on the wire. With PasuGuardrail the same chunks are held, pasu is asked on the assembled response, and the client gets HTTP 400 with no chunk at all">
</p>

## Envoy

[`envoy/envoy.yaml`](envoy/envoy.yaml). The settings that matter:

- `processing_mode` bodies **BUFFERED**, **STREAMED** or
  **FULL_DUPLEX_STREAMED**. Whichever it is, pasu holds a body it judges until
  the last byte and forwards none of it before the verdict. pasu reads the mode
  Envoy reports and refuses (500) a route whose body it would never see whole:
  with `response_body_mode: NONE` every tool call would otherwise pass unseen,
  and `BUFFERED_PARTIAL` shows only the first part.
- `failure_mode_allow: false` (the default). Never true.
- `message_timeout` above the HITL approval timeout if you run `--ui`.
- `per_connection_buffer_limit_bytes` large enough for your prompts and
  completions; over it Envoy refuses (413 / 500).

What a refusal looks like depends on the mode. Measured with Envoy 1.38, a
streamed (`stream: true`) completion carrying a denied tool call:

| body mode | how pasu holds a body | denied streamed tool call | denied prompt |
|---|---|---|---|
| `BUFFERED` | Envoy buffers it | clean 403 | clean 403 |
| `STREAMED` | answers each piece by clearing it; the last piece carries the whole body | **200 headers, then a reset** — no body byte | clean 403 |
| `FULL_DUPLEX_STREAMED` | answers nothing, and withholds the response headers, until the body is whole | clean 403 | clean 403 |

Under `STREAMED` the response headers have gone to the client before the body
is judged, so a refused completion cannot become a 403: Envoy resets the stream
(curl: `transfer closed with outstanding read data remaining`). No tool-call
byte reaches the client, so it is still fail-closed — but a client sees a
broken stream rather than pasu's error. (A non-streamed completion small
enough to arrive in one piece was still a clean 403 in the same run; do not
rely on it.) Use `BUFFERED` or
`FULL_DUPLEX_STREAMED` to get the error. In every held mode the client gets the
body only once it is whole, as with `BUFFERED`: a streamed completion arrives
all at once, not token by token.

`FULL_DUPLEX_STREAMED` needs `request_trailer_mode: SEND` and
`response_trailer_mode: SEND`; Envoy rejects the configuration without them.
It also has no `message_timeout`, which is what lets pasu hold the response
headers. A held body that ends in trailers rather than an end-of-stream piece
is refused (500): LLM APIs do not send trailers. Size limits bound what pasu
holds: over `max_request_bytes` a prompt is refused (413), over
`max_response_bytes` a completion (403). A body pasu does not judge — a
passthrough path, a provider error, a `count_tokens` response, a prompt with
no inspector on — streams through as it arrives.

pasu asks the upstream for `accept-encoding: identity`, so no decompressor
filter is needed. Envoy Gateway (`EnvoyExtensionPolicy.extProc`) and
agentgateway (see [agentgateway](#agentgateway) below) speak the same
protocol. pasu takes the body mode from the `protocol_config` the data plane
sends; Envoy Gateway's `Streamed` works with the reset described above, so
prefer `Buffered` there. Behind Envoy AI Gateway, attach pasu
before AI Gateway's own ext_proc if you redact: AI Gateway can rebuild the
request body and drop an earlier filter's mutation (agent-router#2671).

## agentgateway

[`agentgateway/config.yaml`](agentgateway/config.yaml), standalone
(`agentgateway -f config.yaml`); on Kubernetes the same options sit under
`spec.traffic.extProc`. The settings that matter
([docs](https://agentgateway.dev/docs/standalone/latest/configuration/traffic-management/extproc/)):

- `processingOptions.requestBodyMode` and `responseBodyMode`: **`buffered`**.
  Both default to `fullDuplexStreamed`. agentgateway reports its body modes to
  pasu, so with the default — or `bufferedPartial`, or `responseBodyMode: none`
  — every completion is refused with a 500 naming the setting, before the
  request reaches the provider. `allowModeOverride: true` does not change that.
- `failureMode: failClosed` (the default). Never `failOpen`: with pasu stopped
  it forwarded every case below, the denied tool call included.
- `frontendPolicies.http.maxBufferSize` large enough for your prompts and
  completions. The default is 2 MiB; a larger buffered body is refused (500)
  and not forwarded.

pasu's `accept-encoding: identity` reaches the provider (a client's `gzip` was
replaced), so no decompression is needed. A streamed completion reaches the
client only once whole, as with Envoy.

Measured with agentgateway 1.5.0 and a plain-HTTP mock provider:

| Case | `buffered` | default (`fullDuplexStreamed`) | pasu stopped |
|---|---|---|---|
| text completion | 200 | 500, not forwarded | 500 `ext_proc failed`, not forwarded |
| `shell` tool call | 403, no tool-call byte | 500, not forwarded | 500, not forwarded |
| `shell` tool call, streamed | 403, no tool-call byte | 500, not forwarded | 500, not forwarded |
| `POST /v1/embeddings` | 403, not forwarded | 403, not forwarded | 500, not forwarded |
| prompt with a resident registration number | 403, not forwarded | 500, not forwarded | 500, not forwarded |

## LiteLLM

[`litellm/config.example.yaml`](litellm/config.example.yaml). Use
`generic_guardrail_api` if you never stream tool calls, or
[`pasu_guardrail.py`](litellm/pasu_guardrail.py) (placed next to the config) if
you do. Either way: `mode: [pre_call, post_call]`, `default_on: true`,
`unreachable_fallback: fail_closed`. Set `PASU_GUARDRAIL_API_KEY` on pasu and
`api_key` in LiteLLM to require a shared key.

LiteLLM has a built-in `tool_permission` guardrail for name and argument
patterns. pasu is for when the same policy must also bound the kernel egress
layer, hold calls for a person (`Ask`), redact Korean PII, or feed one audit
stream across every front-end.
