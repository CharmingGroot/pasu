# Integrations

pasu decides; something else may carry the traffic. Every front-end answers
with the same judge — one policy, one audit stream — so a tool call denied
through LiteLLM is denied through Envoy and through pasu's own reverse proxy.

| You run | Attach pasu as | Start pasu with |
|---|---|---|
| nothing yet | the reverse proxy (`base_url` → pasu) | `--frontend reverse --upstream <provider>` |
| [Envoy](envoy/) · Envoy Gateway · agentgateway | an **ext_proc** server | `--frontend ext-proc` |
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

- `processing_mode` bodies **BUFFERED**. pasu reads the mode Envoy reports and
  refuses (500) a completion it would never be shown — with
  `response_body_mode: NONE` every tool call would otherwise pass unseen.
- `failure_mode_allow: false` (the default). Never true.
- `message_timeout` above the HITL approval timeout if you run `--ui`.
- `per_connection_buffer_limit_bytes` large enough for your prompts and
  completions; over it Envoy refuses (413 / 500).

pasu asks the upstream for `accept-encoding: identity`, so no decompressor
filter is needed. Envoy Gateway (`EnvoyExtensionPolicy.extProc`) and
agentgateway (`spec.traffic.extProc`) speak the same protocol; set their body
mode to `Buffered` — agentgateway defaults to `FullDuplexStreamed`, which pasu
refuses rather than judges in pieces. Behind Envoy AI Gateway, attach pasu
before AI Gateway's own ext_proc if you redact: AI Gateway can rebuild the
request body and drop an earlier filter's mutation (agent-router#2671).

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
