---
name: pasu-setup
description: Put pasu in front of an AI agent's LLM traffic and prove it is actually in the path. Use when someone wants to guard an agent's tool calls or prompts with pasu — as a reverse proxy (base_url), an Envoy/Envoy Gateway/agentgateway ext_proc server, or a LiteLLM guardrail — or asks whether their pasu setup is working. Drafts the policy, wires the chosen front-end, and runs a probe that fails if pasu is not seeing the traffic.
---

# pasu setup

This skill switches pasu on. **It is not a guard.** Everything it writes is
advice to an operator; the guard is the pasu process it configures, and the
kernel egress layer under it. Never tell the user they are protected until the
probe in step 5 has passed.

## 1. Find where the agent's LLM traffic goes

Look before asking. Check, in this order:

- A gateway config in the project or deployment: `litellm` config YAML
  (`model_list:`), an Envoy config (`envoy.filters.network.http_connection_manager`),
  Envoy Gateway / agentgateway Kubernetes resources (`Gateway`, `HTTPRoute`,
  `EnvoyExtensionPolicy`, `AgentgatewayPolicy`).
- Base URL settings: `OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `base_url=` in code,
  `api_base` in LiteLLM params.
- The provider format the agent speaks: OpenAI Chat Completions or Responses,
  Anthropic Messages, Gemini `generateContent`.

## 2. Pick the front-end

| The traffic already crosses | Use | pasu flag |
|---|---|---|
| nothing | reverse proxy | `--frontend reverse --upstream <provider base URL> --provider openai\|anthropic\|gemini` |
| Envoy, Envoy Gateway, agentgateway | ext_proc server | `--frontend ext-proc --listen 0.0.0.0:8791` |
| LiteLLM proxy | guardrail | `--frontend litellm --listen 127.0.0.1:8790` |

Prefer attaching to a gateway that already exists over adding a hop. The
reverse proxy is for when there is none.

## 3. Draft the policy

Write `rules.yaml`. Rules match a tool **name exactly** (`tool:`) or an egress
**host** (`host:`, exact or a leading-dot suffix). First match wins.

- Start from `default: deny`. Allow-listing the agent's own tools is the point;
  a default of `allow` also cannot be lowered to the kernel layer.
- List the tools the agent actually declares (its tool/function definitions),
  and decide each: `allow`, `deny`, or `ask` (a person approves — only useful
  with `--ui`).
- `ask` for anything that moves money, deletes, deploys or sends messages.
- Add the provider hosts as `host:` allows if the kernel layer will run.
- Show the user the draft and get their decision on each `ask`/`deny`. Do not
  guess on their behalf.

```yaml
rules:
  - name: allow-search
    match: { tool: web_search }
    action: allow
  - name: confirm-transfer
    match: { tool: transfer_funds }
    action: ask
    reason: "human approval for money movement"
  - name: allow-llm
    match: { host: "api.openai.com" }
    action: allow
default: deny
```

Prompt inspection is separate from the policy: `--block-pii-kr` (Korean PII),
`--presidio-rules <yaml>`, and `--redact` to replace instead of refuse.

## 4. Wire it

Copy from the repository's `integrations/` — every example there was run against
the real gateway. The settings that must not be changed:

- **Envoy / Envoy Gateway / agentgateway**: request and response body modes as
  the example sets them; `failure_mode_allow: false` (Envoy) / `failOpen: false`
  (Envoy Gateway); `message_timeout` above 120 s if `--ui` is used.
- **LiteLLM**: top-level `guardrails:` (not under `litellm_settings`),
  `mode: [pre_call, post_call]`, `default_on: true`,
  `unreachable_fallback: fail_closed`. If the agent streams tool calls, use
  `guardrail: pasu_guardrail.PasuGuardrail` with `pasu_guardrail.py` next to the
  config — the built-in `generic_guardrail_api` lets a streamed tool call reach
  the client before the block.
- **Reverse proxy**: point the agent's base URL at pasu, e.g.
  `OPENAI_BASE_URL=http://127.0.0.1:8788/v1`.

Never set a fail-open option to make an error go away. An error from pasu is
the guard working; find the cause. A 500 with `"type":"pasu_misconfigured"`
means the data plane is set up so pasu cannot see a body it must judge — its
message names the setting in Envoy, Envoy Gateway and agentgateway spelling.

Three Envoy Gateway settings switch pasu off without any error, and pasu cannot
detect them because it is never asked: a missing `processingMode`,
`failOpen: true`, and `shadowMode: true`. The probe below catches the first and
the last; check `failOpen` by reading the policy.

## 5. Prove pasu is in the path

A pasu that is running but not in the path looks healthy and checks nothing.
Run the probe through **the same URL the agent uses**, and read the answer:

**Reverse proxy or Envoy family** — pasu refuses endpoints it does not guard,
so an embeddings call must come back from pasu, not the provider:

```bash
curl -s -X POST "$AGENT_BASE_URL/embeddings" \
  -H 'content-type: application/json' -d '{"input":"probe","model":"x"}'
# pass: HTTP 403 with "type":"pasu_policy_block"
# fail: anything from the provider (200, 401, 404) — pasu is not in the path
```

(`$AGENT_BASE_URL` includes `/v1` when the agent's does.)

**LiteLLM** — with an inspector on (`--block-pii-kr`), a prompt carrying a test
resident number must be refused by pasu. The number below is a format example,
not a real person's:

```bash
curl -s "$LITELLM_URL/v1/chat/completions" -H "Authorization: Bearer $LITELLM_KEY" \
  -H 'content-type: application/json' \
  -d '{"model":"<a model in model_list>","messages":[{"role":"user","content":"id 900101-1234567"}]}'
# pass: HTTP 400 whose message starts "pasu-proxy blocked this request"
```

Without an inspector, check pasu's stderr instead: after one tool-calling turn
of the agent, a JSONL line `{"layer":"litellm-guardrail",...}` must appear.

Then, if the policy has a `deny`, trigger it once through the agent and confirm
the refusal and the audit line (`"verdict":"deny"`).

Report to the user exactly which probes passed. If one failed, say pasu is not
guarding this agent yet — do not soften it.

## 6. Say what is still open

- The proxy layer is cooperative: a tool that opens its own socket goes around
  every front-end. On Linux, recommend the kernel layer
  (`pasu run -- <agent command>` or `pasu-daemon --policy rules.yaml`) with the
  same `rules.yaml`.
- The HITL UI (`--ui`) prints a token URL once at startup; only a browser that
  opened it can approve. Keep that line out of logs the agent can read.
