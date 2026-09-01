# Adapting pasu

pasu is meant to be taken apart. This is what the seams are, and what you have
to implement to sit on each one.

## The rule

**Every crate depends only on `pasu-core`.** Nothing in this repository imports
another project's code or ships another project's rules — where pasu reads a
format someone else defined, it reads the published shape of that format and
says so, and the test fixtures are written here.

## The seams

```
                    ┌───────────────────────────────┐
                    │          pasu-core            │
                    │  Event · Verdict · Finding    │
                    │  RuleEngine · Layer           │
                    │  Approver · AuditSink         │
                    │  Inspector · redact::Policy   │
                    └───────────────────────────────┘
                       ▲      ▲      ▲      ▲     ▲
        ┌──────────────┘      │      │      │     └──────────────┐
        │                     │      │      │                    │
   ┌────┴─────┐        ┌──────┴───┐  │  ┌───┴──────┐      ┌──────┴─────┐
   │  rules   │        │  egress  │  │  │  audit   │      │  adapters  │
   │RuleEngine│        │  Layer   │  │  │AuditSink │      │ Inspector  │
   └──────────┘        └──────────┘  │  └──────────┘      └────────────┘
                                     │                     pii-kr
                              ┌──────┴──────┐              presidio
                              │     ui      │              yours
                              │  Approver   │
                              └─────────────┘

   hosts:  pasu-proxy (LLM API)   pasu-daemon (kernel)   yours
```

A host runs the layers. The proxy and the daemon are two hosts that ship here;
neither is privileged in the design.

## What to implement

| To… | Implement | Example |
| --- | --- | --- |
| scan content for something | `Inspector` | `pasu-inspect-pii-kr` |
| decide about a tool call | `RuleEngine` | `pasu-rules` |
| enforce somewhere new | `Layer` | `pasu-egress` |
| send decisions elsewhere | `AuditSink` | `pasu-audit` |
| ask a human | `Approver` | `pasu-ui` |
| speak a provider's wire format | `WireFormat` | `Provider` (the built-ins) |

### An inspector

```rust
impl Inspector for MyScanner {
    fn name(&self) -> &str { "my-scanner" }
    fn inspect(&self, text: &str) -> Vec<Finding> { … }
}
```

Two rules that are not negotiable:

- **Every occurrence, not the first.** Enough to refuse on is not enough to
  redact with.
- **A `Finding` carries no value** — the rule id and the span, never the matched
  text. A message that quotes what it caught is the leak it was meant to stop.

Hand it to `ProxyState.inspectors` and you are done. Nothing in the proxy has to
learn your scanner's name.

### A wire format

`Provider` is the set this repository ships. It is **one implementation** of
`WireFormat`, not the definition of what a format can be — an in-house gateway
with its own shape implements the trait and is a first-class citizen:

```rust
impl WireFormat for HouseFormat {
    fn name(&self) -> &str { "house" }
    fn tool_calls(&self, body: &[u8]) -> Option<Vec<ToolCall>> { … }
    fn tool_calls_streaming(&self, body: &[u8]) -> Option<Vec<ToolCall>> { … }
    fn visit_prompt(&self, value: &mut Value, f: &mut …) -> Option<()> { … }
}
```

Hand it to `ProxyState.provider` as an `Arc<dyn WireFormat>`. No enum variant,
no edit inside the proxy, no fork.

`visit_prompt` covers both reading and rewriting deliberately. Two methods that
decided separately which fields hold prose would drift, and the day they did, a
scanner would be reading a field the redactor no longer edits.

`tests/custom_wire_format.rs` drives a format defined outside `parse.rs` all the
way through the proxy — tool-call guarding and request inspection both — written
the way an outside adapter has to be written, so the seam regressing breaks a
test rather than someone's fork.

## Adapters are separate crates on purpose

`pasu-pii-kr` depends on no pasu crate. That is what lets a gateway which has
never heard of pasu use the scanner, so the adapter cannot live inside it.

The adapter used to live inside `pasu-proxy` instead, which made the proxy the
only thing able to use it and made every build compile the scanner whether or not
anyone wanted it. Now the scanner stays dependency-free, the proxy pulls the
adapter in by feature, and another host can take the adapter without taking the
proxy.

```bash
# no scanner at all — the proxy still builds and runs
cargo build -p pasu-proxy --no-default-features
```

CI builds that combination, and each feature alone. A `use` added outside a
`cfg` compiles fine with default features on and breaks only for the person
building without them — who is exactly the person least able to report it.

## Where the policy lives

`redact::Policy` is in `pasu-core`, not in the proxy. What a finding *means* —
refuse, or replace — is the same question wherever an inspector runs, and a
second host answering it separately is the drift a security tool cannot afford.
