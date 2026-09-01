# pasu-inspect-presidio

Read [Microsoft Presidio](https://github.com/microsoft/presidio) recognizer YAML
and use it as a `pasu_core::Inspector`.

Teams that write PII rules down already have them, and not in pasu's format —
they have Presidio recognizers, because Presidio's no-code YAML is the closest
thing this space has to a common format. Asking someone to retype that is asking
them not to adopt pasu.

**There is no interchange standard, and this is not one.** It reads one popular
format, and says so.

## Use

```rust
use pasu_core::Inspector;
use pasu_inspect_presidio::Import;

let rules = Import { min_score: 0.5 }.read(&yaml, "presidio")?;
for finding in rules.inspect("the number is 123-45-6789") {
    println!("{} at {:?}", finding.rule, finding.span);
}
```

From `pasu-proxy`, with no code:

```bash
pasu-proxy --policy policy.yaml --upstream https://api.openai.com \
  --presidio-rules ./recognizers.yaml --presidio-min-score 0.5
```

## What crosses

Regex and deny-list recognizers — the ones expressible in YAML at all. Anything
needing named-entity recognition is a Python class, and a path that runs on every
message could not afford to execute one.

## What does not, and why

Each of these is reported by name with its reason. None is dropped quietly.

| | why |
|---|---|
| **score** | Presidio ships patterns as weak as `0.01` because context words raise them. A `Finding` has no score and one finding refuses a request, so importing without a threshold fires on ordinary text. |
| **context words** | Nothing here raises a weak pattern, so an imported one is *more* false-positive-prone than it was in Presidio. That is why the threshold exists. |
| **regex dialect** | Presidio is Python `re`; this is the Rust `regex` crate, deliberately — no backtracking, so no ReDoS on a per-message path. Lookaround and backreferences do not compile. |
| **checksums** | Validation logic written in Python does not cross. A pattern that had a checksum behind it arrives without one. |

## Loading is fail-closed; matching is not

A file containing anything unusable is an `Error` naming each recognizer and why.
A half-loaded rule set that reports success leaves an operator believing they are
covered, which is worse than a refusal.

`read_lossy` exists for a caller that means to inspect the gap itself. Everything
else should use `read`.

Once loaded, matching is default-allow, like any content filter over human text:
no allowlist can enumerate the sentences a person may write.

## A finding never carries the value

`Finding` holds the inspector, the rule id and a span. Not the matched text — a
block message that quotes what it caught is the leak it was meant to stop.

## Tested against the real file

Three of the tests run against `example_recognizers.yaml` from
microsoft/presidio, vendored verbatim, rather than a document written here. The
shipped file is refused for its `0.01` zip-code pattern; its deny-list recognizer
imports and matches; and lowering the threshold admits the weak one, so the knob
is not decorative.

## License

Apache-2.0, like the rest of pasu.
