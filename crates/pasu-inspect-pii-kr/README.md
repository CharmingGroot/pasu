# pasu-inspect-pii-kr

Use [`pasu-pii-kr`](../pasu-pii-kr) as a `pasu_core::Inspector`.

```rust
use pasu_core::Inspector;
use pasu_inspect_pii_kr::PiiKr;

let found = PiiKr::builtin().inspect("고객 주민번호는 900101-1234567 입니다");
assert_eq!(found[0].rule, "ko-rrn");
```

## Why an adapter needs its own crate

`pasu-pii-kr` depends on no pasu crate, deliberately. That is what lets a
gateway which has never heard of pasu use the scanner, and it is worth keeping —
so the adapter cannot live there.

It used to live inside `pasu-proxy`. That made the proxy the only thing able to
use it, and made every build of the proxy compile the scanner whether or not
anyone wanted it.

Here both sides are free. The scanner stays dependency-free, the proxy takes
this crate only when asked, and a different host — a daemon, someone else's
gateway — can take the adapter without taking the proxy.

## The shape to copy

An inspector for a scanner this repository has never heard of is the same three
lines of surface:

```rust
impl Inspector for MyScanner {
    fn name(&self) -> &str { "my-scanner" }
    fn inspect(&self, text: &str) -> Vec<Finding> { … }
}
```

Two rules that are not negotiable:

- **Every occurrence, not the first.** Enough to refuse on is not enough to
  redact with.
- **A `Finding` carries no value.** The rule id and the span, never the matched
  text — a message that quotes what it caught is the leak it was meant to stop.

## License

Apache-2.0, like the rest of pasu.
