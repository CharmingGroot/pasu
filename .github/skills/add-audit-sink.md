# Skill: add an audit sink backend

Add a new destination for `AuditRecord`s (every allow/deny/ask decision) — e.g.
a file rotator, a SIEM/HTTP forwarder, syslog. Sinks live in `pasu-audit` and
implement the `pasu-core` `AuditSink` trait, so nothing else has to change.

**Prerequisite reading:** [AGENTS.md](../../AGENTS.md), [CLAUDE.md](../../CLAUDE.md) §1.

## The seam

`pasu-core` defines:

```rust
pub trait AuditSink: Send + Sync {
    fn record(&self, record: &AuditRecord);
}
```

`AuditRecord` is the flattened decision (`layer`, `subject`, `verdict`, optional
`reason`), already `Serialize`. A `Guard` fans decisions to whatever sink it was
given via `.with_sink(Arc<dyn AuditSink>)`. Existing sinks in `pasu-audit`:
`JsonlSink` (writer), `MemorySink` (ring buffer, for tests/UI), `OtelSink`
(OTLP spans, behind the `otel` feature).

## Steps

1. **`crates/pasu-audit/src/`** — add `pub struct <Name>Sink` and
   `impl AuditSink for <Name>Sink`. Keep `record()` cheap and **non-blocking on
   the hot path**: buffer/queue rather than doing synchronous network I/O inside
   `record()` (it runs per decision). Re-export from `lib.rs`.
2. **Heavy or optional deps** (a network client, a syslog crate) go **behind a
   Cargo feature** (mirror the `otel` feature: `#[cfg(feature = "…")]` module +
   re-export). Never pull a heavyweight dep into the default build.
3. **Failure handling**: a sink that can't deliver must **not** break the guard —
   log and drop, never panic or block the decision. (Audit loss ≠ guard failure;
   but never let audit turn a decision fail-open.)
4. **Docs**: mention the sink in the README audit bullet and add a CHANGELOG entry.

## Tests

- Unit test that `record()` actually captures/forwards the record (assert the
  serialized output or the queued item). Follow `MemorySink`'s tests.
- If feature-gated, ensure the crate still builds **without** the feature
  (`cargo test -p pasu-audit`) and **with** it (`cargo test -p pasu-audit --features <name>`).
- `cargo clippy -p pasu-audit --all-targets -- -D warnings` · `cargo fmt`.

## Boundaries

- Sinks stay in `pasu-audit` and depend only on `pasu-core`. Don't make
  `pasu-audit` depend on another library crate.
- Don't change the `AuditSink` trait signature to fit one sink — if a sink needs
  more, that's a `pasu-core` design discussion, not a local hack.
