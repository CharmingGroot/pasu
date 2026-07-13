//! Emit a few pasu verdicts as OTLP spans, for E2E against a real collector.
//!
//!   # terminal 1: an OTLP collector on :4317 (debug exporter prints spans)
//!   docker run --rm -p 4317:4317 otel/opentelemetry-collector:latest
//!   # terminal 2:
//!   cargo run -p pasu-audit --features otel --example otel_demo
//!
//! You should see the spans (pasu.layer / pasu.verdict / pasu.subject …) in the
//! collector output. Run without a collector and it still exits cleanly —
//! telemetry never blocks the guard.

use std::sync::Arc;

use pasu_audit::OtelSink;
use pasu_core::{AuditRecord, AuditSink, Event, EventKind, Verdict};

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:4317".to_string());
    println!("exporting demo spans to {endpoint}");

    let sink: Arc<dyn AuditSink> =
        Arc::new(OtelSink::new(Some(&endpoint)).expect("build OTLP exporter"));

    let decisions = [
        (
            "rig-tool",
            EventKind::ToolCall {
                name: "transfer_funds".into(),
                input: "{}".into(),
            },
            Verdict::Ask("human approval for money movement".into()),
        ),
        (
            "egress",
            EventKind::Egress {
                host: "pastebin.com".into(),
                port: 443,
            },
            Verdict::Deny("not on the allowlist".into()),
        ),
        (
            "egress",
            EventKind::Egress {
                host: "api.openai.com".into(),
                port: 443,
            },
            Verdict::Allow,
        ),
    ];

    for (layer, kind, verdict) in decisions {
        let ev = Event { kind };
        sink.record(&AuditRecord::new(layer, &ev, &verdict));
        println!("emitted: {layer} -> {verdict:?}");
    }

    // Give the batch processor a moment, then drop the sink — OtelSink::drop
    // runs shutdown(), flushing buffered spans to the collector.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    drop(sink);
    println!("done (spans flushed on shutdown)");
}
