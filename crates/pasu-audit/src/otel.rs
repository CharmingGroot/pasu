//! [`OtelSink`] — export each verdict as an OpenTelemetry span (OTLP).
//!
//! pasu does not grow its own observability backend; it emits to the standard
//! and lets the user's stack (Grafana/Tempo/Jaeger/Loki) render it. Each
//! [`AuditRecord`] becomes one span: name = layer, attributes = verdict / subject
//! / reason / layer (+ best-effort tool|host).
//!
//! **Observability is not on the guard's critical path.** Export runs in a
//! background batch processor; a missing/erroring collector is logged and
//! dropped — it never blocks or changes a verdict. (fail-closed applies to the
//! *decision*, never to *telemetry*.)

use opentelemetry::trace::{Span, Status, Tracer, TracerProvider as _};
use opentelemetry::KeyValue;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::runtime;
use opentelemetry_sdk::trace::TracerProvider;
use opentelemetry_sdk::Resource;
use pasu_core::{AuditRecord, AuditSink, VerdictKind};

const SERVICE_NAME: &str = "pasu";
const TRACER_NAME: &str = "pasu-audit";

type BuildError = Box<dyn std::error::Error + Send + Sync>;

/// An [`AuditSink`] that emits each record as an OTLP span.
pub struct OtelSink {
    provider: TracerProvider,
}

impl OtelSink {
    /// Build a sink exporting to `endpoint` (e.g. `http://localhost:4317`), or
    /// to the standard `OTEL_EXPORTER_OTLP_ENDPOINT` when `endpoint` is `None`.
    ///
    /// Must be called inside a Tokio runtime (the batch exporter spawns there).
    /// Construction failure is returned; runtime export errors are handled by
    /// the SDK (logged), never surfaced to `record`.
    pub fn new(endpoint: Option<&str>) -> Result<Self, BuildError> {
        let mut builder = opentelemetry_otlp::SpanExporter::builder().with_tonic();
        if let Some(ep) = endpoint {
            builder = builder.with_endpoint(ep);
        }
        let exporter = builder.build()?;

        let provider = TracerProvider::builder()
            .with_batch_exporter(exporter, runtime::Tokio)
            .with_resource(Resource::new([KeyValue::new("service.name", SERVICE_NAME)]))
            .build();
        Ok(Self { provider })
    }

    /// Flush any buffered spans. Best-effort.
    pub fn shutdown(&self) {
        if let Err(e) = self.provider.shutdown() {
            log::warn!("pasu otel: shutdown/flush failed: {e}");
        }
    }
}

/// Map a record to OTel span attributes (pure — unit-tested without an exporter).
fn attributes(record: &AuditRecord) -> Vec<KeyValue> {
    let verdict = match record.verdict {
        VerdictKind::Allow => "allow",
        VerdictKind::Deny => "deny",
        VerdictKind::Ask => "ask",
    };
    let mut attrs = vec![
        KeyValue::new("pasu.layer", record.layer.clone()),
        KeyValue::new("pasu.verdict", verdict),
        KeyValue::new("pasu.subject", record.subject.clone()),
    ];
    // Best-effort split: egress subjects are "host:port"; tool subjects are names.
    if record.layer.contains("egress") && record.subject.contains(':') {
        attrs.push(KeyValue::new("pasu.host", record.subject.clone()));
    } else {
        attrs.push(KeyValue::new("pasu.tool", record.subject.clone()));
    }
    if let Some(reason) = &record.reason {
        attrs.push(KeyValue::new("pasu.reason", reason.clone()));
    }
    attrs
}

impl AuditSink for OtelSink {
    fn record(&self, record: &AuditRecord) {
        // Create + end one span per decision. The batch processor exports it in
        // the background; any collector error is the SDK's problem, not ours.
        let tracer = self.provider.tracer(TRACER_NAME);
        let mut span = tracer
            .span_builder(record.layer.clone())
            .with_attributes(attributes(record))
            .start(&tracer);
        if record.verdict == VerdictKind::Deny {
            span.set_status(Status::error("denied"));
        }
        span.end();
    }
}

impl Drop for OtelSink {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasu_core::{Event, EventKind, Verdict};

    fn rec_tool_deny() -> AuditRecord {
        let ev = Event {
            kind: EventKind::ToolCall {
                name: "transfer_funds".into(),
                input: "{}".into(),
            },
        };
        AuditRecord::new("rig-tool", &ev, &Verdict::Deny("needs approval".into()))
    }

    fn rec_egress_allow() -> AuditRecord {
        let ev = Event {
            kind: EventKind::Egress {
                host: "api.openai.com".into(),
                port: 443,
            },
        };
        AuditRecord::new("egress", &ev, &Verdict::Allow)
    }

    fn get<'a>(attrs: &'a [KeyValue], key: &str) -> Option<&'a opentelemetry::Value> {
        attrs
            .iter()
            .find(|kv| kv.key.as_str() == key)
            .map(|kv| &kv.value)
    }

    #[test]
    fn tool_deny_maps_to_attributes() {
        let a = attributes(&rec_tool_deny());
        assert_eq!(get(&a, "pasu.verdict").unwrap().as_str(), "deny");
        assert_eq!(get(&a, "pasu.layer").unwrap().as_str(), "rig-tool");
        assert_eq!(get(&a, "pasu.tool").unwrap().as_str(), "transfer_funds");
        assert_eq!(get(&a, "pasu.reason").unwrap().as_str(), "needs approval");
        assert!(get(&a, "pasu.host").is_none());
    }

    #[test]
    fn egress_allow_maps_host_and_no_reason() {
        let a = attributes(&rec_egress_allow());
        assert_eq!(get(&a, "pasu.verdict").unwrap().as_str(), "allow");
        assert_eq!(get(&a, "pasu.host").unwrap().as_str(), "api.openai.com:443");
        assert!(get(&a, "pasu.reason").is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn record_does_not_block_when_collector_is_absent() {
        // fail-open: exporting to a dead endpoint must not panic or block the
        // (synchronous) record() call — the guard path is unaffected.
        let sink = OtelSink::new(Some("http://127.0.0.1:59999")).expect("builds lazily");
        sink.record(&rec_tool_deny());
        sink.record(&rec_egress_allow());
        // if we got here without hanging/panicking, telemetry stayed off the hot path
    }
}
