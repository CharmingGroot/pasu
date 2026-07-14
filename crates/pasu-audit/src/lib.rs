//! pasu-audit — concrete [`AuditSink`] implementations.
//!
//! Layers emit [`AuditRecord`]s through the `pasu_core::AuditSink` trait; this
//! crate provides where they go:
//!   - [`JsonlSink`]  — one JSON object per line (JSONL) to any writer (stderr,
//!     a file, a pipe to a SIEM).
//!   - [`MemorySink`] — collects records in memory (tests, or a UI buffer).
//!
//!   - [`OtelSink`]   — export each record as an OpenTelemetry span (OTLP),
//!     behind the `otel` feature. pasu exports to your standard observability
//!     stack rather than growing its own dashboard.
//!
//! Design: roadmap.md (M5 observability).

#[cfg(feature = "otel")]
pub mod otel;
#[cfg(feature = "otel")]
pub use otel::OtelSink;

use std::io::Write;
use std::sync::Mutex;

use pasu_core::{AuditRecord, AuditSink};

/// Writes each audit record as one JSON line (JSONL) to `W`.
pub struct JsonlSink<W: Write + Send> {
    writer: Mutex<W>,
}

impl<W: Write + Send> JsonlSink<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: Mutex::new(writer),
        }
    }

    /// Recover the underlying writer (e.g. to inspect it in tests).
    pub fn into_inner(self) -> W {
        self.writer.into_inner().unwrap()
    }
}

impl JsonlSink<std::io::Stderr> {
    /// A sink that writes JSONL to stderr.
    pub fn stderr() -> Self {
        Self::new(std::io::stderr())
    }
}

impl<W: Write + Send> AuditSink for JsonlSink<W> {
    fn record(&self, record: &AuditRecord) {
        // Best-effort: audit logging must never break the guard path.
        let Ok(mut w) = self.writer.lock() else {
            return;
        };
        if let Ok(line) = serde_json::to_string(record) {
            let _ = writeln!(w, "{line}");
        }
    }
}

/// Collects audit records in memory. Useful for tests and as a small UI buffer.
#[derive(Default)]
pub struct MemorySink {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemorySink {
    /// A snapshot of the records collected so far.
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().unwrap().clone()
    }
}

impl AuditSink for MemorySink {
    fn record(&self, record: &AuditRecord) {
        self.records.lock().unwrap().push(record.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pasu_core::{Event, EventKind, Verdict};

    fn tool_deny() -> AuditRecord {
        let ev = Event {
            kind: EventKind::ToolCall {
                name: "rm_rf".into(),
                input: "{}".into(),
            },
        };
        AuditRecord::new("proxy-tool", &ev, &Verdict::Deny("destructive".into()))
    }

    fn egress_allow() -> AuditRecord {
        let ev = Event {
            kind: EventKind::Egress {
                host: "api.openai.com".into(),
                port: 443,
            },
        };
        AuditRecord::new("egress", &ev, &Verdict::Allow)
    }

    #[test]
    fn jsonl_writes_one_json_line_per_record() {
        let sink = JsonlSink::new(Vec::<u8>::new());
        sink.record(&tool_deny());
        sink.record(&egress_allow());
        let out = String::from_utf8(sink.into_inner()).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("\"verdict\":\"deny\""));
        assert!(lines[0].contains("\"subject\":\"rm_rf\""));
        assert!(lines[1].contains("\"verdict\":\"allow\""));
        assert!(lines[1].contains("api.openai.com:443"));
    }

    #[test]
    fn memory_sink_collects_records() {
        let sink = MemorySink::default();
        sink.record(&tool_deny());
        sink.record(&egress_allow());
        let recs = sink.records();
        assert_eq!(recs.len(), 2);
        assert_eq!(recs[0].subject, "rm_rf");
        assert_eq!(recs[1].subject, "api.openai.com:443");
    }
}
