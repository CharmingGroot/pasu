//! pasu-egress — control plane for the kernel egress guard (eBPF loader + policy).
//!
//! [`EgressLayer`] adapts a [`RuleEngine`] into [`pasu_core::Layer`], so egress
//! decisions share the same `Verdict` model as the rig (cooperative) layer. The
//! eBPF program enforces in-kernel (BLOCK map); this is the control-plane policy
//! view — the seam where a DNS-aware resolver or a userspace fallback will plug
//! in. Design: docs/architecture.md, docs/repo-structure.md
//!
//! The eBPF loader binary lives in `main.rs`.

use pasu_core::{Event, EventKind, Layer, RuleEngine, Verdict};

/// The egress layer: evaluates outbound-network events through a [`RuleEngine`].
///
/// Non-egress events are out of scope (returns `Allow`); when disabled, the
/// layer passes everything (runtime toggle, mirroring the other layers).
pub struct EgressLayer<E: RuleEngine> {
    engine: E,
    enabled: bool,
}

impl<E: RuleEngine> EgressLayer<E> {
    /// Enabled layer backed by `engine`.
    pub fn new(engine: E) -> Self {
        Self {
            engine,
            enabled: true,
        }
    }

    /// Runtime toggle. When disabled the layer allows everything.
    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }
}

impl<E: RuleEngine> Layer for EgressLayer<E> {
    fn name(&self) -> &str {
        "egress"
    }

    fn enabled(&self) -> bool {
        self.enabled
    }

    fn check(&self, event: &Event) -> Verdict {
        if !self.enabled {
            return Verdict::Allow;
        }
        match &event.kind {
            EventKind::Egress { .. } => self.engine.evaluate(event),
            // This layer only governs egress; other events are someone else's job.
            _ => Verdict::Allow,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// allow one host, deny the rest.
    struct AllowHost(&'static str);
    impl RuleEngine for AllowHost {
        fn evaluate(&self, event: &Event) -> Verdict {
            match &event.kind {
                EventKind::Egress { host, .. } if host == self.0 => Verdict::Allow,
                EventKind::Egress { host, .. } => Verdict::Deny(format!("blocked: {host}")),
                _ => Verdict::Allow,
            }
        }
    }

    fn egress(host: &str, port: u16) -> Event {
        Event {
            kind: EventKind::Egress {
                host: host.to_string(),
                port,
            },
        }
    }

    #[test]
    fn evaluates_egress_through_the_engine() {
        let layer = EgressLayer::new(AllowHost("llm.internal"));
        assert_eq!(layer.name(), "egress");
        assert!(layer.enabled());
        assert!(matches!(
            layer.check(&egress("llm.internal", 443)),
            Verdict::Allow
        ));
        assert!(matches!(
            layer.check(&egress("evil.example", 443)),
            Verdict::Deny(_)
        ));
    }

    #[test]
    fn ignores_non_egress_events() {
        let layer = EgressLayer::new(AllowHost("x"));
        let tool_call = Event {
            kind: EventKind::ToolCall {
                name: "do_thing".into(),
                input: "{}".into(),
            },
        };
        assert!(matches!(layer.check(&tool_call), Verdict::Allow));
    }

    #[test]
    fn disabled_allows_everything() {
        let mut layer = EgressLayer::new(AllowHost("x"));
        layer.set_enabled(false);
        assert!(!layer.enabled());
        assert!(matches!(
            layer.check(&egress("evil.example", 1)),
            Verdict::Allow
        ));
    }
}
