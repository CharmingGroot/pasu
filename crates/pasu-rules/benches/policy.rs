//! Micro-benchmarks for the policy hot path (`RuleEngine::evaluate`).
//!
//! Measures per-decision overhead of the cooperative layer's policy check —
//! the cost paid on every tool call / egress. Run: `cargo bench -p pasu-rules`.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use pasu_core::{Event, EventKind, RuleEngine};
use pasu_rules::RulesetEngine;

const POLICY: &str = r#"
rules:
  - name: allow-llm
    match: { host: ".openai.com" }
    action: allow
  - name: block-rm
    match: { tool: rm_rf }
    action: deny
  - name: confirm-transfer
    match: { tool: transfer_funds }
    action: ask
default: deny
"#;

fn egress(host: &str) -> Event {
    Event {
        kind: EventKind::Egress {
            host: host.to_string(),
            port: 443,
        },
    }
}

fn tool(name: &str) -> Event {
    Event {
        kind: EventKind::ToolCall {
            name: name.to_string(),
            input: "{}".into(),
        },
    }
}

fn bench_evaluate(c: &mut Criterion) {
    let engine = RulesetEngine::from_yaml(POLICY).expect("valid policy");

    // First-rule hit (allow by domain suffix).
    let allowed = egress("api.openai.com");
    c.bench_function("evaluate/allow_first_rule", |b| {
        b.iter(|| engine.evaluate(black_box(&allowed)))
    });

    // Mid-list hit (tool deny).
    let denied = tool("rm_rf");
    c.bench_function("evaluate/deny_tool", |b| {
        b.iter(|| engine.evaluate(black_box(&denied)))
    });

    // No match → walks all rules, then default-deny (worst case for this ruleset).
    let unmatched = egress("evil.example");
    c.bench_function("evaluate/default_deny_full_scan", |b| {
        b.iter(|| engine.evaluate(black_box(&unmatched)))
    });
}

criterion_group!(benches, bench_evaluate);
criterion_main!(benches);
