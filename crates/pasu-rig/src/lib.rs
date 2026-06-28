//! pasu-rig — rig framework integration (the cooperative, in-process layer).
//!
//! Implements rig's hook points so a rig agent is guarded by default:
//!   - `AgentHook`     — tool-call gate + HITL approval (Verdict::Deny/Ask).
//!   - `HttpClientExt` — LLM egress guard (allow/deny provider HTTP by policy).
//!
//! Decisions go through `RuleEngine` and map to `pasu_core::Verdict`. This is
//! the *cooperative* layer: it sees tool_name/args and declared egress, but not
//! arbitrary code a tool runs internally. The kernel eBPF egress guard
//! (pasu-egress / pasu-ebpf) is the *enforcing* backstop — see the combo PoC
//! (enforcing > cooperative). Design: docs/rig-integration.md, docs/architecture.md
//!
//! rig is the only crate allowed to depend on `rig`; pasu-core stays pure so the
//! engine can later gain adapters for other agent frameworks.

// TODO(MVP): PasuSecurityHook { engine: Box<dyn RuleEngine>, enabled: bool }
//   - impl rig::AgentHook  — ToolCall event → Event::ToolCall → engine.evaluate
//        Verdict::Deny → Flow::skip, Verdict::Ask → HITL approval gate (fail-closed)
//   - impl rig::HttpClientExt (PasuHttpClient) — provider egress → Event::Egress
// Validated as PoCs in pasu-rig-hook-poc (tool gate / HITL / LLM egress).
// Tests: a TP(block) + TN(pass) pair per rule, plus a HITL deny path — docs/testing.md
