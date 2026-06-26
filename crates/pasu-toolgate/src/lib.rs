//! pasu-toolgate — tool call gate.
//!
//! Blocks tool calls before execution by inspecting the declaration (cooperative).
//! Evaluates via `RuleEngine` and implements the `Layer` trait.
//! Design: docs/architecture.md (tool gate)

// TODO(MVP): ToolGate { engine: Box<dyn RuleEngine>, enabled: bool }
//   - impl Layer for ToolGate
//   - convert the on_tool_start input into Event::ToolCall → engine.evaluate
// Tests: a TP(block) + TN(pass) pair per rule — docs/testing.md
