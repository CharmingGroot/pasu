//! pasu-l1 — tool call gate.
//!
//! 에이전트가 tool을 실행하기 전에 선언을 검사해 사전 차단(cooperative).
//! `RuleEngine`으로 평가하고 `Layer` trait을 구현한다.
//! 설계: docs/architecture.md (L1)

// TODO(MVP): ToolGate { engine: Box<dyn RuleEngine>, enabled: bool } 구현
//   - impl Layer for ToolGate
//   - on_tool_start 진입점에서 Event::ToolCall로 변환 → engine.evaluate
// 테스트: 룰마다 TP(차단) + TN(통과) 쌍 — docs/testing.md
