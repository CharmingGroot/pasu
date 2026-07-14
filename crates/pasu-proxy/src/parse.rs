//! Parse LLM API responses for the tool calls a model proposed.
//!
//! The tool-call *decision* (name + arguments) rides in the provider response
//! body, so extracting it here catches intent without any SDK hook. The three
//! provider wire formats cover effectively every SDK: OpenAI Chat Completions
//! (+ compatible), Anthropic Messages, and Gemini `generateContent`.

use serde::Deserialize;

/// A tool call a model proposed, extracted from a provider response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    /// Arguments as a JSON string. OpenAI emits a string already; Anthropic and
    /// Gemini emit a JSON object, which we serialize so the guard sees one shape.
    pub arguments: String,
}

/// Which provider wire format the response uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// OpenAI Chat Completions and OpenAI-compatible servers (vLLM, etc.).
    OpenAi,
    /// Anthropic Messages API.
    Anthropic,
    /// Google Gemini `generateContent`.
    Gemini,
}

/// Extract the tool calls from a response body.
///
/// - `Some(calls)` — the body parsed as a known response; `calls` may be empty
///   (a normal completion with nothing to guard).
/// - `None` — the body is not a response we can parse (not JSON / unknown shape
///   / a stream). The proxy passes those through untouched.
#[must_use]
pub fn extract(body: &[u8], provider: Provider) -> Option<Vec<ToolCall>> {
    match provider {
        Provider::OpenAi => extract_openai(body),
        Provider::Anthropic => extract_anthropic(body),
        Provider::Gemini => extract_gemini(body),
    }
}

// OpenAI: choices[].message.tool_calls[].function.{name, arguments}
#[derive(Deserialize)]
struct OpenAiResponse {
    #[serde(default)]
    choices: Vec<OpenAiChoice>,
}

#[derive(Deserialize)]
struct OpenAiChoice {
    #[serde(default)]
    message: Option<OpenAiMessage>,
}

#[derive(Deserialize)]
struct OpenAiMessage {
    #[serde(default)]
    tool_calls: Vec<OpenAiToolCall>,
}

#[derive(Deserialize)]
struct OpenAiToolCall {
    function: OpenAiFunction,
}

#[derive(Deserialize)]
struct OpenAiFunction {
    name: String,
    #[serde(default)]
    arguments: String,
}

fn extract_openai(body: &[u8]) -> Option<Vec<ToolCall>> {
    let resp: OpenAiResponse = serde_json::from_slice(body).ok()?;
    let calls = resp
        .choices
        .into_iter()
        .filter_map(|c| c.message)
        .flat_map(|m| m.tool_calls)
        .map(|tc| ToolCall {
            name: tc.function.name,
            arguments: tc.function.arguments,
        })
        .collect();
    Some(calls)
}

// Anthropic: content[] blocks where type == "tool_use" carry {name, input}.
#[derive(Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicBlock>,
}

#[derive(Deserialize)]
struct AnthropicBlock {
    #[serde(rename = "type")]
    kind: String,
    name: Option<String>,
    #[serde(default)]
    input: serde_json::Value,
}

fn extract_anthropic(body: &[u8]) -> Option<Vec<ToolCall>> {
    let resp: AnthropicResponse = serde_json::from_slice(body).ok()?;
    let calls = resp
        .content
        .into_iter()
        .filter(|b| b.kind == "tool_use")
        .filter_map(|b| {
            b.name.map(|name| ToolCall {
                name,
                arguments: b.input.to_string(),
            })
        })
        .collect();
    Some(calls)
}

// Gemini: candidates[].content.parts[].functionCall.{name, args}
#[derive(Deserialize)]
struct GeminiResponse {
    #[serde(default)]
    candidates: Vec<GeminiCandidate>,
}

#[derive(Deserialize)]
struct GeminiCandidate {
    #[serde(default)]
    content: Option<GeminiContent>,
}

#[derive(Deserialize)]
struct GeminiContent {
    #[serde(default)]
    parts: Vec<GeminiPart>,
}

#[derive(Deserialize)]
struct GeminiPart {
    #[serde(rename = "functionCall")]
    #[serde(default)]
    function_call: Option<GeminiFunctionCall>,
}

#[derive(Deserialize)]
struct GeminiFunctionCall {
    name: String,
    #[serde(default)]
    args: serde_json::Value,
}

fn extract_gemini(body: &[u8]) -> Option<Vec<ToolCall>> {
    let resp: GeminiResponse = serde_json::from_slice(body).ok()?;
    let calls = resp
        .candidates
        .into_iter()
        .filter_map(|c| c.content)
        .flat_map(|c| c.parts)
        .filter_map(|p| p.function_call)
        .map(|fc| ToolCall {
            name: fc.name,
            arguments: fc.args.to_string(),
        })
        .collect();
    Some(calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WITH_CALL: &[u8] = br#"{
        "choices": [
            { "message": { "role": "assistant", "tool_calls": [
                { "id": "c1", "type": "function",
                  "function": { "name": "delete_file", "arguments": "{\"path\":\"/etc/passwd\"}" } }
            ] } }
        ]
    }"#;

    #[test]
    fn extracts_openai_tool_call_name_and_args() {
        let calls = extract(WITH_CALL, Provider::OpenAi).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn plain_completion_has_no_tool_calls() {
        let body = br#"{"choices":[{"message":{"role":"assistant","content":"hi"}}]}"#;
        let calls = extract(body, Provider::OpenAi).expect("parses");
        assert!(calls.is_empty());
    }

    #[test]
    fn multiple_choices_and_calls_are_all_collected() {
        let body = br#"{"choices":[
            {"message":{"tool_calls":[{"function":{"name":"a","arguments":"{}"}}]}},
            {"message":{"tool_calls":[
                {"function":{"name":"b","arguments":"{}"}},
                {"function":{"name":"c","arguments":"{}"}}
            ]}}
        ]}"#;
        let calls = extract(body, Provider::OpenAi).expect("parses");
        let names: Vec<&str> = calls.iter().map(|c| c.name.as_str()).collect();
        assert_eq!(names, ["a", "b", "c"]);
    }

    #[test]
    fn non_json_body_is_passthrough_none() {
        assert!(extract(b"event: message\ndata: {}\n\n", Provider::OpenAi).is_none());
        assert!(extract(b"not json at all", Provider::OpenAi).is_none());
    }

    // Anthropic Messages: a tool_use block alongside a text block.
    const ANTHROPIC_WITH_CALL: &[u8] = br#"{
        "role": "assistant",
        "content": [
            { "type": "text", "text": "let me help" },
            { "type": "tool_use", "id": "tu_1", "name": "delete_file",
              "input": { "path": "/etc/passwd" } }
        ]
    }"#;

    #[test]
    fn extracts_anthropic_tool_use_name_and_input() {
        let calls = extract(ANTHROPIC_WITH_CALL, Provider::Anthropic).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn anthropic_text_only_has_no_tool_calls() {
        let body = br#"{"role":"assistant","content":[{"type":"text","text":"hi"}]}"#;
        let calls = extract(body, Provider::Anthropic).expect("parses");
        assert!(calls.is_empty());
    }

    // Gemini generateContent: a functionCall part.
    const GEMINI_WITH_CALL: &[u8] = br#"{
        "candidates": [
            { "content": { "role": "model", "parts": [
                { "functionCall": { "name": "delete_file",
                                    "args": { "path": "/etc/passwd" } } }
            ] } }
        ]
    }"#;

    #[test]
    fn extracts_gemini_function_call_name_and_args() {
        let calls = extract(GEMINI_WITH_CALL, Provider::Gemini).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn gemini_text_only_has_no_tool_calls() {
        let body = br#"{"candidates":[{"content":{"parts":[{"text":"hi"}]}}]}"#;
        let calls = extract(body, Provider::Gemini).expect("parses");
        assert!(calls.is_empty());
    }
}
