//! Parse LLM API responses for the tool calls a model proposed.
//!
//! The tool-call *decision* (name + arguments) rides in the provider response
//! body, so extracting it here catches intent without any SDK hook. OpenAI
//! (+ compatible) is implemented; Anthropic / Gemini extend [`Provider`].

use serde::Deserialize;

/// A tool call a model proposed, extracted from a provider response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    pub name: String,
    /// Raw arguments as the provider emitted them (OpenAI: a JSON string).
    pub arguments: String,
}

/// Which provider wire format the response uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Provider {
    /// OpenAI Chat Completions and OpenAI-compatible servers (vLLM, etc.).
    OpenAi,
    // Anthropic, Gemini: follow-up.
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
}
