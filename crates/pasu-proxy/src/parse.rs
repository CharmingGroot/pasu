//! Parse LLM API responses for the tool calls a model proposed.
//!
//! The tool-call *decision* (name + arguments) rides in the provider response
//! body, so extracting it here catches intent without any SDK hook. The three
//! provider wire formats cover effectively every SDK: OpenAI Chat Completions
//! (+ compatible) and the Responses API, Anthropic Messages, and Gemini
//! `generateContent`.

use serde_json::Value;

/// A tool call a model proposed, extracted from a provider response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolCall {
    /// Tool name as the model asked for it.
    pub name: String,
    /// Arguments as a JSON string. OpenAI emits a string already; Anthropic and
    /// Gemini emit a JSON object, which we serialize so the guard sees one shape.
    pub arguments: String,
}

impl ToolCall {
    /// A call whose arguments arrived as a JSON *string*, as OpenAI sends them.
    ///
    /// The string is what the model wrote, escapes and all; the agent decodes it
    /// before running anything. Guarding the undecoded form lets `\u002fetc`
    /// past a rule that looks for `/etc`, so a string that parses is
    /// re-serialized — the shape Anthropic and Gemini arguments already have.
    /// One that does not parse is kept verbatim: there is no decoded form to
    /// prefer, and the agent cannot decode it either.
    #[must_use]
    pub fn from_raw_arguments(name: &str, raw: &str) -> Self {
        let arguments = serde_json::from_str::<Value>(raw)
            .map(|v| v.to_string())
            .unwrap_or_else(|_| raw.to_string());
        Self {
            name: name.to_string(),
            arguments,
        }
    }
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

/// A provider's wire format: how to find tool calls in a response, and where a
/// person's text sits in a request.
///
/// The proxy is deliberately blind to which formats exist. [`Provider`] is the
/// set this repository ships, and it is one implementation of this trait rather
/// than the definition of what a format can be — an in-house gateway with its
/// own shape implements this and is a first-class citizen, without editing an
/// enum here and without a fork.
pub trait WireFormat: Send + Sync {
    /// For logs and errors. Not parsed by anything.
    fn name(&self) -> &str;

    /// Tool calls in a whole (non-streaming) response body.
    ///
    /// `None` means this is not a body the format recognises. The proxy treats
    /// that as "nothing to guard here", not as "allowed" — the kernel layer is
    /// what covers a path this cannot read.
    fn tool_calls(&self, body: &[u8]) -> Option<Vec<ToolCall>>;

    /// Tool calls reassembled from an SSE stream body.
    fn tool_calls_streaming(&self, body: &[u8]) -> Option<Vec<ToolCall>>;

    /// Visit every piece of human-authored text in a **request** body.
    ///
    /// Returning `Some(replacement)` from `f` writes it back, which is how
    /// redaction works. One method for both reading and rewriting on purpose:
    /// two that decided separately which fields hold prose would drift, and the
    /// day they did, a scanner would be reading a field the redactor no longer
    /// edits.
    fn visit_prompt(
        &self,
        value: &mut serde_json::Value,
        f: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Option<()>;

    /// What `method` on `path` (no query) is, to the proxy.
    ///
    /// The default treats every path as a completion — the strictest reading:
    /// the prompt is screened and the response must parse as this format or it
    /// is refused. A format that knows its API names the rest.
    fn route(&self, method: &str, path: &str) -> Route {
        let _ = (method, path);
        Route::Completion
    }
}

/// How the proxy treats an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    /// A model call: the prompt is screened, and the response must parse as the
    /// format's response — its tool calls are guarded, and a body that does not
    /// parse is refused.
    Completion,
    /// Carries a prompt but cannot return a tool call (token counting): the
    /// prompt is screened, the response is not parsed.
    RequestOnly,
    /// Neither sends a prompt nor returns a tool call (listing models).
    Passthrough,
    /// Not an endpoint this format knows. Refused before it leaves: an unknown
    /// endpoint is one the proxy cannot guard in either direction.
    Unknown,
}

const GET: &str = "GET";

/// `path` is `prefix/<one segment>` — a single resource under a collection.
fn one_below<'a>(path: &'a str, collection: &str) -> Option<&'a str> {
    let rest = path.split_once(collection)?.1.strip_prefix('/')?;
    (!rest.is_empty() && !rest.contains('/')).then_some(rest)
}

fn is_model_listing(method: &str, path: &str) -> bool {
    method == GET && (path.ends_with("/models") || one_below(path, "/models").is_some())
}

fn openai_route(method: &str, path: &str) -> Route {
    if path.ends_with("/chat/completions") || path.ends_with("/responses") {
        return Route::Completion;
    }
    // Retrieving or cancelling a stored response returns the response itself,
    // tool calls included.
    if one_below(path, "/responses").is_some()
        || path
            .strip_suffix("/cancel")
            .is_some_and(|p| one_below(p, "/responses").is_some())
    {
        return Route::Completion;
    }
    if is_model_listing(method, path) {
        return Route::Passthrough;
    }
    Route::Unknown
}

fn anthropic_route(method: &str, path: &str) -> Route {
    if path.ends_with("/messages") {
        return Route::Completion;
    }
    if path.ends_with("/messages/count_tokens") {
        return Route::RequestOnly;
    }
    if is_model_listing(method, path) {
        return Route::Passthrough;
    }
    Route::Unknown
}

fn gemini_route(method: &str, path: &str) -> Route {
    if path.ends_with(":generateContent") || path.ends_with(":streamGenerateContent") {
        return Route::Completion;
    }
    if path.ends_with(":countTokens") {
        return Route::RequestOnly;
    }
    if is_model_listing(method, path) {
        return Route::Passthrough;
    }
    Route::Unknown
}

impl WireFormat for Provider {
    fn name(&self) -> &str {
        match self {
            Provider::OpenAi => "openai",
            Provider::Anthropic => "anthropic",
            Provider::Gemini => "gemini",
        }
    }

    fn tool_calls(&self, body: &[u8]) -> Option<Vec<ToolCall>> {
        extract(body, *self)
    }

    fn tool_calls_streaming(&self, body: &[u8]) -> Option<Vec<ToolCall>> {
        crate::stream::extract_stream(body, *self)
    }

    fn visit_prompt(
        &self,
        value: &mut serde_json::Value,
        f: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Option<()> {
        crate::prompt::visit(value, *self, f)
    }

    fn route(&self, method: &str, path: &str) -> Route {
        match self {
            Provider::OpenAi => openai_route(method, path),
            Provider::Anthropic => anthropic_route(method, path),
            Provider::Gemini => gemini_route(method, path),
        }
    }
}

/// Extract the tool calls from a response body.
///
/// - `Some(calls)` — the body is a response of this provider; `calls` may be
///   empty (a normal completion with nothing to guard).
/// - `None` — the body is not a response this provider sends, or one whose tool
///   calls are malformed. On a completion endpoint the proxy refuses those: a
///   shape it cannot read is a shape it cannot guard.
#[must_use]
pub fn extract(body: &[u8], provider: Provider) -> Option<Vec<ToolCall>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    match provider {
        Provider::OpenAi => openai(&value),
        Provider::Anthropic => anthropic(&value),
        Provider::Gemini => gemini_body(&value),
    }
}

/// Chat Completions or the Responses API, told apart by their top-level key.
pub(crate) fn openai(value: &Value) -> Option<Vec<ToolCall>> {
    if let Some(choices) = value.get("choices") {
        return openai_chat(choices);
    }
    responses_output(value.get("output")?)
}

// Chat Completions: choices[].message.tool_calls[].function.{name, arguments},
// and the deprecated choices[].message.function_call.{name, arguments}.
fn openai_chat(choices: &Value) -> Option<Vec<ToolCall>> {
    let mut calls = Vec::new();
    for choice in choices.as_array()? {
        let Some(message) = choice.get("message") else {
            continue;
        };
        if let Some(tool_calls) = message.get("tool_calls").filter(|v| !v.is_null()) {
            for tc in tool_calls.as_array()? {
                calls.push(openai_function(tc.get("function")?)?);
            }
        }
        if let Some(fc) = message.get("function_call").filter(|v| !v.is_null()) {
            calls.push(openai_function(fc)?);
        }
    }
    Some(calls)
}

fn openai_function(function: &Value) -> Option<ToolCall> {
    let name = function.get("name")?.as_str()?;
    let arguments = match function.get("arguments") {
        None | Some(Value::Null) => "",
        Some(v) => v.as_str()?,
    };
    Some(ToolCall::from_raw_arguments(name, arguments))
}

/// Output items the provider executes itself. The work is done by the time the
/// response arrives, and nothing on the client runs it.
const SERVER_SIDE_ITEMS: &[&str] = &[
    "web_search_call",
    "file_search_call",
    "code_interpreter_call",
    "image_generation_call",
    "mcp_call",
    "mcp_list_tools",
];

const CALL_SUFFIX: &str = "_call";

/// Responses API: `output[]` items. Anything typed `*_call` that the provider
/// does not run itself is something the client is being asked to run, so it is
/// a tool call — including item types newer than this code.
pub(crate) fn responses_output(output: &Value) -> Option<Vec<ToolCall>> {
    let mut calls = Vec::new();
    for item in output.as_array()? {
        if let Some(call) = responses_item(item)? {
            calls.push(call);
        }
    }
    Some(calls)
}

/// `None` when the item is malformed; `Some(None)` when it is not a tool call.
pub(crate) fn responses_item(item: &Value) -> Option<Option<ToolCall>> {
    let kind = item.get("type")?.as_str()?;
    let named = |field: &str| -> Option<ToolCall> {
        let name = item.get("name")?.as_str()?;
        let raw = match item.get(field) {
            None | Some(Value::Null) => "",
            Some(v) => v.as_str()?,
        };
        Some(ToolCall::from_raw_arguments(name, raw))
    };
    match kind {
        "function_call" | "mcp_approval_request" => named("arguments").map(Some),
        // Free-form input, not JSON: kept verbatim.
        "custom_tool_call" => {
            let name = item.get("name")?.as_str()?;
            let input = item.get("input").and_then(Value::as_str).unwrap_or("");
            Some(Some(ToolCall {
                name: name.to_string(),
                arguments: input.to_string(),
            }))
        }
        k if SERVER_SIDE_ITEMS.contains(&k) => Some(None),
        k if k.ends_with(CALL_SUFFIX) => {
            let name = k.trim_end_matches(CALL_SUFFIX);
            let arguments = item
                .get("action")
                .or_else(|| item.get("input"))
                .or_else(|| item.get("arguments"))
                .map(Value::to_string)
                .unwrap_or_default();
            Some(Some(ToolCall {
                name: name.to_string(),
                arguments,
            }))
        }
        _ => Some(None),
    }
}

// Anthropic: content[] blocks where type == "tool_use" carry {name, input}.
fn anthropic(value: &Value) -> Option<Vec<ToolCall>> {
    let mut calls = Vec::new();
    for block in value.get("content")?.as_array()? {
        if block.get("type")?.as_str()? != "tool_use" {
            continue;
        }
        calls.push(ToolCall {
            name: block.get("name")?.as_str()?.to_string(),
            arguments: block
                .get("input")
                .cloned()
                .unwrap_or(Value::Null)
                .to_string(),
        });
    }
    Some(calls)
}

/// Gemini answers `streamGenerateContent` without `alt=sse` as a JSON array of
/// the same responses it would otherwise stream.
fn gemini_body(value: &Value) -> Option<Vec<ToolCall>> {
    let Some(chunks) = value.as_array() else {
        return gemini(value);
    };
    let mut calls = Vec::new();
    for chunk in chunks {
        calls.extend(gemini(chunk)?);
    }
    Some(calls)
}

// Gemini: candidates[].content.parts[].functionCall.{name, args}. A prompt the
// provider refused carries `promptFeedback` and no candidates.
pub(crate) fn gemini(value: &Value) -> Option<Vec<ToolCall>> {
    let candidates = match value.get("candidates") {
        Some(c) => c.as_array()?,
        None => {
            value.get("promptFeedback")?;
            return Some(Vec::new());
        }
    };
    let mut calls = Vec::new();
    for candidate in candidates {
        let Some(parts) = candidate.get("content").and_then(|c| c.get("parts")) else {
            continue;
        };
        for part in parts.as_array()? {
            let Some(fc) = part.get("functionCall") else {
                continue;
            };
            calls.push(ToolCall {
                name: fc.get("name")?.as_str()?.to_string(),
                arguments: fc.get("args").cloned().unwrap_or(Value::Null).to_string(),
            });
        }
    }
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
    /// The model controls the escapes in an OpenAI arguments string. The agent
    /// decodes them; the guard must see what the agent will see.
    #[test]
    fn escaped_arguments_are_decoded_before_the_guard_sees_them() {
        let body = br#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"read_file","arguments":"{\"path\":\"\\u002fetc\\u002fpasswd\"}"}}]}}]}"#;
        let calls = extract(body, Provider::OpenAi).expect("parses");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn arguments_that_are_not_json_are_kept_verbatim() {
        let call = ToolCall::from_raw_arguments("t", "{broken");
        assert_eq!(call.arguments, "{broken");
    }

    #[test]
    fn a_malformed_tool_call_makes_the_response_unreadable() {
        let body = br#"{"choices":[{"message":{"tool_calls":[{"function":{"name":7}}]}}]}"#;
        assert!(extract(body, Provider::OpenAi).is_none());
    }

    /// An object that is no provider's response used to parse as "no tool
    /// calls", because every field defaulted.
    #[test]
    fn an_unrelated_object_is_not_a_response() {
        assert!(extract(br#"{"hello":"world"}"#, Provider::OpenAi).is_none());
        assert!(extract(br#"{"hello":"world"}"#, Provider::Anthropic).is_none());
        assert!(extract(br#"{"hello":"world"}"#, Provider::Gemini).is_none());
    }

    #[test]
    fn a_responses_item_type_newer_than_this_code_is_still_a_call() {
        let body = br#"{"output":[{"type":"quantum_shell_call","action":{"cmd":"x"}}]}"#;
        let calls = extract(body, Provider::OpenAi).expect("parses");
        assert_eq!(calls[0].name, "quantum_shell");
    }

    #[test]
    fn a_gemini_prompt_the_provider_refused_has_no_calls() {
        let body = br#"{"promptFeedback":{"blockReason":"SAFETY"}}"#;
        assert_eq!(extract(body, Provider::Gemini), Some(Vec::new()));
    }

    #[test]
    fn routes_are_named_per_provider() {
        let o = Provider::OpenAi;
        assert_eq!(o.route("POST", "/v1/chat/completions"), Route::Completion);
        assert_eq!(
            o.route("POST", "/openai/deployments/d/chat/completions"),
            Route::Completion
        );
        assert_eq!(o.route("POST", "/v1/responses"), Route::Completion);
        assert_eq!(o.route("GET", "/v1/responses/resp_1"), Route::Completion);
        assert_eq!(
            o.route("POST", "/v1/responses/resp_1/cancel"),
            Route::Completion
        );
        assert_eq!(o.route("GET", "/v1/models"), Route::Passthrough);
        assert_eq!(o.route("POST", "/v1/models"), Route::Unknown);
        assert_eq!(o.route("POST", "/v1/embeddings"), Route::Unknown);
        assert_eq!(o.route("POST", "/v1/files"), Route::Unknown);

        let a = Provider::Anthropic;
        assert_eq!(a.route("POST", "/v1/messages"), Route::Completion);
        assert_eq!(
            a.route("POST", "/v1/messages/count_tokens"),
            Route::RequestOnly
        );
        assert_eq!(a.route("POST", "/v1/messages/batches"), Route::Unknown);

        let g = Provider::Gemini;
        assert_eq!(
            g.route("POST", "/v1beta/models/g:generateContent"),
            Route::Completion
        );
        assert_eq!(
            g.route("POST", "/v1beta/models/g:streamGenerateContent"),
            Route::Completion
        );
        assert_eq!(
            g.route("POST", "/v1beta/models/g:countTokens"),
            Route::RequestOnly
        );
        assert_eq!(g.route("GET", "/v1beta/models"), Route::Passthrough);
        assert_eq!(
            g.route("POST", "/v1beta/models/g:embedContent"),
            Route::Unknown
        );
    }
}
