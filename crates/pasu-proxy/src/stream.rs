//! Reassemble tool calls from streaming (SSE) provider responses.
//!
//! A streaming response carries the same tool-call decision as a non-streaming
//! one, split across events. Each provider fragments differently: OpenAI Chat
//! Completions concatenates `delta.tool_calls[].function.arguments` per index,
//! the Responses API announces an item and then streams its arguments,
//! Anthropic pairs a `content_block_start` (the name) with `input_json_delta`
//! fragments, and Gemini emits whole `functionCall` parts per event. The proxy
//! buffers the full response body, so reassembly runs over the complete stream.
//!
//! Strict on purpose: an event whose data is not JSON, or a fragment that
//! cannot be tied to a named call, makes the whole stream unreadable (`None`).
//! A lenient parser that skipped what it did not understand would skip exactly
//! the call it was there to catch.

use std::collections::BTreeMap;

use serde_json::Value;

use crate::parse::{self, Provider, ToolCall};

const DONE: &str = "[DONE]";
const RESPONSES_EVENT_PREFIX: &str = "response.";

/// Whether a response content-type is a server-sent-event stream.
#[must_use]
pub fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|c| c.to_ascii_lowercase().contains("text/event-stream"))
}

/// Extract the tool calls from a buffered SSE body.
///
/// Same contract as [`parse::extract`]: `Some(calls)` when the body is a stream
/// of the given provider (`calls` may be empty — nothing to guard), `None` when
/// it is not one this can read.
#[must_use]
pub fn extract_stream(body: &[u8], provider: Provider) -> Option<Vec<ToolCall>> {
    let events = events(std::str::from_utf8(body).ok()?)?;
    match provider {
        Provider::OpenAi if events.iter().any(is_responses_event) => responses(&events),
        Provider::OpenAi => openai_chat(&events),
        Provider::Anthropic => anthropic(&events),
        Provider::Gemini => gemini(&events),
    }
}

/// Every event's data, parsed. Follows the SSE framing rules — CR, LF or CRLF
/// line ends, a blank line ends an event, several `data:` lines in one event
/// join with a newline — and also reads a final event that is not followed by
/// a blank line, since a client may act on it.
fn events(text: &str) -> Option<Vec<Value>> {
    let text = text.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = Vec::new();
    for block in text.split("\n\n") {
        let mut data: Option<String> = None;
        for line in block.lines() {
            if line.starts_with(':') {
                continue;
            }
            let (field, value) = line.split_once(':').unwrap_or((line, ""));
            if field != "data" {
                continue;
            }
            let value = value.strip_prefix(' ').unwrap_or(value);
            match &mut data {
                Some(d) => {
                    d.push('\n');
                    d.push_str(value);
                }
                None => data = Some(value.to_string()),
            }
        }
        let Some(data) = data else { continue };
        if data.trim() == DONE {
            continue;
        }
        out.push(serde_json::from_str(&data).ok()?);
    }
    if out.is_empty() {
        return None;
    }
    Some(out)
}

fn is_responses_event(event: &Value) -> bool {
    event
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|t| t.starts_with(RESPONSES_EVENT_PREFIX))
}

fn index(v: &Value, key: &str) -> Option<u64> {
    match v.get(key) {
        None => Some(0),
        Some(i) => i.as_u64(),
    }
}

/// Name and argument fragments of one call, as they accumulate.
#[derive(Default)]
struct Partial {
    name: Option<String>,
    arguments: String,
}

impl Partial {
    fn absorb(&mut self, function: &Value) -> Option<()> {
        if let Some(name) = function.get("name").filter(|n| !n.is_null()) {
            self.name = Some(name.as_str()?.to_string());
        }
        if let Some(args) = function.get("arguments").filter(|a| !a.is_null()) {
            self.arguments.push_str(args.as_str()?);
        }
        Some(())
    }

    /// Fragments that never got a name cannot be judged, so they fail closed.
    fn finish(self) -> Option<ToolCall> {
        Some(ToolCall::from_raw_arguments(&self.name?, &self.arguments))
    }
}

/// Key for the deprecated `delta.function_call`, which has no index of its own.
const LEGACY_FUNCTION_CALL: u64 = u64::MAX;

fn openai_chat(events: &[Value]) -> Option<Vec<ToolCall>> {
    let mut acc: BTreeMap<(u64, u64), Partial> = BTreeMap::new();
    for event in events {
        let Some(choices) = event.get("choices") else {
            continue;
        };
        for choice in choices.as_array()? {
            let Some(delta) = choice.get("delta").filter(|d| !d.is_null()) else {
                continue;
            };
            let ci = index(choice, "index")?;
            if let Some(tool_calls) = delta.get("tool_calls").filter(|t| !t.is_null()) {
                for tc in tool_calls.as_array()? {
                    let Some(function) = tc.get("function") else {
                        continue;
                    };
                    acc.entry((ci, index(tc, "index")?))
                        .or_default()
                        .absorb(function)?;
                }
            }
            if let Some(fc) = delta.get("function_call").filter(|f| !f.is_null()) {
                acc.entry((ci, LEGACY_FUNCTION_CALL))
                    .or_default()
                    .absorb(fc)?;
            }
        }
    }
    acc.into_values().map(Partial::finish).collect()
}

/// Responses API events. An item is announced by `output_item.added` and
/// restated whole by `output_item.done`; argument deltas in between fill in an
/// item that was announced with none. A delta for an item never announced has
/// no name to judge, so it fails closed.
fn responses(events: &[Value]) -> Option<Vec<ToolCall>> {
    let mut items: BTreeMap<u64, Value> = BTreeMap::new();
    let mut deltas: BTreeMap<u64, String> = BTreeMap::new();
    for event in events {
        let Some(kind) = event.get("type").and_then(Value::as_str) else {
            continue;
        };
        match kind {
            "response.output_item.added" | "response.output_item.done" => {
                let item = event.get("item")?.clone();
                items.insert(index(event, "output_index")?, item);
            }
            "response.function_call_arguments.delta" | "response.custom_tool_call_input.delta" => {
                let delta = event.get("delta")?.as_str()?;
                deltas
                    .entry(index(event, "output_index")?)
                    .or_default()
                    .push_str(delta);
            }
            "response.completed" | "response.incomplete" | "response.failed" => {
                let output = event.get("response").and_then(|r| r.get("output"));
                for (i, item) in output
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .enumerate()
                {
                    items.entry(i as u64).or_insert_with(|| item.clone());
                }
            }
            _ => {}
        }
    }
    let mut calls = Vec::new();
    for (i, delta) in &deltas {
        let item = items.get_mut(i)?;
        let field = if item.get("type").and_then(Value::as_str) == Some("custom_tool_call") {
            "input"
        } else {
            "arguments"
        };
        let empty = item
            .get(field)
            .and_then(Value::as_str)
            .is_none_or(str::is_empty);
        if empty {
            item.as_object_mut()?
                .insert(field.to_string(), Value::String(delta.clone()));
        }
    }
    for item in items.values() {
        if let Some(call) = parse::responses_item(item)? {
            calls.push(call);
        }
    }
    Some(calls)
}

/// Only `tool_use` blocks run on the client. Other blocks — text, and
/// `server_tool_use`, which streams `input_json_delta` too — are tracked so
/// their deltas are skipped rather than mistaken for a nameless call; a delta
/// for a block never started fails closed.
fn anthropic(events: &[Value]) -> Option<Vec<ToolCall>> {
    let mut blocks: BTreeMap<u64, Option<Partial>> = BTreeMap::new();
    for event in events {
        let Some(kind) = event.get("type").and_then(Value::as_str) else {
            continue;
        };
        match kind {
            "content_block_start" => {
                let block = event.get("content_block")?;
                let tool = if block.get("type")?.as_str()? == "tool_use" {
                    Some(Partial {
                        name: Some(block.get("name")?.as_str()?.to_string()),
                        arguments: String::new(),
                    })
                } else {
                    None
                };
                blocks.insert(index(event, "index")?, tool);
            }
            "content_block_delta" => {
                let delta = event.get("delta")?;
                if delta.get("type").and_then(Value::as_str) != Some("input_json_delta") {
                    continue;
                }
                let Some(partial) = blocks.get_mut(&index(event, "index")?)? else {
                    continue;
                };
                partial
                    .arguments
                    .push_str(delta.get("partial_json")?.as_str()?);
            }
            _ => {}
        }
    }
    blocks
        .into_values()
        .flatten()
        .map(Partial::finish)
        .collect()
}

fn gemini(events: &[Value]) -> Option<Vec<ToolCall>> {
    let mut calls = Vec::new();
    for event in events {
        calls.extend(parse::gemini(event)?);
    }
    Some(calls)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_event_stream_content_type() {
        assert!(is_event_stream(Some("text/event-stream")));
        assert!(is_event_stream(Some("text/event-stream; charset=utf-8")));
        assert!(!is_event_stream(Some("application/json")));
        assert!(!is_event_stream(None));
    }

    // OpenAI: name in the first chunk, arguments split across two more.
    const OPENAI_SSE: &str = "\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"delete_file\",\"arguments\":\"\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{\\\"path\\\":\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"\\\"/etc/passwd\\\"}\"}}]}}]}\n\n\
data: [DONE]\n";

    #[test]
    fn reassembles_openai_tool_call_across_chunks() {
        let calls = extract_stream(OPENAI_SSE.as_bytes(), Provider::OpenAi).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn openai_text_only_stream_has_no_tool_calls() {
        let sse =
            "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi\"}}]}\n\ndata: [DONE]\n";
        let calls = extract_stream(sse.as_bytes(), Provider::OpenAi).expect("parses");
        assert!(calls.is_empty());
    }

    // Anthropic: tool_use block start + two input_json_delta fragments.
    const ANTHROPIC_SSE: &str = "\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":1,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"delete_file\",\"input\":{}}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":1,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"\\\"/etc/passwd\\\"}\"}}\n\n\
event: message_stop\n\
data: {\"type\":\"message_stop\"}\n";

    #[test]
    fn reassembles_anthropic_tool_use_across_deltas() {
        let calls = extract_stream(ANTHROPIC_SSE.as_bytes(), Provider::Anthropic).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn anthropic_text_only_stream_has_no_tool_calls() {
        let sse = "\
event: content_block_start\n\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n\
event: content_block_delta\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n";
        let calls = extract_stream(sse.as_bytes(), Provider::Anthropic).expect("parses");
        assert!(calls.is_empty());
    }

    #[test]
    fn reassembles_gemini_function_call_chunk() {
        let sse = "data: {\"candidates\":[{\"content\":{\"parts\":[{\"functionCall\":{\"name\":\"delete_file\",\"args\":{\"path\":\"/etc/passwd\"}}}]}}]}\n";
        let calls = extract_stream(sse.as_bytes(), Provider::Gemini).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "delete_file");
        assert_eq!(calls[0].arguments, r#"{"path":"/etc/passwd"}"#);
    }

    #[test]
    fn non_sse_body_is_passthrough_none() {
        assert!(extract_stream(b"{\"choices\":[]}", Provider::OpenAi).is_none());
        assert!(extract_stream(b"plain text", Provider::OpenAi).is_none());
        assert!(extract_stream(&[0xff, 0xfe], Provider::OpenAi).is_none());
    }
    /// SSE allows one event's data over several `data:` lines. Treating each
    /// line as its own JSON document dropped the event, and the call in it.
    #[test]
    fn a_multi_line_data_event_is_joined_not_skipped() {
        let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":\n\
data: [{\"index\":0,\"function\":{\"name\":\"shell\",\"arguments\":\"{}\"}}]}}]}\n\n\
data: [DONE]\n\n";
        let calls = extract_stream(sse.as_bytes(), Provider::OpenAi).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].name, "shell");
    }

    #[test]
    fn crlf_framing_is_read() {
        let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"shell\",\"arguments\":\"{}\"}}]}}]}\r\n\r\ndata: [DONE]\r\n\r\n";
        let calls = extract_stream(sse.as_bytes(), Provider::OpenAi).expect("parses");
        assert_eq!(calls[0].name, "shell");
    }

    #[test]
    fn an_event_that_is_not_json_makes_the_stream_unreadable() {
        let sse = "data: {\"choices\":[]}\n\ndata: {not json\n\n";
        assert!(extract_stream(sse.as_bytes(), Provider::OpenAi).is_none());
    }

    #[test]
    fn argument_fragments_without_a_name_fail_closed() {
        let sse = "data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"{}\"}}]}}]}\n\n";
        assert!(extract_stream(sse.as_bytes(), Provider::OpenAi).is_none());
    }

    #[test]
    fn a_responses_delta_for_an_unannounced_item_fails_closed() {
        let sse = "data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":3,\"delta\":\"{}\"}\n\n";
        assert!(extract_stream(sse.as_bytes(), Provider::OpenAi).is_none());
    }

    #[test]
    fn responses_arguments_streamed_after_the_item_are_guarded() {
        let sse = "\
data: {\"type\":\"response.output_item.added\",\"output_index\":0,\"item\":{\"type\":\"function_call\",\"name\":\"shell\",\"arguments\":\"\"}}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"{\\\"cmd\\\":\"}\n\n\
data: {\"type\":\"response.function_call_arguments.delta\",\"output_index\":0,\"delta\":\"\\\"id\\\"}\"}\n\n";
        let calls = extract_stream(sse.as_bytes(), Provider::OpenAi).expect("parses");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].arguments, r#"{"cmd":"id"}"#);
    }

    /// `server_tool_use` streams `input_json_delta` like a client tool does,
    /// but the provider runs it. Its deltas are not a nameless call.
    #[test]
    fn anthropic_server_tool_deltas_are_not_a_call() {
        let sse = "\
data: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"server_tool_use\",\"id\":\"s1\",\"name\":\"web_search\",\"input\":{}}}\n\n\
data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"query\\\":\\\"x\\\"}\"}}\n\n";
        let calls = extract_stream(sse.as_bytes(), Provider::Anthropic).expect("parses");
        assert!(calls.is_empty());
    }

    #[test]
    fn anthropic_delta_for_a_block_never_started_fails_closed() {
        let sse = "data: {\"type\":\"content_block_delta\",\"index\":4,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n";
        assert!(extract_stream(sse.as_bytes(), Provider::Anthropic).is_none());
    }
}
