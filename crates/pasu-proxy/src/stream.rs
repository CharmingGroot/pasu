//! Reassemble tool calls from streaming (SSE) provider responses.
//!
//! A streaming response carries the same tool-call decision as a non-streaming
//! one, split across `data:` chunks. Each provider fragments differently:
//! OpenAI concatenates `delta.tool_calls[].function.arguments` per index,
//! Anthropic pairs a `content_block_start` (the name) with `input_json_delta`
//! fragments (the arguments), and Gemini emits whole `functionCall` parts per
//! chunk. The proxy buffers the full response body, so reassembly here runs
//! over the complete stream.

use std::collections::BTreeMap;

use serde::Deserialize;

use crate::parse::{extract, Provider, ToolCall};

/// Whether a response content-type is a server-sent-event stream.
#[must_use]
pub fn is_event_stream(content_type: Option<&str>) -> bool {
    content_type.is_some_and(|c| c.to_ascii_lowercase().contains("text/event-stream"))
}

/// Extract the tool calls from a buffered SSE body.
///
/// Same contract as [`extract`]: `Some(calls)` when the body parsed as a
/// stream of the given provider (`calls` may be empty — nothing to guard),
/// `None` when it isn't SSE we understand (the proxy passes it through).
#[must_use]
pub fn extract_stream(body: &[u8], provider: Provider) -> Option<Vec<ToolCall>> {
    let text = std::str::from_utf8(body).ok()?;
    let datas: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .map(str::trim_start)
        .filter(|d| !d.is_empty() && *d != "[DONE]")
        .collect();
    if datas.is_empty() {
        return None;
    }
    match provider {
        Provider::OpenAi => Some(reassemble_openai(&datas)),
        Provider::Anthropic => Some(reassemble_anthropic(&datas)),
        Provider::Gemini => Some(reassemble_gemini(&datas)),
    }
}

// OpenAI: choices[].delta.tool_calls[] — name arrives once per tool index,
// arguments arrive as string fragments to concatenate.
#[derive(Deserialize)]
struct OaChunk {
    #[serde(default)]
    choices: Vec<OaChoice>,
}

#[derive(Deserialize)]
struct OaChoice {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    delta: Option<OaDelta>,
}

#[derive(Deserialize)]
struct OaDelta {
    #[serde(default)]
    tool_calls: Vec<OaToolDelta>,
}

#[derive(Deserialize)]
struct OaToolDelta {
    #[serde(default)]
    index: u32,
    #[serde(default)]
    function: Option<OaFnDelta>,
}

#[derive(Deserialize)]
struct OaFnDelta {
    name: Option<String>,
    arguments: Option<String>,
}

fn reassemble_openai(datas: &[&str]) -> Vec<ToolCall> {
    // (choice index, tool index) -> (name, concatenated arguments)
    let mut acc: BTreeMap<(u32, u32), (String, String)> = BTreeMap::new();
    for data in datas {
        let Ok(chunk) = serde_json::from_str::<OaChunk>(data) else {
            continue;
        };
        for choice in chunk.choices {
            let Some(delta) = choice.delta else { continue };
            for tc in delta.tool_calls {
                let entry = acc.entry((choice.index, tc.index)).or_default();
                if let Some(f) = tc.function {
                    if let Some(name) = f.name {
                        entry.0 = name;
                    }
                    if let Some(args) = f.arguments {
                        entry.1.push_str(&args);
                    }
                }
            }
        }
    }
    acc.into_values()
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, arguments)| ToolCall { name, arguments })
        .collect()
}

// Anthropic: a content_block_start of type tool_use carries the name; the
// arguments arrive as input_json_delta fragments for the same block index.
#[derive(Deserialize)]
struct AnEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    index: u32,
    #[serde(default)]
    content_block: Option<AnBlock>,
    #[serde(default)]
    delta: Option<AnDelta>,
}

#[derive(Deserialize)]
struct AnBlock {
    #[serde(rename = "type")]
    kind: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct AnDelta {
    #[serde(rename = "type")]
    kind: Option<String>,
    partial_json: Option<String>,
}

fn reassemble_anthropic(datas: &[&str]) -> Vec<ToolCall> {
    // block index -> (name, concatenated partial_json)
    let mut acc: BTreeMap<u32, (String, String)> = BTreeMap::new();
    for data in datas {
        let Ok(ev) = serde_json::from_str::<AnEvent>(data) else {
            continue;
        };
        match ev.kind.as_str() {
            "content_block_start" => {
                let Some(block) = ev.content_block else {
                    continue;
                };
                if block.kind == "tool_use" {
                    if let Some(name) = block.name {
                        acc.insert(ev.index, (name, String::new()));
                    }
                }
            }
            "content_block_delta" => {
                let Some(delta) = ev.delta else { continue };
                if delta.kind.as_deref() != Some("input_json_delta") {
                    continue;
                }
                if let (Some(json), Some(entry)) = (delta.partial_json, acc.get_mut(&ev.index)) {
                    entry.1.push_str(&json);
                }
            }
            _ => {}
        }
    }
    acc.into_values()
        .map(|(name, args)| ToolCall {
            name,
            // An empty input streams no delta; normalize to the empty object.
            arguments: if args.is_empty() { "{}".into() } else { args },
        })
        .collect()
}

// Gemini: each data chunk is a complete GenerateContentResponse fragment, so
// the non-streaming extractor applies per chunk.
fn reassemble_gemini(datas: &[&str]) -> Vec<ToolCall> {
    datas
        .iter()
        .filter_map(|d| extract(d.as_bytes(), Provider::Gemini))
        .flatten()
        .collect()
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
}
