//! The text an agent is about to send to a provider.
//!
//! The proxy forwards requests untouched today, so anything an agent scraped
//! out of a file or a database row reaches the provider unexamined. The kernel
//! layer cannot help here: it has to permit the provider's address or the agent
//! cannot work at all, and past that the payload is TLS and opaque to it. The
//! request body is the only place this is readable.
//!
//! # Why not scan the raw bytes
//!
//! A request body is JSON with a known shape, and most of it is not prose —
//! tool schemas, base64 attachments, model names, ids. Running a PII matcher
//! over the whole thing invites false positives from the parts no human wrote,
//! and a false positive here stops an agent mid-task.
//!
//! So this pulls out the fields a person's text actually lands in, per provider,
//! and nothing else. Three shapes cover every SDK, for the same reason the
//! response side only needs three.
//!
//! # What it does not do
//!
//! It does not decide anything. It returns text; whether that text is allowed is
//! [`pasu_pii_kr`]'s question and the proxy's to act on.

use serde_json::Value;

use crate::parse::Provider;

/// Every piece of human-authored text in a request body, in the order it
/// appears.
///
/// `None` means the body is not a request shape this understands — not JSON, or
/// an unknown layout. The caller decides what to do with that; this does not
/// guess, because guessing wrong in either direction is worse than saying so.
#[must_use]
pub fn prompt_text(body: &[u8], provider: Provider) -> Option<Vec<String>> {
    let value: Value = serde_json::from_slice(body).ok()?;
    let found = match provider {
        Provider::OpenAi => openai(&value),
        Provider::Anthropic => anthropic(&value),
        Provider::Gemini => gemini(&value),
    }?;
    Some(found)
}

/// `{"messages":[{"role":..,"content":"…"}]}`, and the content-parts form the
/// same API also accepts.
fn openai(value: &Value) -> Option<Vec<String>> {
    let messages = value.get("messages")?.as_array()?;
    let mut out = Vec::new();
    for message in messages {
        match message.get("content") {
            Some(Value::String(text)) => out.push(text.clone()),
            Some(Value::Array(parts)) => push_parts(parts, "text", &mut out),
            _ => {}
        }
        // A tool result is human-facing text too, and it is the field most
        // likely to carry a record an agent just read.
        if let Some(Value::String(text)) = message.get("tool_call_id").and(message.get("content")) {
            out.push(text.clone());
        }
    }
    Some(out)
}

/// `{"system":…,"messages":[{"role":..,"content":…}]}`.
fn anthropic(value: &Value) -> Option<Vec<String>> {
    let messages = value.get("messages")?.as_array()?;
    let mut out = Vec::new();
    match value.get("system") {
        Some(Value::String(text)) => out.push(text.clone()),
        Some(Value::Array(parts)) => push_parts(parts, "text", &mut out),
        _ => {}
    }
    for message in messages {
        match message.get("content") {
            Some(Value::String(text)) => out.push(text.clone()),
            Some(Value::Array(parts)) => {
                push_parts(parts, "text", &mut out);
                // tool_result content, which carries whatever a tool returned.
                for part in parts {
                    match part.get("content") {
                        Some(Value::String(text)) => out.push(text.clone()),
                        Some(Value::Array(inner)) => push_parts(inner, "text", &mut out),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(out)
}

/// `{"contents":[{"parts":[{"text":"…"}]}]}`, plus the system instruction.
fn gemini(value: &Value) -> Option<Vec<String>> {
    let contents = value.get("contents")?.as_array()?;
    let mut out = Vec::new();
    if let Some(parts) = value
        .get("systemInstruction")
        .and_then(|s| s.get("parts"))
        .and_then(Value::as_array)
    {
        push_parts(parts, "text", &mut out);
    }
    for content in contents {
        if let Some(parts) = content.get("parts").and_then(Value::as_array) {
            push_parts(parts, "text", &mut out);
        }
    }
    Some(out)
}

/// Collect `field` from every part that carries it as a string.
fn push_parts(parts: &[Value], field: &str, out: &mut Vec<String>) {
    for part in parts {
        if let Some(Value::String(text)) = part.get(field) {
            out.push(text.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn openai_messages_are_found_as_strings_and_as_parts() {
        let body = br#"{"model":"gpt-4","messages":[
            {"role":"system","content":"you are helpful"},
            {"role":"user","content":[{"type":"text","text":"the record says 900101-1234567"}]}
        ]}"#;

        let text = prompt_text(body, Provider::OpenAi).expect("a known shape");

        assert!(
            text.iter().any(|t| t.contains("900101-1234567")),
            "{text:?}"
        );
        assert!(text.iter().any(|t| t == "you are helpful"));
    }

    #[test]
    fn anthropic_system_and_tool_results_are_found() {
        let body = br#"{"model":"claude","system":"be careful","messages":[
            {"role":"user","content":"hello"},
            {"role":"user","content":[{"type":"tool_result","content":"customer 900101-1234567"}]}
        ]}"#;

        let text = prompt_text(body, Provider::Anthropic).expect("a known shape");

        assert!(text.iter().any(|t| t == "be careful"));
        assert!(
            text.iter().any(|t| t.contains("900101-1234567")),
            "a tool result is the field most likely to carry a record: {text:?}"
        );
    }

    #[test]
    fn gemini_contents_and_system_instruction_are_found() {
        let body = br#"{"systemInstruction":{"parts":[{"text":"be brief"}]},
            "contents":[{"parts":[{"text":"id 900101-1234567"}]}]}"#;

        let text = prompt_text(body, Provider::Gemini).expect("a known shape");

        assert!(text.iter().any(|t| t == "be brief"));
        assert!(text.iter().any(|t| t.contains("900101-1234567")));
    }

    /// The point of parsing rather than scanning: the parts no human wrote stay
    /// out, so a base64 blob or a tool schema cannot trip a matcher.
    #[test]
    fn nothing_but_human_text_is_returned() {
        let body = br#"{"model":"gpt-4","tools":[{"function":{"name":"sql","description":"900101-1234567"}}],
            "messages":[{"role":"user","content":"hello"}]}"#;

        let text = prompt_text(body, Provider::OpenAi).expect("a known shape");

        assert_eq!(text, vec!["hello".to_string()]);
    }

    #[test]
    fn an_unknown_shape_says_so_rather_than_guessing() {
        assert!(prompt_text(b"not json", Provider::OpenAi).is_none());
        assert!(prompt_text(br#"{"other":1}"#, Provider::OpenAi).is_none());
    }
}
