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
    let mut value: Value = serde_json::from_slice(body).ok()?;
    let mut found = Vec::new();
    visit(&mut value, provider, &mut |text| {
        found.push(text.to_string());
        None
    })?;
    Some(found)
}

/// Rewrite the same fields [`prompt_text`] reads, and return the new body.
///
/// `rewrite` is given each piece of text and returns a replacement, or `None` to
/// leave it alone.
///
/// **One traversal, two uses.** Extraction and rewriting share the walk on
/// purpose: two functions that decided separately which fields hold prose would
/// drift, and the day they did, a scanner would be reading a field the redactor
/// no longer edits. The body is rebuilt from the parsed value rather than by
/// string replacement, so what leaves is still valid JSON in the provider's
/// shape.
///
/// `None` means the body is not a shape this understands, exactly as in
/// [`prompt_text`].
#[must_use]
pub fn rewrite_prompt(
    body: &[u8],
    provider: Provider,
    rewrite: &mut dyn FnMut(&str) -> Option<String>,
) -> Option<Vec<u8>> {
    let mut value: Value = serde_json::from_slice(body).ok()?;
    visit(&mut value, provider, rewrite)?;
    serde_json::to_vec(&value).ok()
}

/// The single traversal. `f` sees every human-authored string; returning
/// `Some(replacement)` writes it back.
fn visit(
    value: &mut Value,
    provider: Provider,
    f: &mut dyn FnMut(&str) -> Option<String>,
) -> Option<()> {
    match provider {
        Provider::OpenAi => openai(value, f),
        Provider::Anthropic => anthropic(value, f),
        Provider::Gemini => gemini(value, f),
    }
}

/// Apply `f` to a string field in place.
fn touch(slot: Option<&mut Value>, f: &mut dyn FnMut(&str) -> Option<String>) {
    if let Some(Value::String(text)) = slot {
        if let Some(replacement) = f(text) {
            *text = replacement;
        }
    }
}

/// `{"messages":[{"role":..,"content":"…"}]}`, and the content-parts form the
/// same API also accepts. A tool result rides in `content` too, and it is the
/// field most likely to carry a record an agent just read.
fn openai(value: &mut Value, f: &mut dyn FnMut(&str) -> Option<String>) -> Option<()> {
    let messages = value.get_mut("messages")?.as_array_mut()?;
    for message in messages {
        match message.get_mut("content") {
            Some(Value::String(_)) => touch(message.get_mut("content"), f),
            Some(Value::Array(parts)) => walk_parts(parts, "text", f),
            _ => {}
        }
    }
    Some(())
}

/// `{"system":…,"messages":[{"role":..,"content":…}]}`.
fn anthropic(value: &mut Value, f: &mut dyn FnMut(&str) -> Option<String>) -> Option<()> {
    match value.get_mut("system") {
        Some(Value::String(_)) => touch(value.get_mut("system"), f),
        Some(Value::Array(parts)) => walk_parts(parts, "text", f),
        _ => {}
    }
    let messages = value.get_mut("messages")?.as_array_mut()?;
    for message in messages {
        match message.get_mut("content") {
            Some(Value::String(_)) => touch(message.get_mut("content"), f),
            Some(Value::Array(parts)) => {
                walk_parts(parts, "text", f);
                // tool_result content, which carries whatever a tool returned.
                for part in parts.iter_mut() {
                    match part.get_mut("content") {
                        Some(Value::String(_)) => touch(part.get_mut("content"), f),
                        Some(Value::Array(inner)) => walk_parts(inner, "text", f),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    Some(())
}

/// `{"contents":[{"parts":[{"text":"…"}]}]}`, plus the system instruction.
fn gemini(value: &mut Value, f: &mut dyn FnMut(&str) -> Option<String>) -> Option<()> {
    if let Some(parts) = value
        .get_mut("systemInstruction")
        .and_then(|s| s.get_mut("parts"))
        .and_then(Value::as_array_mut)
    {
        walk_parts(parts, "text", f);
    }
    let contents = value.get_mut("contents")?.as_array_mut()?;
    for content in contents {
        if let Some(parts) = content.get_mut("parts").and_then(Value::as_array_mut) {
            walk_parts(parts, "text", f);
        }
    }
    Some(())
}

/// Apply `f` to `field` on every part that carries it as a string.
fn walk_parts(parts: &mut [Value], field: &str, f: &mut dyn FnMut(&str) -> Option<String>) {
    for part in parts.iter_mut() {
        touch(part.get_mut(field), f);
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
