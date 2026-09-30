//! The decisions, without the transport.
//!
//! The reverse proxy, the Envoy `ext_proc` server and the LiteLLM guardrail
//! endpoint all ask the same three questions — may this endpoint be used, may
//! this prompt leave, may these tool calls reach the agent — and must answer
//! them identically. A second copy of any of these answers is the one that
//! drifts, so each front-end hands bytes to a [`Judge`] and acts on what comes
//! back.

use std::sync::Arc;

use axum::body::Bytes;
use pasu_core::redact::{redact, Action, Policy as RedactionPolicy};
use pasu_core::{Approver, Finding, Guard, Inspector, RuleEngine, Verdict};

use crate::inspect::inspect;
use crate::parse::{Route, ToolCall, WireFormat};
use crate::prompt::{prompt_text, rewrite_prompt};
use crate::stream::is_event_stream;

/// Default request cap. Large enough for vision payloads and long contexts,
/// which routinely exceed axum's 2 MiB default.
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 32 * 1024 * 1024;
/// Default response cap. A long streamed completion is mostly SSE framing.
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

/// Knobs with a safe default each.
#[derive(Debug, Clone)]
pub struct ProxyOptions {
    /// A request body larger than this is refused (413).
    pub max_request_bytes: usize,
    /// A response body larger than this is refused rather than buffered. The
    /// read timeout is an idle one, so without this a stream that never stops
    /// sending would be buffered without end.
    pub max_response_bytes: usize,
    /// Paths (no query) forwarded without any inspection, whatever the format
    /// says about them. For endpoints the operator has decided about.
    pub passthrough_paths: Vec<String>,
}

impl Default for ProxyOptions {
    fn default() -> Self {
        Self {
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            passthrough_paths: Vec::new(),
        }
    }
}

/// Everything a decision needs, and nothing about how the bytes arrived.
pub struct Judge<E: RuleEngine, A: Approver> {
    /// Judges each parsed tool call (policy → audit → HITL, fail-closed).
    pub guard: Guard<E, A>,
    /// The wire format to parse. A trait object, not the enum: the proxy runs a
    /// format rather than knowing which ones exist, so an in-house shape needs
    /// no change here.
    pub provider: Arc<dyn WireFormat>,
    /// What reads the prompt before it leaves, if anything.
    ///
    /// Empty is the default and means the prompt is not read at all. A
    /// deployment with no exposure to what an inspector matches should not
    /// have an agent stopped mid-task by a false positive it never asked for.
    /// Several, because the question is rarely single: Korean PII *and* cloud
    /// credentials *and* an in-house pattern.
    pub inspectors: Vec<Arc<dyn Inspector>>,
    /// Which findings refuse the request and which are replaced in it.
    /// Blocking everything is the default.
    pub redaction: RedactionPolicy,
    /// Size limits and operator-named exceptions.
    pub options: ProxyOptions,
}

/// What screening a request body decided.
#[derive(Debug)]
pub enum Screened {
    /// Send this body — the original, or one with findings replaced.
    Send(Bytes),
    /// Do not send it, for this reason.
    Refuse(String),
}

/// What screening a list of texts decided.
#[derive(Debug, PartialEq, Eq)]
pub enum TextScreen {
    /// Nothing found.
    Clean,
    /// Refuse, for this reason. Names the rule, never the value.
    Refuse(String),
    /// Every finding was replaced; these are the texts to send instead, in order.
    Rewritten(Vec<String>),
}

/// The parts of an upstream response a decision reads.
pub struct ResponseView<'a> {
    /// HTTP status.
    pub status: u16,
    /// `Content-Type`, if any.
    pub content_type: Option<&'a str>,
    /// Whether every `Content-Encoding` is `identity` (or there is none).
    pub identity_encoded: bool,
    /// The whole body.
    pub body: &'a [u8],
}

impl<E: RuleEngine, A: Approver> Judge<E, A> {
    /// What `method` on `path` (no query) is, operator exceptions first.
    pub fn route(&self, method: &str, path: &str) -> Route {
        if self.options.passthrough_paths.iter().any(|p| p == path) {
            return Route::Passthrough;
        }
        self.provider.route(method, path)
    }

    /// The refusal for an endpoint nobody named.
    #[must_use]
    pub fn unknown_endpoint(method: &str, path: &str) -> String {
        format!(
            "pasu-proxy: {method} {path} is not an endpoint this proxy guards, so it was not \
             sent (--passthrough-path forwards a path uninspected)"
        )
    }

    /// Inspect a request body's prompt, and refuse it, rewrite it, or leave it.
    ///
    /// Fail-closed: a hit refuses, and so does a body that cannot be read while
    /// an inspector is on — an inspector that cannot see the prompt has not
    /// checked it. A blocking finding wins over a redactable one: sending a
    /// body with one rule removed while another said "stop" would be answering
    /// the wrong question.
    pub fn screen_request(&self, body: Bytes) -> Screened {
        if self.inspectors.is_empty() || body.is_empty() {
            return Screened::Send(body);
        }
        let Some(texts) = prompt_text(&body, self.provider.as_ref()) else {
            return Screened::Refuse(format!(
                "pasu-proxy blocked this request: it is not a {} request it can read, so its \
                 prompt could not be inspected",
                self.provider.name()
            ));
        };
        let findings: Vec<Vec<Finding>> = texts.iter().map(|t| self.findings(t)).collect();
        if findings.iter().all(Vec::is_empty) {
            return Screened::Send(body);
        }
        if let Some(reason) = self.blocking(findings.iter().flatten()) {
            return Screened::Refuse(reason);
        }

        // The visitor walks the texts in the order `prompt_text` returned them,
        // so each is redacted with its own findings — a span found in one
        // message is an offset into that message only.
        let mut replaced: Vec<String> = Vec::new();
        let mut index = 0;
        let rewritten = rewrite_prompt(&body, self.provider.as_ref(), &mut |text| {
            let own = findings.get(index).map_or(&[][..], Vec::as_slice);
            index += 1;
            let out = redact(text, own, &self.redaction)?;
            replaced.extend(out.rules);
            Some(out.text)
        });
        match rewritten {
            Some(new_body) if !replaced.is_empty() => {
                log_redaction(&mut replaced);
                Screened::Send(Bytes::from(new_body))
            }
            // Findings existed but none could be replaced — an off-boundary
            // span, or a shape that would not rebuild. Fail closed rather than
            // forward a body that still carries what was found.
            _ => Screened::Refuse(UNREDACTABLE.into()),
        }
    }

    /// The same decision over texts a caller already extracted.
    pub fn screen_texts(&self, texts: &[String]) -> TextScreen {
        if self.inspectors.is_empty() {
            return TextScreen::Clean;
        }
        let findings: Vec<Vec<Finding>> = texts.iter().map(|t| self.findings(t)).collect();
        if findings.iter().all(Vec::is_empty) {
            return TextScreen::Clean;
        }
        if let Some(reason) = self.blocking(findings.iter().flatten()) {
            return TextScreen::Refuse(reason);
        }
        let mut replaced: Vec<String> = Vec::new();
        let mut out = Vec::with_capacity(texts.len());
        for (text, own) in texts.iter().zip(&findings) {
            if own.is_empty() {
                out.push(text.clone());
                continue;
            }
            let Some(r) = redact(text, own, &self.redaction) else {
                return TextScreen::Refuse(UNREDACTABLE.into());
            };
            replaced.extend(r.rules);
            out.push(r.text);
        }
        log_redaction(&mut replaced);
        TextScreen::Rewritten(out)
    }

    /// Judge tool calls a model proposed. `Err` carries the refusal.
    pub async fn judge_tool_calls(&self, calls: &[ToolCall]) -> Result<(), String> {
        if calls.is_empty() {
            return Ok(());
        }
        let result = inspect(&self.guard, calls).await;
        match &result.overall {
            Verdict::Deny(reason) => {
                let denied: Vec<&str> = result.denied_calls().collect();
                Err(format!(
                    "pasu-proxy blocked tool call(s) {denied:?}: {reason}"
                ))
            }
            _ => Ok(()),
        }
    }

    /// Judge an upstream response on `route`. `Err` carries the refusal.
    ///
    /// Only a successful completion is parsed: a provider error cannot carry a
    /// tool call, and turning a 429 into a 403 would break every client's
    /// retry. A completion that is compressed, or does not read as this format,
    /// is refused — what was not read was not checked.
    pub async fn judge_response(&self, route: Route, resp: ResponseView<'_>) -> Result<(), String> {
        if route != Route::Completion || !(200..300).contains(&resp.status) {
            return Ok(());
        }
        if !resp.identity_encoded {
            return Err(
                "pasu-proxy: the provider compressed its response, so it could not be read".into(),
            );
        }
        let calls = if is_event_stream(resp.content_type) {
            self.provider.tool_calls_streaming(resp.body)
        } else {
            self.provider.tool_calls(resp.body)
        };
        let Some(calls) = calls else {
            return Err(format!(
                "pasu-proxy: the response is not a {} response it can read, so its tool calls \
                 could not be checked",
                self.provider.name()
            ));
        };
        self.judge_tool_calls(&calls).await
    }

    fn findings(&self, text: &str) -> Vec<Finding> {
        self.inspectors
            .iter()
            .flat_map(|i| i.inspect(text))
            .collect()
    }

    /// The refusal for the first finding the policy blocks, if any. The
    /// inspector and rule ids, never the value: a block that quotes what it
    /// caught is the leak it was meant to stop.
    fn blocking<'f>(&self, mut findings: impl Iterator<Item = &'f Finding>) -> Option<String> {
        let f = findings.find(|f| self.redaction.action_for(&f.rule) == Action::Block)?;
        Some(format!(
            "pasu-proxy blocked this request: its prompt matched {}/{} and was not sent",
            f.inspector, f.rule
        ))
    }
}

const UNREDACTABLE: &str = "pasu-proxy blocked this request: its prompt matched a rule that \
                            could not be redacted safely, so it was not sent";

/// An altered prompt that says nothing is a debugging trap: the model answers
/// about text the operator never wrote. Counts and rule ids only — saying which
/// values were removed would undo the removal.
fn log_redaction(replaced: &mut Vec<String>) {
    replaced.sort();
    replaced.dedup();
    eprintln!(
        "pasu-proxy: redacted {} rule(s) from this request ({})",
        replaced.len(),
        replaced.join(", ")
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parse::Provider;
    use pasu_core::DenyAll;

    /// Finds every `SECRET`.
    struct Secret;
    impl Inspector for Secret {
        fn name(&self) -> &str {
            "test"
        }
        fn inspect(&self, text: &str) -> Vec<Finding> {
            text.match_indices("SECRET")
                .map(|(i, m)| Finding {
                    inspector: "test".into(),
                    rule: "secret".into(),
                    span: i..i + m.len(),
                })
                .collect()
        }
    }

    struct AllowAll;
    impl RuleEngine for AllowAll {
        fn evaluate(&self, _event: &pasu_core::Event) -> Verdict {
            Verdict::Allow
        }
    }

    fn judge() -> Judge<AllowAll, DenyAll> {
        Judge {
            guard: Guard::new(AllowAll, "test"),
            provider: Arc::new(Provider::OpenAi),
            inspectors: vec![Arc::new(Secret)],
            redaction: RedactionPolicy::redact_everything(),
            options: ProxyOptions::default(),
        }
    }

    /// A span is an offset into the text it was found in. Applying every
    /// message's findings to every message overwrote bytes of a message that
    /// held nothing.
    #[test]
    fn a_finding_in_one_text_does_not_touch_another() {
        let texts = vec!["id SECRET".to_string(), "hi abcdefgh".to_string()];
        let TextScreen::Rewritten(out) = judge().screen_texts(&texts) else {
            panic!("expected a rewrite");
        };
        assert_eq!(out[0], "id [REDACTED:secret]");
        assert_eq!(out[1], "hi abcdefgh", "an innocent message was altered");
    }

    #[test]
    fn a_finding_in_one_message_does_not_touch_another_in_a_body() {
        let body = serde_json::json!({"messages": [
            {"role": "user", "content": "id SECRET"},
            {"role": "user", "content": "hi abcdefgh"}
        ]});
        let Screened::Send(out) = judge().screen_request(Bytes::from(body.to_string())) else {
            panic!("expected a rewrite");
        };
        let out: serde_json::Value = serde_json::from_slice(&out).unwrap();
        assert_eq!(out["messages"][0]["content"], "id [REDACTED:secret]");
        assert_eq!(out["messages"][1]["content"], "hi abcdefgh");
    }

    #[test]
    fn clean_texts_are_left_alone() {
        assert_eq!(judge().screen_texts(&["hello".into()]), TextScreen::Clean);
    }
}
