//! The Envoy ext_proc front-end under `STREAMED` and `FULL_DUPLEX_STREAMED`
//! body modes, against the shipped ruleset.
//!
//! Each test drives a [`Session`] the way Envoy does and applies every answer
//! the way Envoy would — a cleared piece forwards nothing, a replaced one
//! forwards the replacement, a full-duplex piece forwards only what the server
//! sends back — so the assertions are about bytes that would reach the provider
//! or the client, not about the shape of the protobufs.
#![cfg(feature = "ext-proc")]

use std::collections::VecDeque;
use std::sync::Arc;

use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::processing_mode::BodySendMode;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    body_mutation::Mutation, external_processor_client::ExternalProcessorClient,
    processing_request::Request as Phase, processing_response::Response as Reply, BodyResponse,
    HttpBody, HttpHeaders, HttpTrailers, ProcessingRequest, ProcessingResponse,
    ProtocolConfiguration,
};
use pasu_core::Guard;
use pasu_proxy::ext_proc::{ExtProc, ExternalProcessorServer, Session};
use pasu_proxy::{Judge, Provider};
use pasu_rules::RulesetEngine;
use serde_json::json;

const PRODUCTION_RULES: &str = include_str!("../../../deploy/rules.yaml");
const RRN: &str = "900101-1234567";

type TestJudge = Judge<RulesetEngine, pasu_core::DenyAll>;

fn judge(inspect: bool, redact: bool) -> TestJudge {
    Judge {
        guard: Guard::new(
            RulesetEngine::from_yaml(PRODUCTION_RULES).expect("production ruleset"),
            "envoy-ext-proc",
        ),
        provider: Arc::new(Provider::OpenAi),
        inspectors: if inspect {
            vec![Arc::new(pasu_inspect_pii_kr::PiiKr::builtin())]
        } else {
            Vec::new()
        },
        redaction: if redact {
            pasu_core::redact::Policy::redact_everything()
        } else {
            pasu_core::redact::Policy::block_everything()
        },
        options: Default::default(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Streamed,
    FullDuplex,
}

impl Mode {
    fn wire(self) -> i32 {
        match self {
            Mode::Streamed => BodySendMode::Streamed as i32,
            Mode::FullDuplex => BodySendMode::FullDuplexStreamed as i32,
        }
    }
}

const MODES: [Mode; 2] = [Mode::Streamed, Mode::FullDuplex];

fn headers(pairs: &[(&str, &str)], end_of_stream: bool) -> HttpHeaders {
    HttpHeaders {
        headers: Some(HeaderMap {
            headers: pairs
                .iter()
                .map(|(k, v)| HeaderValue {
                    key: (*k).into(),
                    raw_value: v.as_bytes().to_vec(),
                    ..HeaderValue::default()
                })
                .collect(),
        }),
        end_of_stream,
        ..HttpHeaders::default()
    }
}

fn msg(phase: Phase) -> ProcessingRequest {
    ProcessingRequest {
        request: Some(phase),
        ..ProcessingRequest::default()
    }
}

fn request_headers_with(path: &str, request: i32, response: i32) -> ProcessingRequest {
    let mut m = msg(Phase::RequestHeaders(headers(
        &[(":method", "POST"), (":path", path)],
        false,
    )));
    m.protocol_config = Some(ProtocolConfiguration {
        request_body_mode: request,
        response_body_mode: response,
        send_body_without_waiting_for_header_response: false,
    });
    m
}

fn chat_headers(mode: Mode) -> ProcessingRequest {
    request_headers_with("/v1/chat/completions", mode.wire(), mode.wire())
}

/// A body sent as `pieces`, the last one ending the stream.
fn pieces(phase: fn(HttpBody) -> Phase, body: &[u8], cuts: &[usize]) -> Vec<ProcessingRequest> {
    let mut bounds = vec![0];
    bounds.extend_from_slice(cuts);
    bounds.push(body.len());
    bounds
        .windows(2)
        .enumerate()
        .map(|(i, w)| {
            msg(phase(HttpBody {
                body: body[w[0]..w[1]].to_vec(),
                end_of_stream: i == cuts.len(),
                ..HttpBody::default()
            }))
        })
        .collect()
}

fn response_headers(status: &str, content_type: &str) -> ProcessingRequest {
    msg(Phase::ResponseHeaders(headers(
        &[(":status", status), ("content-type", content_type)],
        false,
    )))
}

fn prompt(content: &str) -> Vec<u8> {
    json!({"model": "m", "messages": [{"role": "user", "content": content}]})
        .to_string()
        .into_bytes()
}

fn sse(events: &[serde_json::Value]) -> Vec<u8> {
    let mut out = String::new();
    for e in events {
        out.push_str(&format!("data: {e}\n\n"));
    }
    out.push_str("data: [DONE]\n\n");
    out.into_bytes()
}

fn streamed_tool_call(name: &str) -> Vec<u8> {
    sse(&[
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0, "id": "c1",
            "type": "function", "function": {"name": name, "arguments": ""}}]}}]}),
        json!({"choices": [{"index": 0, "delta": {"tool_calls": [{"index": 0,
            "function": {"arguments": "{\"cmd\":\"rm -rf /\"}"}}]}}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "tool_calls"}]}),
    ])
}

fn streamed_text() -> Vec<u8> {
    sse(&[
        json!({"choices": [{"index": 0, "delta": {"content": "Hello"}}]}),
        json!({"choices": [{"index": 0, "delta": {"content": ", world"}}]}),
        json!({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}]}),
    ])
}

/// Thirds of `body`, cut wherever that falls — mid-name, mid-JSON.
fn thirds(body: &[u8]) -> Vec<usize> {
    vec![body.len() / 3, 2 * body.len() / 3]
}

/// What Envoy would have let through, given pasu's answers.
#[derive(Debug, Default)]
struct Wire {
    refused: Option<i32>,
    upstream: Vec<u8>,
    downstream: Vec<u8>,
    /// The response headers were answered, so Envoy sent them to the client.
    headers_downstream: bool,
    /// Full duplex: the last body answer said `end_of_stream`.
    upstream_ended: bool,
    downstream_ended: bool,
    /// Answers Envoy would reject: a piece answered twice, a buffered-style
    /// answer in full duplex, a streamed one outside it.
    protocol_errors: Vec<String>,
    /// STREAMED pieces never answered.
    unanswered: usize,
}

async fn drive(judge: &TestJudge, mode: Mode, phases: Vec<ProcessingRequest>) -> Wire {
    let mut session = Session::default();
    let mut wire = Wire::default();
    let mut request_pieces: VecDeque<Vec<u8>> = VecDeque::new();
    let mut response_pieces: VecDeque<Vec<u8>> = VecDeque::new();
    for phase in phases {
        match &phase.request {
            Some(Phase::RequestBody(b)) => request_pieces.push_back(b.body.clone()),
            Some(Phase::ResponseBody(b)) => response_pieces.push_back(b.body.clone()),
            _ => {}
        }
        let step = session.handle(judge, phase).await;
        if let Some(code) = step.refused_with() {
            wire.refused = Some(code);
            break;
        }
        for r in step.into_responses() {
            apply(
                &mut wire,
                mode,
                r,
                &mut request_pieces,
                &mut response_pieces,
            );
        }
    }
    if mode == Mode::Streamed && wire.refused.is_none() {
        wire.unanswered = request_pieces.len() + response_pieces.len();
    }
    wire
}

fn apply(
    wire: &mut Wire,
    mode: Mode,
    r: ProcessingResponse,
    request_pieces: &mut VecDeque<Vec<u8>>,
    response_pieces: &mut VecDeque<Vec<u8>>,
) {
    match r.response {
        Some(Reply::ResponseHeaders(_)) => wire.headers_downstream = true,
        Some(Reply::RequestBody(b)) => {
            let piece = request_pieces.pop_front();
            let ended = deliver(
                mode,
                piece,
                b,
                &mut wire.upstream,
                &mut wire.protocol_errors,
            );
            wire.upstream_ended |= ended;
        }
        Some(Reply::ResponseBody(b)) => {
            if !wire.headers_downstream {
                wire.protocol_errors
                    .push("a response body answered before its headers".into());
            }
            let piece = response_pieces.pop_front();
            let ended = deliver(
                mode,
                piece,
                b,
                &mut wire.downstream,
                &mut wire.protocol_errors,
            );
            wire.downstream_ended |= ended;
        }
        _ => {}
    }
}

/// Apply one body answer; whether it ended the stream (full duplex).
fn deliver(
    mode: Mode,
    piece: Option<Vec<u8>>,
    b: BodyResponse,
    out: &mut Vec<u8>,
    errors: &mut Vec<String>,
) -> bool {
    let mutation = b
        .response
        .and_then(|c| c.body_mutation)
        .and_then(|m| m.mutation);
    match (mode, mutation) {
        (Mode::FullDuplex, Some(Mutation::StreamedResponse(s))) => {
            out.extend(s.body);
            return s.end_of_stream;
        }
        (Mode::FullDuplex, other) => {
            errors.push(format!(
                "full duplex answered without a streamed body: {other:?}"
            ));
            return false;
        }
        (Mode::Streamed, _) if piece.is_none() => {
            errors.push("a STREAMED answer for a piece that was never sent".into());
        }
        (Mode::Streamed, None | Some(Mutation::ClearBody(false))) => {
            out.extend(piece.unwrap_or_default());
        }
        (Mode::Streamed, Some(Mutation::ClearBody(true))) => {}
        (Mode::Streamed, Some(Mutation::Body(body))) => out.extend(body),
        (Mode::Streamed, Some(Mutation::StreamedResponse(_))) => {
            errors.push("a streamed body answer outside full duplex".into());
        }
    }
    false
}

fn completion(
    mode: Mode,
    request: &[u8],
    request_cuts: &[usize],
    status: &str,
    content_type: &str,
    response: &[u8],
    response_cuts: &[usize],
) -> Vec<ProcessingRequest> {
    let mut phases = vec![chat_headers(mode)];
    phases.extend(pieces(Phase::RequestBody, request, request_cuts));
    phases.push(response_headers(status, content_type));
    phases.extend(pieces(Phase::ResponseBody, response, response_cuts));
    phases
}

fn assert_clean(wire: &Wire) {
    assert!(
        wire.protocol_errors.is_empty(),
        "answers Envoy would reject: {:?}",
        wire.protocol_errors
    );
    assert_eq!(wire.unanswered, 0, "STREAMED pieces left unanswered");
}

// --- tool calls in the response -------------------------------------------

/// TP. A denied call cut into thirds — the name itself split — is refused, and
/// not one byte of it reaches the client.
#[tokio::test]
async fn a_denied_tool_call_in_pieces_is_refused_and_no_piece_is_forwarded() {
    let body = streamed_tool_call("shell");
    for mode in MODES {
        let wire = drive(
            &judge(false, false),
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "text/event-stream",
                &body,
                &thirds(&body),
            ),
        )
        .await;
        assert_eq!(wire.refused, Some(403), "{mode:?}");
        assert!(
            wire.downstream.is_empty(),
            "{mode:?}: {} byte(s) of a denied tool call reached the client",
            wire.downstream.len()
        );
        assert!(
            wire.protocol_errors.is_empty(),
            "{mode:?}: {:?}",
            wire.protocol_errors
        );
    }
}

/// Under full duplex pasu withholds the response headers too, so the refusal
/// is a clean local reply. Under STREAMED they have gone — the refusal ends
/// the stream, and the client has headers but no body.
#[tokio::test]
async fn only_full_duplex_can_refuse_before_the_response_headers_leave() {
    let body = streamed_tool_call("shell");
    let run = |mode| {
        let body = body.clone();
        async move {
            drive(
                &judge(false, false),
                mode,
                completion(
                    mode,
                    &prompt("hi"),
                    &[],
                    "200",
                    "text/event-stream",
                    &body,
                    &thirds(&body),
                ),
            )
            .await
        }
    };
    assert!(!run(Mode::FullDuplex).await.headers_downstream);
    assert!(run(Mode::Streamed).await.headers_downstream);
}

/// TN. A text completion in pieces arrives byte-identical, once.
#[tokio::test]
async fn a_text_completion_in_pieces_is_delivered_byte_identical() {
    let body = streamed_text();
    for mode in MODES {
        let wire = drive(
            &judge(false, false),
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "text/event-stream",
                &body,
                &thirds(&body),
            ),
        )
        .await;
        assert_eq!(wire.refused, None, "{mode:?}: false positive");
        assert_clean(&wire);
        assert_eq!(
            wire.downstream, body,
            "{mode:?}: the completion was altered"
        );
        if mode == Mode::FullDuplex {
            assert!(
                wire.downstream_ended,
                "full duplex never ended the response"
            );
        }
    }
}

/// TN, non-streamed JSON cut mid-document.
#[tokio::test]
async fn a_json_completion_in_pieces_is_delivered_byte_identical() {
    let body = json!({"choices": [{"message": {"content": "hello there"}}]})
        .to_string()
        .into_bytes();
    for mode in MODES {
        let wire = drive(
            &judge(false, false),
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "application/json",
                &body,
                &thirds(&body),
            ),
        )
        .await;
        assert_eq!(wire.refused, None, "{mode:?}");
        assert_clean(&wire);
        assert_eq!(wire.downstream, body, "{mode:?}");
    }
}

/// A body longer than one full-duplex answer should carry goes back in
/// several, and only the last ends the stream.
#[tokio::test]
async fn a_large_full_duplex_body_goes_back_in_bounded_pieces() {
    let long = "x".repeat(200 * 1024);
    let body = json!({"choices": [{"message": {"content": long}}]})
        .to_string()
        .into_bytes();
    let mut session = Session::default();
    let j = judge(false, false);
    let mut phases = vec![chat_headers(Mode::FullDuplex)];
    phases.extend(pieces(Phase::RequestBody, &prompt("hi"), &[]));
    phases.push(response_headers("200", "application/json"));
    phases.extend(pieces(Phase::ResponseBody, &body, &[1000, 100_000]));
    let mut last = Vec::new();
    for phase in phases {
        last = session.handle(&j, phase).await.into_responses();
    }
    let bodies: Vec<(usize, bool)> = last
        .iter()
        .filter_map(|r| match &r.response {
            Some(Reply::ResponseBody(b)) => match b
                .response
                .as_ref()
                .and_then(|c| c.body_mutation.as_ref())
                .and_then(|m| m.mutation.as_ref())
            {
                Some(Mutation::StreamedResponse(s)) => Some((s.body.len(), s.end_of_stream)),
                _ => None,
            },
            _ => None,
        })
        .collect();
    assert!(bodies.len() > 1, "one answer of {} bytes", body.len());
    assert!(bodies.iter().all(|(len, _)| *len <= 64 * 1024));
    let ends: Vec<bool> = bodies.iter().map(|(_, e)| *e).collect();
    assert_eq!(ends.iter().filter(|e| **e).count(), 1);
    assert_eq!(ends.last(), Some(&true));
    assert_eq!(bodies.iter().map(|(l, _)| l).sum::<usize>(), body.len());
}

// --- the prompt in the request ----------------------------------------------

/// TP. A prompt whose RRN is split across pieces is refused, and nothing of
/// it — not the first half of the number, not the JSON before it — reaches
/// the provider.
#[tokio::test]
async fn a_prompt_with_pii_split_across_pieces_is_refused_and_nothing_is_sent() {
    let body = prompt(&format!("my id {RRN} ok"));
    let at = body
        .windows(3)
        .position(|w| w == b"-12")
        .expect("rrn in body")
        + 2;
    for mode in MODES {
        let mut phases = vec![chat_headers(mode)];
        phases.extend(pieces(Phase::RequestBody, &body, &[10, at]));
        let wire = drive(&judge(true, false), mode, phases).await;
        assert_eq!(wire.refused, Some(403), "{mode:?}");
        assert!(
            wire.upstream.is_empty(),
            "{mode:?}: {:?} reached the provider",
            String::from_utf8_lossy(&wire.upstream)
        );
    }
}

/// TN for the inspector: a clean prompt in pieces reaches the provider whole
/// and unchanged.
#[tokio::test]
async fn a_clean_prompt_in_pieces_reaches_the_provider_unchanged() {
    let body = prompt("an ordinary question about 12 apples");
    for mode in MODES {
        let mut phases = vec![chat_headers(mode)];
        phases.extend(pieces(Phase::RequestBody, &body, &thirds(&body)));
        let wire = drive(&judge(true, false), mode, phases).await;
        assert_eq!(wire.refused, None, "{mode:?}: false positive");
        assert_clean(&wire);
        assert_eq!(wire.upstream, body, "{mode:?}");
    }
}

/// With redaction on, the split prompt is sent — redacted, whole, once.
#[tokio::test]
async fn a_redacted_prompt_in_pieces_reaches_the_provider_redacted() {
    let body = prompt(&format!("my id {RRN} ok"));
    for mode in MODES {
        let mut phases = vec![chat_headers(mode)];
        phases.extend(pieces(Phase::RequestBody, &body, &thirds(&body)));
        let wire = drive(&judge(true, true), mode, phases).await;
        assert_eq!(wire.refused, None, "{mode:?}");
        assert_clean(&wire);
        let sent = String::from_utf8(wire.upstream).expect("utf-8");
        assert!(!sent.contains(RRN), "{mode:?}: {sent}");
        assert!(
            !sent.contains("900101"),
            "{mode:?}: a fragment survived: {sent}"
        );
        let parsed: serde_json::Value = serde_json::from_str(&sent).expect("a whole JSON body");
        assert!(parsed["messages"][0]["content"]
            .as_str()
            .is_some_and(|c| c.contains("[REDACTED")));
    }
}

/// Without an inspector the prompt is not judged, so it is not held either.
#[tokio::test]
async fn an_unscreened_prompt_streams_through_piece_by_piece() {
    let body = prompt("hi there");
    for mode in MODES {
        let mut session = Session::default();
        let j = judge(false, false);
        session.handle(&j, chat_headers(mode)).await;
        let first = pieces(Phase::RequestBody, &body, &[5]).remove(0);
        let answers = session.handle(&j, first).await.into_responses();
        assert_eq!(answers.len(), 1, "{mode:?}: the first piece was held");
    }
}

// --- limits -------------------------------------------------------------------

#[tokio::test]
async fn a_held_response_over_the_limit_is_refused() {
    let body = streamed_text();
    for mode in MODES {
        let mut j = judge(false, false);
        j.options.max_response_bytes = body.len() / 2;
        let wire = drive(
            &j,
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "text/event-stream",
                &body,
                &thirds(&body),
            ),
        )
        .await;
        assert_eq!(wire.refused, Some(403), "{mode:?}");
        assert!(wire.downstream.is_empty(), "{mode:?}");
    }
}

#[tokio::test]
async fn a_held_request_over_the_limit_is_refused() {
    let body = prompt(&"a".repeat(300));
    for mode in MODES {
        let mut j = judge(true, false);
        j.options.max_request_bytes = 200;
        let mut phases = vec![chat_headers(mode)];
        phases.extend(pieces(Phase::RequestBody, &body, &[100, 190, 250]));
        let wire = drive(&j, mode, phases).await;
        assert_eq!(wire.refused, Some(413), "{mode:?}");
        assert!(wire.upstream.is_empty(), "{mode:?}");
    }
}

/// The limit is on the whole body held, not on any one piece.
#[tokio::test]
async fn pieces_each_under_the_limit_but_together_over_it_are_refused() {
    let body = streamed_text();
    let cuts: Vec<usize> = (1..10).map(|i| i * body.len() / 10).collect();
    for mode in MODES {
        let mut j = judge(false, false);
        j.options.max_response_bytes = body.len() - 1;
        let wire = drive(
            &j,
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "text/event-stream",
                &body,
                &cuts,
            ),
        )
        .await;
        assert_eq!(wire.refused, Some(403), "{mode:?}");
    }
}

// --- what is not judged streams through ---------------------------------------

#[tokio::test]
async fn a_passthrough_path_streams_through_untouched() {
    let body = b"data: {\"anything\": 1}\n\ndata: {\"more\": 2}\n\n".to_vec();
    for mode in MODES {
        let mut j = judge(true, false);
        j.options.passthrough_paths = vec!["/v1/models".into()];
        let mut phases = vec![request_headers_with("/v1/models", mode.wire(), mode.wire())];
        phases.extend(pieces(Phase::RequestBody, &prompt(RRN), &[4]));
        phases.push(response_headers("200", "text/event-stream"));
        phases.extend(pieces(Phase::ResponseBody, &body, &[7, 20]));
        let wire = drive(&j, mode, phases).await;
        assert_eq!(wire.refused, None, "{mode:?}");
        assert_clean(&wire);
        assert_eq!(wire.upstream, prompt(RRN), "{mode:?}");
        assert_eq!(wire.downstream, body, "{mode:?}");
    }
}

/// A provider error is not parsed, so it is not held: each piece goes on as
/// it comes.
#[tokio::test]
async fn a_provider_error_streams_through_piece_by_piece() {
    let body = br#"{"error": {"message": "rate limited", "type": "rate_limit"}}"#.to_vec();
    for mode in MODES {
        let j = judge(false, false);
        let mut session = Session::default();
        for phase in [
            chat_headers(mode),
            pieces(Phase::RequestBody, &prompt("hi"), &[]).remove(0),
            response_headers("429", "application/json"),
        ] {
            session.handle(&j, phase).await;
        }
        let first = pieces(Phase::ResponseBody, &body, &[9]).remove(0);
        let answers = session.handle(&j, first).await.into_responses();
        assert_eq!(answers.len(), 1, "{mode:?}: an error body was held");
        let wire = drive(
            &j,
            mode,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "429",
                "application/json",
                &body,
                &[9, 30],
            ),
        )
        .await;
        assert_eq!(wire.refused, None, "{mode:?}");
        assert_clean(&wire);
        assert_eq!(wire.downstream, body, "{mode:?}");
    }
}

/// A `RequestOnly` route's response is never judged.
#[tokio::test]
async fn a_request_only_response_streams_through() {
    let body = b"{\"input_tokens\": 5}".to_vec();
    for mode in MODES {
        let mut phases = vec![request_headers_with(
            "/v1/messages/count_tokens",
            mode.wire(),
            mode.wire(),
        )];
        phases.extend(pieces(Phase::RequestBody, &prompt("hi"), &[]));
        phases.push(response_headers("200", "application/json"));
        phases.extend(pieces(Phase::ResponseBody, &body, &[3, 10]));
        let mut j = judge(false, false);
        j.provider = Arc::new(Provider::Anthropic);
        let wire = drive(&j, mode, phases).await;
        assert_eq!(wire.refused, None, "{mode:?}");
        assert_clean(&wire);
        assert_eq!(wire.downstream, body, "{mode:?}");
    }
}

// --- trailers and settings ------------------------------------------------------

/// A body that ends in trailers ended without `end_of_stream` on a piece, so
/// what was held was never judged. It must not be released unjudged.
#[tokio::test]
async fn a_held_body_ending_in_trailers_is_refused() {
    let body = streamed_tool_call("shell");
    for mode in MODES {
        let mut phases = vec![chat_headers(mode)];
        phases.extend(pieces(Phase::RequestBody, &prompt("hi"), &[]));
        phases.push(response_headers("200", "text/event-stream"));
        let mut open = pieces(Phase::ResponseBody, &body, &[]);
        if let Some(Phase::ResponseBody(b)) = &mut open[0].request {
            b.end_of_stream = false;
        }
        phases.extend(open);
        phases.push(msg(Phase::ResponseTrailers(HttpTrailers::default())));
        let wire = drive(&judge(false, false), mode, phases).await;
        assert_eq!(wire.refused, Some(500), "{mode:?}");
        assert!(wire.downstream.is_empty(), "{mode:?}");
    }
}

#[tokio::test]
async fn streamed_and_full_duplex_filters_are_accepted() {
    for mode in MODES {
        let mut session = Session::default();
        let step = session
            .handle(&judge(true, false), chat_headers(mode))
            .await;
        assert_eq!(step.refused_with(), None, "{mode:?}");
        let r = step.into_responses().remove(0);
        // Full duplex does not allow a mode override; STREAMED is what the
        // operator chose. Either way pasu holds the body itself.
        assert!(r.mode_override.is_none(), "{mode:?}");
    }
}

/// `BUFFERED_PARTIAL` shows only the first part of a body over the limit: a
/// tool call past it would never be judged.
#[tokio::test]
async fn a_partial_body_mode_is_refused_for_what_pasu_judges() {
    let partial = BodySendMode::BufferedPartial as i32;
    let buffered = BodySendMode::Buffered as i32;
    for (request, response, inspect, expected) in [
        (buffered, partial, false, Some(500)),
        (partial, buffered, true, Some(500)),
        // The request is not judged without an inspector.
        (partial, buffered, false, None),
        (
            BodySendMode::None as i32,
            BodySendMode::Streamed as i32,
            false,
            None,
        ),
        (buffered, BodySendMode::Grpc as i32, false, Some(500)),
    ] {
        let mut session = Session::default();
        let step = session
            .handle(
                &judge(inspect, false),
                request_headers_with("/v1/chat/completions", request, response),
            )
            .await;
        assert_eq!(
            step.refused_with(),
            expected,
            "request {request} response {response} inspect {inspect}"
        );
    }
}

// --- over real gRPC -----------------------------------------------------------

async fn serve(j: TestJudge) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = ExternalProcessorServer::new(ExtProc::new(Arc::new(j)));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });
    format!("http://{addr}")
}

async fn exchange(url: &str, phases: Vec<ProcessingRequest>) -> Vec<ProcessingResponse> {
    let mut client = ExternalProcessorClient::connect(url.to_string())
        .await
        .expect("connect");
    let mut replies = client
        .process(tokio_stream::iter(phases))
        .await
        .expect("process")
        .into_inner();
    let mut out = Vec::new();
    while let Some(r) = replies.message().await.expect("reply") {
        out.push(r);
    }
    out
}

/// The server loop sends every answer of a release, in order, and nothing for
/// a held piece.
#[tokio::test]
async fn over_grpc_full_duplex_holds_then_releases_in_order() {
    let url = serve(judge(false, false)).await;
    let body = streamed_text();
    let replies = exchange(
        &url,
        completion(
            Mode::FullDuplex,
            &prompt("hi"),
            &[],
            "200",
            "text/event-stream",
            &body,
            &thirds(&body),
        ),
    )
    .await;
    let kinds: Vec<&str> = replies
        .iter()
        .map(|r| match &r.response {
            Some(Reply::RequestHeaders(_)) => "request-headers",
            Some(Reply::RequestBody(_)) => "request-body",
            Some(Reply::ResponseHeaders(_)) => "response-headers",
            Some(Reply::ResponseBody(_)) => "response-body",
            _ => "other",
        })
        .collect();
    assert_eq!(
        kinds,
        [
            "request-headers",
            "request-body",
            "response-headers",
            "response-body"
        ],
        "three response pieces, one release after the last"
    );
    let Some(Reply::ResponseBody(b)) = &replies[3].response else {
        unreachable!()
    };
    let Some(Mutation::StreamedResponse(s)) = b
        .response
        .as_ref()
        .and_then(|c| c.body_mutation.as_ref())
        .and_then(|m| m.mutation.as_ref())
    else {
        panic!("not a streamed body");
    };
    assert_eq!(s.body, body);
    assert!(s.end_of_stream);
}

#[tokio::test]
async fn over_grpc_a_denied_streamed_tool_call_ends_with_a_403_and_nothing_else() {
    let url = serve(judge(false, false)).await;
    let body = streamed_tool_call("shell");
    for mode in MODES {
        let replies = exchange(
            &url,
            completion(
                mode,
                &prompt("hi"),
                &[],
                "200",
                "text/event-stream",
                &body,
                &thirds(&body),
            ),
        )
        .await;
        let Some(Reply::ImmediateResponse(i)) = replies.last().and_then(|r| r.response.clone())
        else {
            panic!("{mode:?}: the stream did not end with a refusal");
        };
        assert_eq!(i.status.unwrap().code, 403);
        let mut wire = Wire::default();
        let mut none = VecDeque::from(vec![Vec::new(); 8]);
        let mut pieces_seen: VecDeque<Vec<u8>> = pieces(Phase::ResponseBody, &body, &thirds(&body))
            .into_iter()
            .filter_map(|p| match p.request {
                Some(Phase::ResponseBody(b)) => Some(b.body),
                _ => None,
            })
            .collect();
        for r in replies {
            apply(&mut wire, mode, r, &mut none, &mut pieces_seen);
        }
        assert!(
            wire.downstream.is_empty(),
            "{mode:?}: tool-call bytes were released"
        );
    }
}
