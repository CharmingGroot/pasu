//! The Envoy ext_proc front-end against the shipped ruleset: each phase as Envoy
//! sends it, and one request end to end over real gRPC.
#![cfg(feature = "ext-proc")]

use std::sync::Arc;

use envoy_types::pb::envoy::config::core::v3::{HeaderMap, HeaderValue};
use envoy_types::pb::envoy::extensions::filters::http::ext_proc::v3::processing_mode::BodySendMode;
use envoy_types::pb::envoy::service::ext_proc::v3::{
    body_mutation::Mutation, external_processor_client::ExternalProcessorClient,
    processing_request::Request as Phase, processing_response::Response as Reply, HttpBody,
    HttpHeaders, ProcessingRequest, ProtocolConfiguration,
};
use pasu_core::Guard;
use pasu_proxy::ext_proc::{ExtProc, ExternalProcessorServer, Session, Step};
use pasu_proxy::{Judge, Provider};
use pasu_rules::RulesetEngine;
use serde_json::json;

const PRODUCTION_RULES: &str = include_str!("../../../deploy/rules.yaml");
const RRN: &str = "900101-1234567";

fn judge(inspect: bool, redact: bool) -> Judge<RulesetEngine, pasu_core::DenyAll> {
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

/// Header values as current Envoy sends them: in `raw_value`.
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

fn buffered_config() -> Option<ProtocolConfiguration> {
    Some(ProtocolConfiguration {
        request_body_mode: BodySendMode::Buffered as i32,
        response_body_mode: BodySendMode::Buffered as i32,
        send_body_without_waiting_for_header_response: false,
    })
}

fn chat_headers() -> ProcessingRequest {
    let mut m = msg(Phase::RequestHeaders(headers(
        &[(":method", "POST"), (":path", "/v1/chat/completions?x=1")],
        false,
    )));
    m.protocol_config = buffered_config();
    m
}

fn body(phase: fn(HttpBody) -> Phase, bytes: Vec<u8>, end_of_stream: bool) -> ProcessingRequest {
    msg(phase(HttpBody {
        body: bytes,
        end_of_stream,
        ..HttpBody::default()
    }))
}

fn response_headers(status: &str, extra: &[(&str, &str)]) -> ProcessingRequest {
    let mut pairs = vec![(":status", status), ("content-type", "application/json")];
    pairs.extend_from_slice(extra);
    msg(Phase::ResponseHeaders(headers(&pairs, false)))
}

fn tool_call_body(name: &str) -> Vec<u8> {
    json!({"choices": [{"message": {"tool_calls": [
        {"id": "c1", "type": "function", "function": {"name": name, "arguments": "{}"}}]}}]})
    .to_string()
    .into_bytes()
}

fn text_body() -> Vec<u8> {
    json!({"choices": [{"message": {"content": "hello"}}]})
        .to_string()
        .into_bytes()
}

/// Run a request's phases through one session; the refusal status, if any.
async fn run(
    judge: &Judge<RulesetEngine, pasu_core::DenyAll>,
    phases: Vec<ProcessingRequest>,
) -> Option<i32> {
    let mut session = Session::default();
    for phase in phases {
        let step = session.handle(judge, phase).await;
        if let Some(code) = step.refused_with() {
            return Some(code);
        }
    }
    None
}

fn prompt(content: &str) -> Vec<u8> {
    json!({"model": "m", "messages": [{"role": "user", "content": content}]})
        .to_string()
        .into_bytes()
}

#[tokio::test]
async fn a_denied_tool_call_is_refused_before_the_client_sees_it() {
    let code = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt("hi"), true),
            response_headers("200", &[]),
            body(Phase::ResponseBody, tool_call_body("shell"), true),
        ],
    )
    .await;
    assert_eq!(code, Some(403));
}

#[tokio::test]
async fn a_completion_without_tool_calls_passes() {
    let code = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt("hi"), true),
            response_headers("200", &[]),
            body(Phase::ResponseBody, text_body(), true),
        ],
    )
    .await;
    assert_eq!(code, None, "false positive");
}

#[tokio::test]
async fn a_streamed_responses_api_tool_call_is_refused() {
    let mut headers_msg = chat_headers();
    if let Some(Phase::RequestHeaders(h)) = &mut headers_msg.request {
        *h = headers(&[(":method", "POST"), (":path", "/v1/responses")], false);
    }
    let sse = "data: {\"type\":\"response.output_item.added\",\"output_index\":0,\
               \"item\":{\"type\":\"function_call\",\"name\":\"shell\",\"arguments\":\"{}\"}}\n\n";
    let code = run(
        &judge(false, false),
        vec![
            headers_msg,
            body(Phase::RequestBody, b"{\"input\":\"hi\"}".to_vec(), true),
            msg(Phase::ResponseHeaders(headers(
                &[(":status", "200"), ("content-type", "text/event-stream")],
                false,
            ))),
            body(Phase::ResponseBody, sse.as_bytes().to_vec(), true),
        ],
    )
    .await;
    assert_eq!(code, Some(403));
}

#[tokio::test]
async fn an_unknown_endpoint_is_refused_at_the_headers() {
    let mut m = msg(Phase::RequestHeaders(headers(
        &[(":method", "POST"), (":path", "/v1/embeddings")],
        false,
    )));
    m.protocol_config = buffered_config();
    assert_eq!(run(&judge(false, false), vec![m]).await, Some(403));
}

/// Envoy tells the server its body modes. A filter that would never send the
/// completion body is a filter under which no tool call is ever judged.
#[tokio::test]
async fn a_filter_that_would_not_send_the_response_body_is_refused() {
    let mut m = chat_headers();
    m.protocol_config = Some(ProtocolConfiguration {
        request_body_mode: BodySendMode::Buffered as i32,
        response_body_mode: BodySendMode::None as i32,
        send_body_without_waiting_for_header_response: false,
    });
    assert_eq!(run(&judge(false, false), vec![m]).await, Some(500));
}

#[tokio::test]
async fn a_streamed_body_piece_is_refused_not_passed() {
    let code = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt("hi"), true),
            response_headers("200", &[]),
            body(Phase::ResponseBody, b"{\"choices\":".to_vec(), false),
        ],
    )
    .await;
    assert_eq!(code, Some(500));
}

#[tokio::test]
async fn a_compressed_completion_is_refused() {
    let code = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt("hi"), true),
            response_headers("200", &[("content-encoding", "gzip")]),
            body(Phase::ResponseBody, text_body(), true),
        ],
    )
    .await;
    assert_eq!(code, Some(403));
}

#[tokio::test]
async fn a_provider_error_passes_through() {
    let code = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt("hi"), true),
            response_headers("429", &[]),
            body(Phase::ResponseBody, b"{\"error\":{}}".to_vec(), true),
        ],
    )
    .await;
    assert_eq!(code, None);
}

#[tokio::test]
async fn completion_headers_ask_for_identity_and_buffered_bodies() {
    let mut session = Session::default();
    let step = session.handle(&judge(false, false), chat_headers()).await;
    let Step::Continue(r) = step else {
        panic!("headers of a known endpoint were refused");
    };
    let mode = r.mode_override.expect("mode override");
    assert_eq!(mode.response_body_mode, BodySendMode::Buffered as i32);
    let Some(Reply::RequestHeaders(h)) = r.response else {
        panic!("not a headers response");
    };
    let set = &h.response.unwrap().header_mutation.unwrap().set_headers[0];
    let header = set.header.as_ref().unwrap();
    assert_eq!(header.key, "accept-encoding");
    assert_eq!(header.raw_value, b"identity");
}

#[tokio::test]
async fn a_prompt_with_pii_is_refused() {
    let code = run(
        &judge(true, false),
        vec![
            chat_headers(),
            body(Phase::RequestBody, prompt(&format!("id {RRN}")), true),
        ],
    )
    .await;
    assert_eq!(code, Some(403));
}

/// A rewritten body must carry its new length: Envoy checks a buffered body
/// against the content-length it already has.
#[tokio::test]
async fn a_redacted_prompt_is_replaced_with_its_new_length() {
    let j = judge(true, true);
    let mut session = Session::default();
    session.handle(&j, chat_headers()).await;
    let step = session
        .handle(
            &j,
            body(Phase::RequestBody, prompt(&format!("id {RRN}")), true),
        )
        .await;
    let Step::Continue(r) = step else {
        panic!("a redactable prompt was refused");
    };
    let Some(Reply::RequestBody(b)) = r.response else {
        panic!("not a body response");
    };
    let common = b.response.unwrap();
    let Some(Mutation::Body(new)) = common.body_mutation.unwrap().mutation else {
        panic!("no body mutation");
    };
    assert!(!String::from_utf8_lossy(&new).contains(RRN));
    let length = &common.header_mutation.unwrap().set_headers[0];
    let header = length.header.as_ref().unwrap();
    assert_eq!(header.key, "content-length");
    assert_eq!(header.raw_value, new.len().to_string().as_bytes());
}

/// The same refusal, over a real gRPC stream the way Envoy drives it.
#[tokio::test]
async fn over_grpc_a_denied_tool_call_ends_the_stream_with_a_403() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let service = ExternalProcessorServer::new(ExtProc::new(Arc::new(judge(false, false))));
    tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(listener))
            .await
    });

    let mut client = ExternalProcessorClient::connect(format!("http://{addr}"))
        .await
        .expect("connect");
    let outbound = tokio_stream::iter(vec![
        chat_headers(),
        body(Phase::RequestBody, prompt("hi"), true),
        response_headers("200", &[]),
        body(Phase::ResponseBody, tool_call_body("shell"), true),
    ]);
    let mut replies = client
        .process(outbound)
        .await
        .expect("process")
        .into_inner();
    let mut last = None;
    while let Some(r) = replies.message().await.expect("reply") {
        last = r.response;
    }
    let Some(Reply::ImmediateResponse(i)) = last else {
        panic!("the stream did not end with a refusal: {last:?}");
    };
    assert_eq!(i.status.unwrap().code, 403);
    assert!(String::from_utf8_lossy(&i.body).contains("shell"));
}

/// Both wrong settings in one refusal, named the way each data plane spells
/// them: a message that reveals one mistake per round trip is how a guard gets
/// switched off in frustration instead of configured.
#[tokio::test]
async fn a_misconfiguration_names_every_wrong_mode_in_every_spelling() {
    let mut m = chat_headers();
    m.protocol_config = Some(ProtocolConfiguration {
        request_body_mode: BodySendMode::None as i32,
        response_body_mode: BodySendMode::None as i32,
        send_body_without_waiting_for_header_response: false,
    });
    let step = Session::default().handle(&judge(true, false), m).await;
    let Some(Reply::ImmediateResponse(i)) = step.into_responses().pop().and_then(|r| r.response)
    else {
        panic!("not refused");
    };
    let body = String::from_utf8_lossy(&i.body);
    for needle in [
        "response_body_mode",
        "request_body_mode",
        "processingMode",
        "responseBodyMode",
    ] {
        assert!(body.contains(needle), "{needle} missing from {body}");
    }
}

/// A misconfigured data plane is not a policy decision: a different error
/// type, so an alert on `pasu_policy_block` neither fires on it nor hides it.
#[tokio::test]
async fn a_misconfiguration_is_not_reported_as_a_policy_block() {
    let mut m = chat_headers();
    m.protocol_config = Some(ProtocolConfiguration {
        request_body_mode: BodySendMode::Buffered as i32,
        response_body_mode: BodySendMode::None as i32,
        send_body_without_waiting_for_header_response: false,
    });
    let step = Session::default().handle(&judge(false, false), m).await;
    let Some(Reply::ImmediateResponse(i)) = step.into_responses().pop().and_then(|r| r.response)
    else {
        panic!("not refused");
    };
    let reply: serde_json::Value = serde_json::from_slice(&i.body).unwrap();
    assert_eq!(reply["error"]["type"], "pasu_misconfigured");

    let denied = run(
        &judge(false, false),
        vec![
            chat_headers(),
            body_msg_for_type_test(),
            response_headers("200", &[]),
            body(Phase::ResponseBody, tool_call_body("shell"), true),
        ],
    )
    .await;
    assert_eq!(denied, Some(403), "a policy refusal stays a 403");
}

fn body_msg_for_type_test() -> ProcessingRequest {
    body(Phase::RequestBody, prompt("hi"), true)
}
