//! The LiteLLM Generic Guardrail API front-end, against the shipped ruleset.
//!
//! Bodies are shaped the way LiteLLM sends them (see its
//! `GenericGuardrailAPIRequest`): `input_type`, `texts`, and OpenAI-style
//! `tool_calls` whatever the provider was.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
};
use pasu_core::Guard;
use pasu_proxy::litellm::{guardrail_router, GuardrailState, LITELLM_GUARDRAIL_PATH};
use pasu_proxy::{Judge, Provider};
use pasu_rules::RulesetEngine;
use serde_json::{json, Value};
use tower::ServiceExt;

const PRODUCTION_RULES: &str = include_str!("../../../deploy/rules.yaml");
const RRN: &str = "900101-1234567";

fn app(redact: bool, api_key: Option<&str>) -> Router {
    let redaction = if redact {
        pasu_core::redact::Policy::redact_everything()
    } else {
        pasu_core::redact::Policy::block_everything()
    };
    guardrail_router(Arc::new(GuardrailState {
        judge: Judge {
            guard: Guard::new(
                RulesetEngine::from_yaml(PRODUCTION_RULES).expect("production ruleset"),
                "litellm-guardrail",
            ),
            provider: Arc::new(Provider::OpenAi),
            inspectors: vec![Arc::new(pasu_inspect_pii_kr::PiiKr::builtin())],
            redaction,
            options: Default::default(),
        },
        api_key: api_key.map(str::to_string),
    }))
}

async fn call(app: Router, body: Value, key: Option<&str>) -> (StatusCode, Value) {
    let mut req = Request::post(LITELLM_GUARDRAIL_PATH).header("content-type", "application/json");
    if let Some(k) = key {
        req = req.header("x-api-key", k);
    }
    let resp = app
        .oneshot(req.body(Body::from(body.to_string())).expect("request"))
        .await
        .expect("serve");
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

fn response_with(tool_calls: Value) -> Value {
    json!({"input_type": "response", "texts": [], "tool_calls": tool_calls,
           "request_data": {}, "model": "gpt-4o"})
}

#[tokio::test]
async fn a_denied_tool_call_is_blocked() {
    let body = response_with(json!([
        {"id": "c1", "type": "function", "function": {"name": "shell", "arguments": "{\"cmd\":\"id\"}"}}
    ]));
    let (status, out) = call(app(false, None), body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(out["action"], "BLOCKED", "{out}");
    assert!(out["blocked_reason"].as_str().unwrap().contains("shell"));
}

/// Stream chunks carry an `index`; Anthropic calls arrive in the same shape.
#[tokio::test]
async fn a_denied_tool_call_chunk_is_blocked() {
    let body = response_with(json!([
        {"id": "c1", "type": "function", "index": 0,
         "function": {"name": "shell", "arguments": {"cmd": "id"}}}
    ]));
    let (_, out) = call(app(false, None), body, None).await;
    assert_eq!(out["action"], "BLOCKED", "{out}");
}

#[tokio::test]
async fn a_response_without_tool_calls_passes() {
    let body = json!({"input_type": "response", "texts": ["hello"], "request_data": {}});
    let (status, out) = call(app(false, None), body, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(out["action"], "NONE", "{out}");
}

#[tokio::test]
async fn a_tool_call_that_cannot_be_read_is_blocked() {
    let body = response_with(json!([{"id": "c1", "function": {"arguments": "{}"}}]));
    let (_, out) = call(app(false, None), body, None).await;
    assert_eq!(out["action"], "BLOCKED", "{out}");
}

#[tokio::test]
async fn a_prompt_with_pii_is_blocked() {
    let body =
        json!({"input_type": "request", "texts": ["hi", format!("id {RRN}")], "request_data": {}});
    let (_, out) = call(app(false, None), body, None).await;
    assert_eq!(out["action"], "BLOCKED", "{out}");
    assert!(
        !out.to_string().contains(RRN),
        "the refusal quoted the value it caught: {out}"
    );
}

#[tokio::test]
async fn a_prompt_with_pii_is_rewritten_in_order_when_redacting() {
    let body =
        json!({"input_type": "request", "texts": ["hi", format!("id {RRN}")], "request_data": {}});
    let (_, out) = call(app(true, None), body, None).await;
    assert_eq!(out["action"], "GUARDRAIL_INTERVENED", "{out}");
    let texts = out["texts"].as_array().expect("texts");
    assert_eq!(texts.len(), 2, "LiteLLM writes texts back by position");
    assert_eq!(texts[0], "hi");
    assert!(!texts[1].as_str().unwrap().contains(RRN));
}

/// On a request, `tool_calls` are the conversation's history: calls that
/// already ran. Judging them would refuse every later turn of a conversation
/// that once used a denied tool.
#[tokio::test]
async fn history_tool_calls_on_a_request_are_not_judged() {
    let body = json!({"input_type": "request", "texts": ["next step"], "request_data": {},
        "tool_calls": [{"id": "c0", "type": "function", "function": {"name": "shell", "arguments": "{}"}}]});
    let (_, out) = call(app(false, None), body, None).await;
    assert_eq!(out["action"], "NONE", "{out}");
}

/// LiteLLM refuses the call on a non-2xx answer in its default fail_closed
/// mode, so an unreadable call must be an error, never NONE.
#[tokio::test]
async fn an_unknown_phase_is_an_error_not_a_pass() {
    let (status, _) = call(app(false, None), json!({"texts": ["x"]}), None).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = call(
        app(false, None),
        json!({"input_type": "request", "texts": "x"}),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_api_key_is_required_when_set() {
    let body = json!({"input_type": "response", "request_data": {}});
    let (status, _) = call(app(false, Some("k-123")), body.clone(), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _) = call(app(false, Some("k-123")), body.clone(), Some("k-12X")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, out) = call(app(false, Some("k-123")), body, Some("k-123")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(out["action"], "NONE");
}
