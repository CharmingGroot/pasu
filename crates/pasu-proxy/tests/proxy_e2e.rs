//! End-to-end: a tool call flows over real HTTP through the proxy to a mock
//! upstream, and the proxy blocks a denied tool while passing an allowed one.
//! This is the "the wire is actually guarded" evidence — not a logic-only test.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{HeaderMap, Request, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use pasu_core::Guard;
use pasu_proxy::{router, Provider, ProxyState};
use pasu_rules::RulesetEngine;
use tower::ServiceExt;

// Production-shaped ruleset: allow a safe tool, deny a destructive one, default
// deny (fail-closed).
const RULES: &str = r#"
rules:
  - name: allow-search
    match: { tool: web_search }
    action: allow
  - name: deny-delete
    match: { tool: delete_file }
    action: deny
    reason: destructive filesystem tool
default: deny
"#;

// Mock provider: returns an OpenAI response whose tool_call name is taken from
// the `x-test-tool` header, so a single mock drives both allow and deny cases.
async fn mock_completions(headers: HeaderMap) -> impl IntoResponse {
    let tool = headers
        .get("x-test-tool")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("web_search")
        .to_string();
    Json(serde_json::json!({
        "choices": [ { "message": { "role": "assistant", "tool_calls": [
            { "id": "c1", "type": "function",
              "function": { "name": tool, "arguments": "{}" } }
        ] } } ]
    }))
}

// Streaming mock: the same tool call, split across SSE chunks the way OpenAI
// streams it (name first, arguments as fragments).
async fn mock_completions_sse(headers: HeaderMap) -> impl IntoResponse {
    let tool = headers
        .get("x-test-tool")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("web_search")
        .to_string();
    let body = format!(
        "data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"id\":\"c1\",\"function\":{{\"name\":\"{tool}\",\"arguments\":\"\"}}}}]}}}}]}}\n\n\
         data: {{\"choices\":[{{\"index\":0,\"delta\":{{\"tool_calls\":[{{\"index\":0,\"function\":{{\"arguments\":\"{{}}\"}}}}]}}}}]}}\n\n\
         data: [DONE]\n\n"
    );
    ([("content-type", "text/event-stream")], body)
}

async fn spawn_mock_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new()
        .route("/v1/chat/completions", post(mock_completions))
        .route("/v1/sse/chat/completions", post(mock_completions_sse));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn proxy_app(upstream_base: String) -> Router {
    proxy_app_with_inspectors(upstream_base, Vec::new())
}

fn proxy_app_with_inspectors(
    upstream_base: String,
    inspectors: Vec<Arc<dyn pasu_core::Inspector>>,
) -> Router {
    let state = Arc::new(ProxyState {
        guard: Guard::new(
            RulesetEngine::from_yaml(RULES).expect("ruleset"),
            "llm-proxy",
        ),
        client: reqwest::Client::new(),
        upstream_base,
        provider: Provider::OpenAi,
        inspectors,
    });
    router(state)
}

/// A completion request whose prompt carries whatever `prompt` says.
fn request_with_prompt(prompt: &str) -> Request<Body> {
    let body = serde_json::json!({
        "model": "gpt-4",
        "messages": [ { "role": "user", "content": prompt } ]
    })
    .to_string();
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("content-type", "application/json")
        .body(Body::from(body))
        .expect("request")
}

fn request_for(tool: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("x-test-tool", tool)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn denied_tool_call_is_blocked_over_the_wire() {
    let app = proxy_app(spawn_mock_upstream().await);
    let resp = app
        .oneshot(request_for("delete_file"))
        .await
        .expect("proxy responds");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allowed_tool_call_passes_through() {
    let app = proxy_app(spawn_mock_upstream().await);
    let resp = app
        .oneshot(request_for("web_search"))
        .await
        .expect("proxy responds");
    assert_eq!(resp.status(), StatusCode::OK);
}

#[tokio::test]
async fn unknown_tool_fails_closed_over_the_wire() {
    let app = proxy_app(spawn_mock_upstream().await);
    let resp = app
        .oneshot(request_for("exfiltrate_secrets"))
        .await
        .expect("proxy responds");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

fn sse_request_for(tool: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/sse/chat/completions")
        .header("x-test-tool", tool)
        .body(Body::empty())
        .expect("request")
}

#[tokio::test]
async fn denied_tool_call_in_sse_stream_is_blocked() {
    let app = proxy_app(spawn_mock_upstream().await);
    let resp = app
        .oneshot(sse_request_for("delete_file"))
        .await
        .expect("proxy responds");
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn allowed_tool_call_in_sse_stream_passes_with_body_intact() {
    let app = proxy_app(spawn_mock_upstream().await);
    let resp = app
        .oneshot(sse_request_for("web_search"))
        .await
        .expect("proxy responds");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), 64 * 1024)
        .await
        .expect("body");
    let text = String::from_utf8(body.to_vec()).expect("utf8");
    // The original SSE bytes pass through untouched.
    assert!(text.contains("data:"), "SSE framing preserved: {text}");
    assert!(text.contains("web_search"));
    assert!(text.contains("[DONE]"));
}

// ---------------------------------------------------------------------------
// The request path
// ---------------------------------------------------------------------------

/// The gap this closes: the proxy forwarded every request untouched, so a prompt
/// carrying a customer record reached the provider unexamined. The kernel layer
/// cannot cover it — it must permit the provider's address, and past that the
/// payload is TLS.
#[tokio::test]
async fn a_prompt_carrying_pii_never_reaches_the_provider() {
    let upstream = spawn_mock_upstream().await;
    let app = proxy_app_with_inspectors(
        upstream,
        vec![Arc::new(pasu_proxy::inspectors::PiiKr::builtin())],
    );

    let response = app
        .oneshot(request_with_prompt("고객 주민번호는 900101-1234567 입니다"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let said = String::from_utf8_lossy(&body);
    assert!(
        said.contains("ko-rrn"),
        "the rule id belongs in the reason: {said}"
    );
    assert!(
        !said.contains("900101-1234567"),
        "a block that quotes what it caught is the leak it was meant to stop: {said}"
    );
}

/// The other direction, and the one a false positive would break: an ordinary
/// prompt still gets through, and its response is still guarded as before.
#[tokio::test]
async fn an_ordinary_prompt_still_reaches_the_provider() {
    let upstream = spawn_mock_upstream().await;
    let app = proxy_app_with_inspectors(
        upstream,
        vec![Arc::new(pasu_proxy::inspectors::PiiKr::builtin())],
    );

    let response = app
        .oneshot(request_with_prompt("오늘 날씨 어때?"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

/// Off by default. A deployment that did not ask for this must behave exactly as
/// it did before the check existed.
#[tokio::test]
async fn without_the_filter_the_request_path_is_untouched() {
    let upstream = spawn_mock_upstream().await;
    let app = proxy_app(upstream);

    let response = app
        .oneshot(request_with_prompt("고객 주민번호는 900101-1234567 입니다"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}
