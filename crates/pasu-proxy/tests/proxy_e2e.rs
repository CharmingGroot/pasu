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

async fn spawn_mock_upstream() -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new().route("/v1/chat/completions", post(mock_completions));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn proxy_app(upstream_base: String) -> Router {
    let state = Arc::new(ProxyState {
        guard: Guard::new(
            RulesetEngine::from_yaml(RULES).expect("ruleset"),
            "llm-proxy",
        ),
        client: reqwest::Client::new(),
        upstream_base,
        provider: Provider::OpenAi,
    });
    router(state)
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
