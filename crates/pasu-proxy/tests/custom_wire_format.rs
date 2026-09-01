//! A wire format this repository has never heard of, driven through the proxy.
//!
//! The trait existing is not the same as the seam working. This test is written
//! the way an outside adapter would have to be — nothing from `parse.rs` is
//! reused, no enum variant is added, and the proxy is not edited — so if the
//! extension point regresses to something only the built-in formats can satisfy,
//! this stops compiling.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use pasu_core::Guard;
use pasu_proxy::parse::{ToolCall, WireFormat};
use pasu_proxy::{router, ProxyState};
use pasu_rules::RulesetEngine;
use serde_json::Value;
use tower::ServiceExt;

const RULES: &str = r#"
rules:
  - name: deny-shell
    match: { tool: shell }
    action: deny
default: allow
"#;

/// An in-house shape: the prompt is a bare `input` string, and a tool call is
/// `{"invoke": {"name": …, "args": …}}`. It resembles no provider on purpose.
struct HouseFormat;

impl WireFormat for HouseFormat {
    fn name(&self) -> &str {
        "house"
    }

    fn tool_calls(&self, body: &[u8]) -> Option<Vec<ToolCall>> {
        let value: Value = serde_json::from_slice(body).ok()?;
        let invoke = value.get("invoke")?;
        Some(vec![ToolCall {
            name: invoke.get("name")?.as_str()?.to_string(),
            arguments: invoke
                .get("args")
                .cloned()
                .unwrap_or(Value::Null)
                .to_string(),
        }])
    }

    fn tool_calls_streaming(&self, _body: &[u8]) -> Option<Vec<ToolCall>> {
        None
    }

    fn visit_prompt(
        &self,
        value: &mut Value,
        f: &mut dyn FnMut(&str) -> Option<String>,
    ) -> Option<()> {
        let Some(Value::String(text)) = value.get_mut("input") else {
            return None;
        };
        if let Some(replacement) = f(text) {
            *text = replacement;
        }
        Some(())
    }
}

async fn upstream_returning(body: Value) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let app = Router::new().route(
        "/v1/run",
        post(move || {
            let body = body.clone();
            async move { Json(body) }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

fn app(upstream: String, inspectors: Vec<Arc<dyn pasu_core::Inspector>>) -> Router {
    let state = Arc::new(ProxyState {
        guard: Guard::new(
            RulesetEngine::from_yaml(RULES).expect("ruleset"),
            "llm-proxy",
        ),
        client: reqwest::Client::new(),
        upstream_base: upstream,
        // The whole point: a format defined outside this repository.
        provider: Arc::new(HouseFormat),
        inspectors,
        redaction: Default::default(),
    });
    router(state)
}

fn run(input: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/run")
        .header("content-type", "application/json")
        .body(Body::from(
            serde_json::json!({ "input": input }).to_string(),
        ))
        .expect("request")
}

/// A tool call in a shape nothing here knows is still guarded by the same rules.
#[tokio::test]
async fn a_denied_tool_call_in_a_custom_format_is_blocked() {
    let upstream = upstream_returning(serde_json::json!({
        "invoke": { "name": "shell", "args": { "cmd": "rm -rf /" } }
    }))
    .await;

    let response = app(upstream, Vec::new())
        .oneshot(run("do the thing"))
        .await
        .expect("response");

    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "the ruleset denies shell whatever the wire format is"
    );
}

#[tokio::test]
async fn an_allowed_tool_call_in_a_custom_format_passes() {
    let upstream = upstream_returning(serde_json::json!({
        "invoke": { "name": "read_file", "args": { "path": "README.md" } }
    }))
    .await;

    let response = app(upstream, Vec::new())
        .oneshot(run("do the thing"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::OK);
}

/// And request inspection reads the custom shape's prompt field, which is the
/// half a tool-call-only trait would have missed.
#[tokio::test]
async fn request_inspection_reads_a_custom_prompt_field() {
    let upstream = upstream_returning(serde_json::json!({ "ok": true })).await;
    let inspectors: Vec<Arc<dyn pasu_core::Inspector>> =
        vec![Arc::new(pasu_inspect_pii_kr::PiiKr::builtin())];

    let response = app(upstream, inspectors)
        .oneshot(run("주민번호 900101-1234567"))
        .await
        .expect("response");

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .expect("body");
    let said = String::from_utf8_lossy(&body);
    assert!(said.contains("ko-rrn"), "{said}");
    assert!(
        !said.contains("900101-1234567"),
        "the refusal must not quote what it caught: {said}"
    );
}
