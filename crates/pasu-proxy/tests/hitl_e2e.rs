//! End-to-end HITL: a tool call that the policy marks `ask` is held at the
//! proxy until a human decides in the UI, and the decision actually changes
//! what the caller gets.
//!
//! 두 계층(proxy·ui)은 각자 단위 테스트가 있었지만 **이음매**는 비어 있었다.
//! `Verdict::Ask` → UI 대기열 등록 → 승인/거부 → 요청 진행/차단으로 이어지는
//! 왕복 전체를 여기서 검증한다.

use std::sync::Arc;
use std::time::Duration;

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
use pasu_ui::UiApprover;
use tower::ServiceExt;

// `ask` 규칙이 있는 운영형 룰셋. 나머지는 fail-closed.
const RULES: &str = r#"
rules:
  - name: ask-transfer
    match: { tool: transfer_funds }
    action: ask
    reason: moves money
  - name: allow-search
    match: { tool: web_search }
    action: allow
default: deny
"#;

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

/// 프록시 + UI 승인자를 실제 배선대로 묶는다(`--ui` 를 준 것과 같은 구성).
fn proxy_with_ui(upstream_base: String) -> (Router, pasu_ui::AppState) {
    let approver = UiApprover::with_timeout(Duration::from_secs(5));
    let approvals = approver.state();
    let state = Arc::new(ProxyState {
        guard: Guard::with_approver(
            RulesetEngine::from_yaml(RULES).expect("ruleset"),
            approver,
            "llm-proxy",
        ),
        client: reqwest::Client::new(),
        upstream_base,
        provider: Arc::new(Provider::OpenAi),
        inspectors: Vec::new(),
        redaction: Default::default(),
    });
    (router(state), approvals)
}

fn request_for(tool: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/v1/chat/completions")
        .header("x-test-tool", tool)
        .body(Body::empty())
        .expect("request")
}

/// 승인 대기열에 항목이 뜰 때까지 기다린다(폴링). 뜨면 그 id 를 준다.
async fn wait_for_pending(approvals: &pasu_ui::AppState) -> (u64, String) {
    for _ in 0..100 {
        if let Some(first) = approvals.list().into_iter().next() {
            return first;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("승인 요청이 UI 대기열에 등록되지 않았다");
}

#[tokio::test]
async fn ask_is_held_then_approved_and_the_call_proceeds() {
    let (app, approvals) = proxy_with_ui(spawn_mock_upstream().await);

    // 요청을 띄워 둔다 — ask 판정이라 응답이 곧바로 오지 않아야 한다.
    let pending_req = tokio::spawn(async move { app.oneshot(request_for("transfer_funds")).await });

    // UI 대기열에 이유와 함께 올라온다.
    let (id, reason) = wait_for_pending(&approvals).await;
    assert!(
        reason.contains("moves money"),
        "규칙의 reason 이 사람에게 전달되어야 한다: {reason:?}"
    );

    // 사람이 승인한다.
    assert!(
        approvals.decide(id, true),
        "대기 중인 id 를 해소할 수 있어야 한다"
    );

    // 승인 뒤에야 응답이 나오고, 통과한다.
    let resp = pending_req
        .await
        .expect("요청 태스크")
        .expect("프록시 응답");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "승인했으므로 업스트림 응답이 그대로 전달되어야 한다"
    );
    assert!(
        approvals.list().is_empty(),
        "해소된 항목은 대기열에서 빠진다"
    );
}

#[tokio::test]
async fn ask_is_held_then_denied_and_the_call_is_blocked() {
    let (app, approvals) = proxy_with_ui(spawn_mock_upstream().await);
    let pending_req = tokio::spawn(async move { app.oneshot(request_for("transfer_funds")).await });

    let (id, _) = wait_for_pending(&approvals).await;
    assert!(approvals.decide(id, false));

    let resp = pending_req
        .await
        .expect("요청 태스크")
        .expect("프록시 응답");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "거부했으므로 tool call 이 차단되어야 한다"
    );
}

/// 아무도 결정하지 않으면 열어두지 않는다 — 타임아웃은 거부다.
#[tokio::test]
async fn ask_without_a_decision_fails_closed() {
    let upstream = spawn_mock_upstream().await;
    let approver = UiApprover::with_timeout(Duration::from_millis(150));
    let state = Arc::new(ProxyState {
        guard: Guard::with_approver(
            RulesetEngine::from_yaml(RULES).expect("ruleset"),
            approver,
            "llm-proxy",
        ),
        client: reqwest::Client::new(),
        upstream_base: upstream,
        provider: Arc::new(Provider::OpenAi),
        inspectors: Vec::new(),
        redaction: Default::default(),
    });

    let resp = router(state)
        .oneshot(request_for("transfer_funds"))
        .await
        .expect("프록시 응답");
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "결정이 없으면 fail-closed 여야 한다"
    );
}

/// ask 규칙이 다른 도구의 판정을 바꾸지 않는다(오탐 회귀).
#[tokio::test]
async fn allowed_tool_is_not_sent_to_the_approval_queue() {
    let (app, approvals) = proxy_with_ui(spawn_mock_upstream().await);

    let resp = app
        .oneshot(request_for("web_search"))
        .await
        .expect("프록시 응답");
    assert_eq!(resp.status(), StatusCode::OK);
    assert!(
        approvals.list().is_empty(),
        "allow 판정은 사람을 부르지 않는다"
    );
}
