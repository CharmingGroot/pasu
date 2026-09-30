//! The UI must answer only to the operator.
//!
//! The kernel layer always lets loopback through, so the agent being guarded
//! can reach this port. Before the access token, one guessed form post
//! approved the agent's own pending `Ask` — the first test here is that attack,
//! and it passed against the old router.

use std::time::Duration;

use axum::body::Body;
use axum::http::{header, Request, StatusCode};
use axum::Router;
use pasu_core::Approver;
use pasu_ui::dashboard::{EgressAdmin, EgressUi};
use pasu_ui::{router, router_with_dashboard, Access, AuditFeed, UiApprover};
use tower::ServiceExt;

const ADDR: &str = "127.0.0.1:8789";

fn token(access: &Access) -> String {
    let url = access.login_url(ADDR.parse().unwrap());
    url.split_once("token=").unwrap().1.to_string()
}

fn approve_post(cookie: Option<&str>, origin: Option<&str>) -> Request<Body> {
    let mut b = Request::post("/decision")
        .header(header::HOST, ADDR)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
    if let Some(c) = cookie {
        b = b.header(header::COOKIE, c);
    }
    if let Some(o) = origin {
        b = b.header(header::ORIGIN, o);
    }
    b.body(Body::from("id=0&approve=true")).unwrap()
}

/// Park one `Ask`, send `req`, and report whether the `Ask` was approved.
async fn ask_then(app: Router, approver: UiApprover, req: Request<Body>) -> (StatusCode, bool) {
    let pending = tokio::spawn({
        let a = approver.clone();
        async move { a.approve("bash: rm -rf /").await }
    });
    while approver.state().list().is_empty() {
        tokio::task::yield_now().await;
    }
    let status = app.oneshot(req).await.unwrap().status();
    (status, pending.await.unwrap())
}

fn setup() -> (Router, UiApprover, Access) {
    let approver = UiApprover::with_timeout(Duration::from_millis(300));
    let access = Access::generate().unwrap();
    let app = router(approver.state(), AuditFeed::new(8), access.clone());
    (app, approver, access)
}

#[tokio::test]
async fn a_post_without_the_token_cannot_approve() {
    let (app, approver, _) = setup();
    let (status, approved) = ask_then(app, approver, approve_post(None, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!approved, "the agent approved its own Ask over loopback");
}

#[tokio::test]
async fn a_wrong_token_cannot_approve() {
    let (app, approver, _) = setup();
    let req = approve_post(Some("pasu_ui=00000000"), None);
    let (status, approved) = ask_then(app, approver, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!approved);
}

#[tokio::test]
async fn the_operator_with_the_cookie_can_approve() {
    let (app, approver, access) = setup();
    let cookie = format!("pasu_ui={}", token(&access));
    let req = approve_post(Some(&cookie), Some(&format!("http://{ADDR}")));
    let (status, approved) = ask_then(app, approver, req).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(
        approved,
        "false positive: the operator's own approval was refused"
    );
}

/// A page on another site that somehow carries the cookie (a browser that
/// ignores `SameSite`) is still refused on the `Origin`.
#[tokio::test]
async fn a_cross_site_post_is_refused_even_with_the_cookie() {
    let (app, approver, access) = setup();
    let cookie = format!("pasu_ui={}", token(&access));
    let req = approve_post(Some(&cookie), Some("https://evil.example"));
    let (status, approved) = ask_then(app, approver, req).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(!approved);
}

#[tokio::test]
async fn opening_the_login_url_sets_a_strict_cookie_and_drops_the_token() {
    let (app, _, access) = setup();
    let req = Request::get(format!("/?token={}", token(&access)))
        .header(header::HOST, ADDR)
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    let cookie = resp.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.contains("SameSite=Strict") && cookie.contains("HttpOnly"));
    assert_eq!(resp.headers()[header::LOCATION], "/");
}

#[tokio::test]
async fn reading_the_audit_view_needs_the_token_too() {
    let (app, _, _) = setup();
    let req = Request::get("/audit")
        .header(header::HOST, ADDR)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

/// The dashboard edits the kernel allowlist; the same attack there would open
/// egress to anywhere.
#[tokio::test]
async fn the_egress_allowlist_cannot_be_edited_without_the_token() {
    let approver = UiApprover::new();
    let egress = EgressUi::new(EgressAdmin::new("/nonexistent.sock"), None);
    let app = router_with_dashboard(
        approver.state(),
        AuditFeed::new(8),
        Some(egress),
        Access::generate().unwrap(),
    );
    let req = Request::post("/egress/allow")
        .header(header::HOST, ADDR)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("ip=203.0.113.9"))
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
