//! pasu-ui — a lightweight human-in-the-loop approval UI.
//!
//! [`UiApprover`] implements [`pasu_core::Approver`]: a `Verdict::Ask` parks a
//! pending request and awaits a human decision (approve/deny) from the web UI.
//! **Fail-closed**: a timeout or dropped channel denies.
//!
//! Deliberately minimal — server-rendered HTML with a meta-refresh, no SPA, one
//! binary (axum). The egress observability dashboard (roadmap M6) plugs in later
//! on top of the observability stream (M5). Design: roadmap.md

pub mod dashboard;

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, State};
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::Router;
use pasu_core::{Approver, AuditRecord, AuditSink};
use serde::Deserialize;
use tokio::sync::oneshot;

/// Default time a pending approval waits before failing closed.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

struct Pending {
    reason: String,
    tx: oneshot::Sender<bool>,
}

#[derive(Default)]
struct Inner {
    pending: Mutex<HashMap<u64, Pending>>,
    next_id: AtomicU64,
}

/// Shared approval state. Cloneable handle; give one clone to the axum app and
/// keep one in the [`UiApprover`].
#[derive(Clone, Default)]
pub struct AppState {
    inner: Arc<Inner>,
}

impl AppState {
    fn park(&self, reason: &str) -> (u64, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        self.inner.pending.lock().unwrap().insert(
            id,
            Pending {
                reason: reason.to_string(),
                tx,
            },
        );
        (id, rx)
    }

    fn drop_pending(&self, id: u64) {
        self.inner.pending.lock().unwrap().remove(&id);
    }

    /// Resolve a pending approval. Returns `false` if the id is unknown.
    pub fn decide(&self, id: u64, approve: bool) -> bool {
        match self.inner.pending.lock().unwrap().remove(&id) {
            Some(p) => {
                let _ = p.tx.send(approve);
                true
            }
            None => false,
        }
    }

    /// `(id, reason)` of every pending approval — for rendering.
    pub fn list(&self) -> Vec<(u64, String)> {
        let mut v: Vec<_> = self
            .inner
            .pending
            .lock()
            .unwrap()
            .iter()
            .map(|(id, p)| (*id, p.reason.clone()))
            .collect();
        v.sort_by_key(|(id, _)| *id);
        v
    }
}

/// [`Approver`] backed by the web UI. Share [`Self::state`] with [`router`].
#[derive(Clone)]
pub struct UiApprover {
    state: AppState,
    timeout: Duration,
}

impl Default for UiApprover {
    fn default() -> Self {
        Self::new()
    }
}

impl UiApprover {
    pub fn new() -> Self {
        Self {
            state: AppState::default(),
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            state: AppState::default(),
            timeout,
        }
    }

    /// Clone of the shared state to hand to [`router`] / [`serve`].
    pub fn state(&self) -> AppState {
        self.state.clone()
    }
}

impl Approver for UiApprover {
    fn approve(&self, reason: &str) -> impl core::future::Future<Output = bool> + Send {
        let (id, rx) = self.state.park(reason);
        let state = self.state.clone();
        let timeout = self.timeout;
        async move {
            match tokio::time::timeout(timeout, rx).await {
                Ok(Ok(decision)) => decision,
                // timeout or dropped sender → fail-closed
                _ => {
                    state.drop_pending(id);
                    false
                }
            }
        }
    }
}

// --- web UI (server-rendered, meta-refresh) ---

/// A bounded ring buffer of recent audit records, exposed at `/audit`.
/// Implements [`AuditSink`], so layers record into it via `with_sink`.
#[derive(Clone)]
pub struct AuditFeed {
    inner: Arc<Mutex<VecDeque<AuditRecord>>>,
    cap: usize,
}

impl AuditFeed {
    /// A feed keeping the most recent `cap` records.
    pub fn new(cap: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(VecDeque::new())),
            cap,
        }
    }

    /// Snapshot of buffered records, oldest first.
    pub fn recent(&self) -> Vec<AuditRecord> {
        self.inner.lock().unwrap().iter().cloned().collect()
    }
}

impl AuditSink for AuditFeed {
    fn record(&self, record: &AuditRecord) {
        let mut q = self.inner.lock().unwrap();
        if self.cap > 0 && q.len() >= self.cap {
            q.pop_front();
        }
        q.push_back(record.clone());
    }
}

/// axum router: approval UI (`/`, `/decision`) + audit view (`/audit`).
pub fn router(approvals: AppState, feed: AuditFeed) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/decision", post(decision))
        .with_state(approvals)
        .merge(
            Router::new()
                .route("/audit", get(audit_index))
                .with_state(feed),
        )
}

/// Router including the egress dashboard (`/egress`) when an admin client is
/// given. `policy_path` (optional) renders the read-only ruleset view.
pub fn router_with_dashboard(
    approvals: AppState,
    feed: AuditFeed,
    egress: Option<dashboard::EgressUi>,
) -> Router {
    let base = router(approvals, feed);
    match egress {
        Some(ui) => base.merge(dashboard::router(ui)),
        None => base,
    }
}

/// Serve the UI on `addr` until the process exits.
pub async fn serve(
    addr: std::net::SocketAddr,
    approvals: AppState,
    feed: AuditFeed,
) -> std::io::Result<()> {
    serve_all(addr, approvals, feed, None).await
}

/// Serve the UI plus the egress dashboard (when `egress` is provided).
pub async fn serve_all(
    addr: std::net::SocketAddr,
    approvals: AppState,
    feed: AuditFeed,
    egress: Option<dashboard::EgressUi>,
) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router_with_dashboard(approvals, feed, egress)).await
}

async fn audit_index(State(feed): State<AuditFeed>) -> Html<String> {
    let rows: String = feed
        .recent()
        .iter()
        .rev()
        .map(|r| {
            let reason = r
                .reason
                .as_deref()
                .map(|x| format!(" — {}", escape(x)))
                .unwrap_or_default();
            format!(
                "<li><code>{}</code> {} → <b>{:?}</b>{}</li>",
                escape(&r.layer),
                escape(&r.subject),
                r.verdict,
                reason
            )
        })
        .collect();
    let body = if rows.is_empty() {
        "<p>no decisions yet</p>".to_string()
    } else {
        format!("<ul>{rows}</ul>")
    };
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\">\
         <meta http-equiv=\"refresh\" content=\"2\">\
         <title>pasu — audit</title>\
         <h1>pasu — recent decisions</h1>{body}"
    ))
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let rows: String = state
        .list()
        .iter()
        .map(|(id, reason)| {
            format!(
                "<li><code>#{id}</code> {reason}\
                 <form method=\"post\" action=\"/decision\" style=\"display:inline\">\
                 <input type=\"hidden\" name=\"id\" value=\"{id}\">\
                 <button name=\"approve\" value=\"true\">approve</button>\
                 <button name=\"approve\" value=\"false\">deny</button></form></li>",
                reason = escape(reason)
            )
        })
        .collect();
    let body = if rows.is_empty() {
        "<p>no pending approvals</p>".to_string()
    } else {
        format!("<ul>{rows}</ul>")
    };
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\">\
         <meta http-equiv=\"refresh\" content=\"2\">\
         <title>pasu — approvals</title>\
         <h1>pasu — pending approvals</h1>\
         <p><a href=\"/audit\">audit log →</a> · <a href=\"/egress\">egress guard →</a></p>{body}"
    ))
}

#[derive(Deserialize)]
struct Decision {
    id: u64,
    approve: bool,
}

async fn decision(State(state): State<AppState>, Form(d): Form<Decision>) -> Redirect {
    state.decide(d.id, d.approve);
    Redirect::to("/")
}

pub(crate) fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fails_closed_on_timeout() {
        let a = UiApprover::with_timeout(Duration::from_millis(30));
        assert!(!a.approve("no one will click").await);
    }

    #[tokio::test]
    async fn approve_decision_resolves_true() {
        let a = UiApprover::new();
        let state = a.state();
        let handle = {
            let a = a.clone();
            tokio::spawn(async move { a.approve("run deploy").await })
        };
        // Wait for the approval to be parked, then approve it.
        let id = loop {
            if let Some((id, _)) = state.list().first() {
                break *id;
            }
            tokio::task::yield_now().await;
        };
        assert!(state.decide(id, true));
        assert!(handle.await.unwrap());
    }

    #[tokio::test]
    async fn deny_decision_resolves_false() {
        let a = UiApprover::new();
        let state = a.state();
        let handle = {
            let a = a.clone();
            tokio::spawn(async move { a.approve("rm -rf").await })
        };
        let id = loop {
            if let Some((id, _)) = state.list().first() {
                break *id;
            }
            tokio::task::yield_now().await;
        };
        assert!(state.decide(id, false));
        assert!(!handle.await.unwrap());
    }

    #[tokio::test]
    async fn decide_unknown_id_is_false() {
        let a = UiApprover::new();
        assert!(!a.state().decide(999, true));
    }

    fn rec(subject: &str) -> pasu_core::AuditRecord {
        let ev = pasu_core::Event {
            kind: pasu_core::EventKind::Egress {
                host: subject.to_string(),
                port: 443,
            },
        };
        pasu_core::AuditRecord::new("rig-egress", &ev, &pasu_core::Verdict::Allow)
    }

    #[test]
    fn audit_feed_keeps_only_recent_within_cap() {
        let feed = AuditFeed::new(2);
        feed.record(&rec("a"));
        feed.record(&rec("b"));
        feed.record(&rec("c"));
        let recent = feed.recent();
        assert_eq!(recent.len(), 2);
        // oldest ("a") dropped; keeps b, c in order.
        assert_eq!(recent[0].subject, "b:443");
        assert_eq!(recent[1].subject, "c:443");
    }

    #[test]
    fn audit_feed_shares_via_clone() {
        let feed = AuditFeed::new(8);
        let handle = feed.clone();
        feed.record(&rec("x"));
        // the clone sees the same buffer
        assert_eq!(handle.recent().len(), 1);
    }
}
