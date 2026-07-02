//! pasu-ui — a lightweight human-in-the-loop approval UI.
//!
//! [`UiApprover`] implements [`pasu_core::Approver`]: a `Verdict::Ask` parks a
//! pending request and awaits a human decision (approve/deny) from the web UI.
//! **Fail-closed**: a timeout or dropped channel denies.
//!
//! Deliberately minimal — server-rendered HTML with a meta-refresh, no SPA, one
//! binary (axum). The egress observability dashboard (roadmap M6) plugs in later
//! on top of the observability stream (M5). Design: roadmap.md

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Form, State};
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::Router;
use pasu_core::Approver;
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

/// axum router for the approval UI, backed by `state`.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/decision", post(decision))
        .with_state(state)
}

/// Serve the UI on `addr` until the process exits.
pub async fn serve(addr: std::net::SocketAddr, state: AppState) -> std::io::Result<()> {
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router(state)).await
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
         <h1>pasu — pending approvals</h1>{body}"
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

fn escape(s: &str) -> String {
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
}
