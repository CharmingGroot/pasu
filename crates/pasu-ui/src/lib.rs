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
    let recent = feed.recent();
    let inner = if recent.is_empty() {
        "<p class=empty>no decisions yet</p>".to_string()
    } else {
        let rows: String = recent
            .iter()
            .rev()
            .map(|r| {
                let reason = r.reason.as_deref().map(escape).unwrap_or_default();
                format!(
                    "<tr><td>{}</td><td class=mono>{}</td><td>{}</td><td class=muted>{}</td></tr>",
                    verdict_pill(&format!("{:?}", r.verdict)),
                    escape(&r.subject),
                    format_args!("<span class=chip>{}</span>", escape(&r.layer)),
                    reason,
                )
            })
            .collect();
        format!(
            "<table><tr><th>verdict</th><th>subject</th><th>layer</th><th>reason</th></tr>{rows}</table>"
        )
    };
    let body = format!(
        "<div class=card><h2>recent decisions</h2>\
         <p class=sub>every allow / ask / deny from both layers (newest first)</p>{inner}</div>"
    );
    Html(page("/audit", &body))
}

async fn index(State(state): State<AppState>) -> Html<String> {
    let pending = state.list();
    let inner = if pending.is_empty() {
        "<p class=empty>nothing waiting — the agent is clear to proceed</p>".to_string()
    } else {
        let rows: String = pending
            .iter()
            .map(|(id, reason)| {
                format!(
                    "<li class=row><span><span class=muted>#{id}</span> {reason}</span>\
                     <span>\
                     <form class=row-form method=post action=/decision>\
                     <input type=hidden name=id value={id}>\
                     <button class=\"btn btn-ok btn-sm\" name=approve value=true>approve</button></form>\
                     <form class=row-form method=post action=/decision>\
                     <input type=hidden name=id value={id}>\
                     <button class=\"btn btn-danger btn-sm\" name=approve value=false>deny</button></form>\
                     </span></li>",
                    reason = escape(reason)
                )
            })
            .collect();
        format!("<ul class=list>{rows}</ul>")
    };
    let n = pending.len();
    let body = format!(
        "<div class=card><h2>pending approvals <span class=count>({n})</span></h2>\
         <p class=sub>human-in-the-loop — a <code>Verdict::Ask</code> waits here (fail-closed on timeout)</p>{inner}</div>"
    );
    Html(page("/", &body))
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

// --- shared design system (self-contained: no external assets) ---

/// The pasu mark (gate + flows), inline so the UI has no external requests.
pub(crate) const LOGO: &str = "<svg class=logo viewBox='0 0 200 200' xmlns='http://www.w3.org/2000/svg' aria-hidden=true>\
<rect width=200 height=200 rx=46 fill=#403aa8/>\
<rect x=34 y=59 width=52 height=14 rx=7 fill=#6b74a0/>\
<rect x=34 y=127 width=52 height=14 rx=7 fill=#6b74a0/>\
<rect x=34 y=93 width=122 height=14 rx=7 fill=#5f9bff/>\
<path d='M153 90 L178 100 L153 110 Z' fill=#7fb0ff/>\
<rect x=88 y=46 width=16 height=46 rx=6 fill=#e2e6ff/>\
<rect x=88 y=108 width=16 height=46 rx=6 fill=#e2e6ff/></svg>";

pub(crate) const STYLE: &str = "\
:root{--bg:#f6f7fb;--panel:#fff;--border:#e6e8f0;--text:#1b1f2a;--muted:#6b7280;--brand:#4f46e5;--brand-2:#3f7ef7;\
--ok:#1f9d57;--ok-bg:#e6f6ec;--warn:#b7791f;--warn-bg:#fdf3e3;--err:#d64550;--err-bg:#fbe9ea;\
--mono:ui-monospace,SFMono-Regular,Menlo,monospace;--shadow:0 1px 2px rgba(16,24,40,.06),0 1px 3px rgba(16,24,40,.08)}\
@media(prefers-color-scheme:dark){:root{--bg:#0f1117;--panel:#171a22;--border:#252a36;--text:#e7e9ef;--muted:#9aa1b2;\
--brand:#8b8cf0;--brand-2:#6f9dff;--ok:#4ade80;--ok-bg:#12271b;--warn:#fbbf24;--warn-bg:#2a2113;--err:#f87171;--err-bg:#2a1517;\
--shadow:0 1px 2px rgba(0,0,0,.4)}}\
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.55 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}\
header{max-width:880px;margin:0 auto;padding:24px 20px 10px;display:flex;align-items:center;gap:14px}\
.logo{width:40px;height:40px;flex:0 0 auto;border-radius:11px;box-shadow:var(--shadow)}\
.brand{font-weight:800;font-size:20px;letter-spacing:.2px;line-height:1}.tag{color:var(--muted);font-size:12px;margin-top:3px}\
nav{margin-left:auto;display:flex;gap:4px}nav a{padding:7px 14px;border-radius:10px;color:var(--muted);text-decoration:none;font-weight:600;font-size:14px}\
nav a:hover{background:var(--panel)}nav a.active{background:var(--brand);color:#fff}\
main{max-width:880px;margin:0 auto;padding:8px 20px 56px}\
.card{background:var(--panel);border:1px solid var(--border);border-radius:16px;padding:18px 20px;margin:16px 0;box-shadow:var(--shadow)}\
.card h2{margin:0 0 3px;font-size:16px}.card .sub{color:var(--muted);font-size:13px;margin:0 0 14px}\
.tiles{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:4px}\
.tile{background:var(--bg);border:1px solid var(--border);border-radius:12px;padding:12px 14px}\
.tile .k{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px}\
.tile .v{font-weight:700;margin-top:5px;font-family:var(--mono);font-size:13px;word-break:break-all}\
.pill{display:inline-block;padding:2px 11px;border-radius:999px;font-size:12px;font-weight:700}\
.pill-ok{background:var(--ok-bg);color:var(--ok)}.pill-warn{background:var(--warn-bg);color:var(--warn)}.pill-err{background:var(--err-bg);color:var(--err)}\
.list{list-style:none;margin:8px 0 0;padding:0}.row{display:flex;align-items:center;gap:10px;justify-content:space-between;padding:9px 12px;border-radius:10px}\
.row:hover{background:var(--bg)}.mono{font-family:var(--mono);font-size:14px}\
.chip{display:inline-block;font-family:var(--mono);font-size:12px;background:var(--bg);border:1px solid var(--border);border-radius:8px;padding:3px 9px;margin:3px 5px 0 0}\
.muted{color:var(--muted)}.count{color:var(--muted);font-weight:600;font-size:13px}\
form.inline{display:flex;gap:8px;margin-top:14px}form.row-form{display:inline;margin:0}\
input:not([type=hidden]){flex:1;min-width:0;padding:9px 12px;border:1px solid var(--border);border-radius:10px;background:var(--bg);color:var(--text);font:inherit}\
.btn{border:1px solid var(--border);background:var(--panel);color:var(--text);border-radius:10px;padding:9px 15px;font:inherit;font-weight:600;cursor:pointer}\
.btn:hover{border-color:var(--brand)}.btn-primary{background:var(--brand);border-color:var(--brand);color:#fff}.btn-primary:hover{filter:brightness(1.06)}\
.btn-ok{background:var(--ok);border-color:var(--ok);color:#fff}.btn-sm{padding:5px 11px;font-size:13px}\
.btn-danger{color:var(--err);border-color:transparent;background:transparent}.btn-danger:hover{background:var(--err-bg)}\
table{width:100%;border-collapse:collapse;font-size:14px;margin-top:6px}\
th{text-align:left;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.5px;padding:6px 10px;border-bottom:1px solid var(--border)}\
td{padding:10px;border-bottom:1px solid var(--border);vertical-align:middle}tr:last-child td{border-bottom:0}\
.empty{color:var(--muted);font-style:italic;padding:10px 2px}\
.err-box{background:var(--err-bg);color:var(--err);border-radius:10px;padding:12px 14px;font-size:14px}\
.err-box code{background:rgba(0,0,0,.06)}\
@media(max-width:560px){header{flex-wrap:wrap}nav{margin-left:0;width:100%;margin-top:8px}}";

/// Full HTML page with the shared header/nav; `active` is the current path.
pub(crate) fn page(active: &str, body: &str) -> String {
    let tab = |href: &str, label: &str| {
        let cls = if active == href { " class=active" } else { "" };
        format!("<a{cls} href=\"{href}\">{label}</a>")
    };
    format!(
        "<!doctype html><html lang=en><head><meta charset=utf-8>\
         <meta name=viewport content=\"width=device-width,initial-scale=1\">\
         <meta http-equiv=refresh content=4>\
         <title>pasu</title><style>{STYLE}</style></head><body>\
         <header>{LOGO}<div><div class=brand>pasu</div><div class=tag>egress guard</div></div>\
         <nav>{}{}{}</nav></header><main>{body}</main></body></html>",
        tab("/", "approvals"),
        tab("/audit", "audit"),
        tab("/egress", "egress"),
    )
}

/// A verdict/action rendered as a coloured pill.
pub(crate) fn verdict_pill(v: &str) -> String {
    let cls = match v.to_ascii_lowercase().as_str() {
        "allow" => "pill-ok",
        "deny" => "pill-err",
        "ask" => "pill-warn",
        _ => "pill-warn",
    };
    format!("<span class=\"pill {cls}\">{}</span>", escape(v.trim()))
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
