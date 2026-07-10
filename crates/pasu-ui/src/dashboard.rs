//! Egress control dashboard (roadmap M11).
//!
//! Talks to the guard's control-plane admin socket (pasu-egress M10) over its
//! newline/JSON protocol — pasu-ui does **not** link the eBPF stack, it speaks
//! the wire protocol. Shows kernel filter coverage, the live allowlist (with
//! add/remove), resolved domains, and a read-only view of the policy ruleset
//! (each rule's verdict + tool/host guard).

use std::path::PathBuf;

use axum::extract::{Form, State};
use axum::response::{Html, Redirect};
use axum::routing::{get, post};
use axum::Router;
use serde::Deserialize;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

use crate::escape;

/// Client for the guard's admin unix socket.
#[derive(Clone)]
pub struct EgressAdmin {
    socket: PathBuf,
}

/// Live status reported by the guard (mirrors pasu-egress `admin::Status`).
#[derive(Debug, Deserialize)]
pub struct EgressStatus {
    pub cgroup_path: String,
    pub attached: bool,
    pub refresh_secs: u64,
    #[serde(default)]
    pub allow_ips: Vec<String>,
    #[serde(default)]
    pub allow_domains: Vec<String>,
}

impl EgressAdmin {
    pub fn new(socket: impl Into<PathBuf>) -> Self {
        Self {
            socket: socket.into(),
        }
    }

    /// Send one request line, read one JSON reply line.
    async fn request(&self, line: &str) -> Result<String, String> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(|e| format!("connect {}: {e}", self.socket.display()))?;
        let (read, mut write) = stream.into_split();
        write
            .write_all(format!("{line}\n").as_bytes())
            .await
            .map_err(|e| e.to_string())?;
        let mut resp = String::new();
        BufReader::new(read)
            .read_line(&mut resp)
            .await
            .map_err(|e| e.to_string())?;
        Ok(resp.trim().to_string())
    }

    pub async fn status(&self) -> Result<EgressStatus, String> {
        let json = self.request("status").await?;
        serde_json::from_str(&json).map_err(|e| format!("bad status reply: {e}"))
    }

    pub async fn allow(&self, ip: &str) -> Result<(), String> {
        ok_reply(self.request(&format!("allow {ip}")).await?)
    }

    pub async fn deny(&self, ip: &str) -> Result<(), String> {
        ok_reply(self.request(&format!("deny {ip}")).await?)
    }
}

fn ok_reply(json: String) -> Result<(), String> {
    #[derive(Deserialize)]
    struct Reply {
        ok: bool,
        #[serde(default)]
        error: Option<String>,
    }
    match serde_json::from_str::<Reply>(&json) {
        Ok(r) if r.ok => Ok(()),
        Ok(r) => Err(r.error.unwrap_or_else(|| "rejected".into())),
        Err(e) => Err(format!("bad reply: {e}")),
    }
}

/// Dashboard state: the admin client + an optional policy file to display.
#[derive(Clone)]
pub struct EgressUi {
    admin: EgressAdmin,
    policy_path: Option<PathBuf>,
}

impl EgressUi {
    pub fn new(admin: EgressAdmin, policy_path: Option<PathBuf>) -> Self {
        Self { admin, policy_path }
    }
}

/// `/egress` dashboard routes.
pub fn router(ui: EgressUi) -> Router {
    Router::new()
        .route("/egress", get(dashboard))
        .route("/egress/allow", post(allow))
        .route("/egress/deny", post(deny))
        .with_state(ui)
}

#[derive(Deserialize)]
struct IpForm {
    ip: String,
}

async fn allow(State(ui): State<EgressUi>, Form(f): Form<IpForm>) -> Redirect {
    let _ = ui.admin.allow(f.ip.trim()).await;
    Redirect::to("/egress")
}

async fn deny(State(ui): State<EgressUi>, Form(f): Form<IpForm>) -> Redirect {
    let _ = ui.admin.deny(f.ip.trim()).await;
    Redirect::to("/egress")
}

async fn dashboard(State(ui): State<EgressUi>) -> Html<String> {
    let status_html = match ui.admin.status().await {
        Ok(s) => render_status(&s),
        Err(e) => format!(
            "<p class=err>guard not reachable: {}</p>\
             <p>start it with <code>--admin-socket &lt;path&gt;</code></p>",
            escape(&e)
        ),
    };
    let policy_html = ui
        .policy_path
        .as_deref()
        .map(render_policy)
        .unwrap_or_default();
    Html(format!(
        "<!doctype html><meta charset=\"utf-8\">\
         <meta http-equiv=\"refresh\" content=\"3\">\
         <title>pasu — egress</title>\
         <style>{STYLE}</style>\
         <h1>pasu — egress guard</h1>\
         <nav><a href=\"/\">approvals</a> · <a href=\"/audit\">audit</a> · <b>egress</b></nav>\
         {status_html}{policy_html}"
    ))
}

fn render_status(s: &EgressStatus) -> String {
    let ips: String = if s.allow_ips.is_empty() {
        "<li class=muted>none — everything is dropped</li>".into()
    } else {
        s.allow_ips
            .iter()
            .map(|ip| {
                format!(
                    "<li><code>{}</code>\
                     <form method=post action=/egress/deny class=inline>\
                     <input type=hidden name=ip value=\"{}\">\
                     <button>remove</button></form></li>",
                    escape(ip),
                    escape(ip)
                )
            })
            .collect()
    };
    let domains: String = if s.allow_domains.is_empty() {
        "<span class=muted>none</span>".into()
    } else {
        s.allow_domains
            .iter()
            .map(|d| format!("<code>{}</code> ", escape(d)))
            .collect()
    };
    format!(
        "<div class=card>\
         <h2>kernel filter</h2>\
         <p>cgroup <code>{cg}</code> · attached <b>{att}</b> · domain refresh {rs}s</p>\
         <h3>allowed IPs ({n})</h3><ul>{ips}</ul>\
         <form method=post action=/egress/allow class=inline>\
         <input name=ip placeholder=\"1.2.3.4\" required>\
         <button>allow</button></form>\
         <h3>allowed domains</h3><p>{domains}</p>\
         </div>",
        cg = escape(&s.cgroup_path),
        att = s.attached,
        rs = s.refresh_secs,
        n = s.allow_ips.len(),
    )
}

// --- read-only policy view (verdict + tool/host guard per rule) ---

#[derive(Deserialize, Default)]
struct PMatch {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    host: Option<String>,
}

#[derive(Deserialize)]
struct PRule {
    name: String,
    #[serde(rename = "match", default)]
    matcher: PMatch,
    action: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
struct PRuleset {
    #[serde(default)]
    rules: Vec<PRule>,
    #[serde(default)]
    default: Option<String>,
}

fn render_policy(path: &std::path::Path) -> String {
    let yaml = match std::fs::read_to_string(path) {
        Ok(y) => y,
        Err(e) => {
            return format!(
                "<div class=card><h2>policy</h2><p class=err>{}</p></div>",
                escape(&e.to_string())
            )
        }
    };
    let rs: PRuleset = match serde_yaml::from_str(&yaml) {
        Ok(r) => r,
        Err(e) => {
            return format!(
                "<div class=card><h2>policy</h2><p class=err>parse: {}</p></div>",
                escape(&e.to_string())
            )
        }
    };
    let rows: String = rs
        .rules
        .iter()
        .map(|r| {
            let guard = match (&r.matcher.tool, &r.matcher.host) {
                (Some(t), _) => format!("tool <code>{}</code>", escape(t)),
                (_, Some(h)) => format!("host <code>{}</code>", escape(h)),
                _ => "<span class=muted>—</span>".into(),
            };
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape(&r.name),
                guard,
                verdict_badge(&r.action),
                r.reason.as_deref().map(escape).unwrap_or_default()
            )
        })
        .collect();
    let default = rs.default.as_deref().unwrap_or("deny");
    format!(
        "<div class=card><h2>policy (read-only)</h2>\
         <table><tr><th>rule</th><th>guard</th><th>verdict</th><th>reason</th></tr>\
         {rows}\
         <tr class=muted><td>default</td><td>—</td><td>{}</td><td>fail-closed</td></tr>\
         </table></div>",
        verdict_badge(default)
    )
}

fn verdict_badge(action: &str) -> String {
    let cls = match action {
        "allow" => "ok",
        "deny" => "err",
        "ask" => "ask",
        _ => "muted",
    };
    format!("<span class=badge-{cls}>{}</span>", escape(action))
}

const STYLE: &str = "body{font-family:system-ui,sans-serif;max-width:720px;margin:2rem auto;padding:0 1rem;color:#1f2430}\
h1{font-size:1.4rem}nav{margin:.5rem 0 1rem;color:#6b7488}nav a{color:#3f7ef7}\
.card{border:1px solid #e2e5ee;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0}\
.inline{display:inline}code{background:#f2f3f8;padding:.1rem .3rem;border-radius:4px}\
ul{list-style:none;padding:0}li{padding:.2rem 0}li form{margin-left:.5rem}\
button{cursor:pointer;border:1px solid #c9d0e6;background:#fff;border-radius:6px;padding:.15rem .5rem}\
input{border:1px solid #c9d0e6;border-radius:6px;padding:.2rem .4rem}\
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:.3rem .5rem;border-bottom:1px solid #eef0f6}\
.muted{color:#9aa1b2}.err{color:#c0333a}\
.badge-ok{color:#1f7a4d;font-weight:600}.badge-err{color:#c0333a;font-weight:600}.badge-ask{color:#a9711b;font-weight:600}";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_status_json() {
        let s: EgressStatus = serde_json::from_str(
            r#"{"cgroup_path":"/sys/fs/cgroup","attached":true,"refresh_secs":30,"allow_ips":["1.1.1.1"],"allow_domains":["api.openai.com"]}"#,
        )
        .unwrap();
        assert!(s.attached);
        assert_eq!(s.allow_ips, vec!["1.1.1.1"]);
        assert_eq!(s.allow_domains, vec!["api.openai.com"]);
    }

    #[test]
    fn ok_reply_parses() {
        assert!(ok_reply("{\"ok\":true}".into()).is_ok());
        assert!(ok_reply("{\"ok\":false,\"error\":\"nope\"}".into()).is_err());
    }

    #[test]
    fn renders_status_with_ip_and_remove_button() {
        let html = render_status(&EgressStatus {
            cgroup_path: "/sys/fs/cgroup/agent".into(),
            attached: true,
            refresh_secs: 30,
            allow_ips: vec!["1.1.1.1".into()],
            allow_domains: vec!["api.openai.com".into()],
        });
        assert!(html.contains("1.1.1.1"));
        assert!(html.contains("action=/egress/deny"));
        assert!(html.contains("action=/egress/allow"));
    }

    #[test]
    fn renders_policy_verdicts_and_guards() {
        let dir = std::env::temp_dir().join("pasu-ui-policy-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("rules.yaml");
        std::fs::write(
            &p,
            "rules:\n  - name: allow-llm\n    match: { host: api.openai.com }\n    action: allow\n  - name: confirm\n    match: { tool: transfer_funds }\n    action: ask\ndefault: deny\n",
        )
        .unwrap();
        let html = render_policy(&p);
        assert!(html.contains("allow-llm"));
        assert!(html.contains("badge-ok")); // allow
        assert!(html.contains("badge-ask")); // ask
        assert!(html.contains("transfer_funds"));
        assert!(html.contains("badge-err")); // default deny
    }
}
