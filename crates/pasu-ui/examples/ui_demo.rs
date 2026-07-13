//! Run the pasu UI (approvals + audit + egress dashboard) against a MOCK guard
//! admin socket, so you can click around without a Linux kernel / eBPF.
//!
//!   cargo run -p pasu-ui --example ui_demo
//!   open http://127.0.0.1:8787/egress
//!
//! The mock speaks the same newline/JSON admin protocol as pasu-egress (M10),
//! with an in-memory allowlist you can edit from the dashboard.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use pasu_ui::dashboard::{EgressAdmin, EgressUi};
use pasu_ui::{AuditFeed, UiApprover};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;

type Allow = Arc<Mutex<BTreeSet<String>>>;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let sock = std::env::temp_dir().join("pasu-ui-demo.sock");
    let _ = std::fs::remove_file(&sock);
    let allow: Allow = Arc::new(Mutex::new(
        ["1.1.1.1".to_string(), "162.159.140.245".to_string()]
            .into_iter()
            .collect(),
    ));

    // Mock admin socket.
    let listener = UnixListener::bind(&sock)?;
    {
        let allow = allow.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let allow = allow.clone();
                tokio::spawn(async move {
                    let (r, mut w) = stream.into_split();
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let reply = handle(&line, &allow);
                        if w.write_all(format!("{reply}\n").as_bytes()).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    }

    // A sample policy so the read-only view has something to show.
    let policy = std::env::temp_dir().join("pasu-ui-demo-rules.yaml");
    std::fs::write(
        &policy,
        "rules:\n  - name: allow-llm\n    match: { host: api.openai.com }\n    action: allow\n  - name: allow-dns\n    match: { host: 1.1.1.1 }\n    action: allow\n  - name: confirm-transfer\n    match: { tool: transfer_funds }\n    action: ask\n    reason: human approval for money movement\n  - name: block-exfil\n    match: { host: pastebin.com }\n    action: deny\ndefault: deny\n",
    )?;

    let approver = UiApprover::new();
    let feed = AuditFeed::new(64);
    let egress = EgressUi::new(EgressAdmin::new(&sock), Some(policy));
    let addr = "127.0.0.1:8787".parse().unwrap();
    println!(
        "pasu UI demo: http://{addr}/egress  (mock socket {})",
        sock.display()
    );
    pasu_ui::serve_all(addr, approver.state(), feed, Some(egress)).await
}

fn handle(line: &str, allow: &Allow) -> String {
    let mut it = line.split_whitespace();
    match it.next().unwrap_or_default() {
        "status" => {
            let ips: Vec<String> = allow.lock().unwrap().iter().cloned().collect();
            serde_json::json!({
                "cgroup_path": "/sys/fs/cgroup/pasu-agent (mock)",
                "attached": true,
                "refresh_secs": 30,
                "allow_ips": ips,
                "allow_domains": ["api.openai.com"],
            })
            .to_string()
        }
        verb @ ("allow" | "deny") => match it.next() {
            Some(ip) => {
                if verb == "allow" {
                    allow.lock().unwrap().insert(ip.to_string());
                } else {
                    allow.lock().unwrap().remove(ip);
                }
                "{\"ok\":true}".to_string()
            }
            None => "{\"ok\":false,\"error\":\"missing ip\"}".to_string(),
        },
        other => format!("{{\"ok\":false,\"error\":\"unknown: {other}\"}}"),
    }
}
