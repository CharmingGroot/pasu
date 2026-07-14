//! `pasu-proxy` binary — serve the LLM-API guard proxy as a sidecar.
//!
//! App-level composition root: it wires the pure proxy library (router /
//! `ProxyState`) with a concrete rule engine (pasu-rules) and serves it on a
//! TCP port. The agent points its `base_url` at this address; the proxy
//! forwards to the real provider and blocks denied tool calls (fail-closed).
//!
//! The library stays decoupled behind pasu-core; only this binary knows about
//! the concrete engine.

use std::sync::Arc;

use anyhow::Context as _;
use clap::Parser;
use pasu_core::{AuditRecord, AuditSink, Guard};
use pasu_proxy::{router, Provider, ProxyState};
use pasu_rules::RulesetEngine;

#[derive(Debug, Parser)]
#[command(about = "LLM-API guard proxy — parses tool calls and blocks denied ones")]
struct Opt {
    /// The pasu policy YAML — the SAME file your agent's rig hook / daemon loads.
    #[clap(short, long)]
    policy: std::path::PathBuf,
    /// Address to listen on. The agent points its `base_url` here.
    #[clap(short, long, default_value = "127.0.0.1:8788")]
    listen: String,
    /// Upstream LLM provider base URL to forward to (e.g. https://api.openai.com).
    #[clap(short, long)]
    upstream: String,
    /// Provider wire format of the upstream.
    #[clap(long, default_value = "openai")]
    provider: String,
}

fn parse_provider(s: &str) -> anyhow::Result<Provider> {
    match s {
        "openai" => Ok(Provider::OpenAi),
        other => anyhow::bail!("unsupported provider {other:?} (supported: openai)"),
    }
}

/// Minimal stderr JSONL audit — one line per decision, visible to any log
/// pipeline without a heavier sink.
struct StderrAudit;

impl AuditSink for StderrAudit {
    fn record(&self, record: &AuditRecord) {
        if let Ok(line) = serde_json::to_string(record) {
            eprintln!("{line}");
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();
    let provider = parse_provider(&opt.provider)?;

    let yaml = std::fs::read_to_string(&opt.policy)
        .with_context(|| format!("read policy {}", opt.policy.display()))?;
    let engine = RulesetEngine::from_yaml(&yaml)
        .with_context(|| format!("parse policy {}", opt.policy.display()))?;

    let guard = Guard::new(engine, "llm-proxy").with_sink(Arc::new(StderrAudit));
    let state = Arc::new(ProxyState {
        guard,
        client: reqwest::Client::new(),
        upstream_base: opt.upstream.clone(),
        provider,
    });

    let listener = tokio::net::TcpListener::bind(&opt.listen)
        .await
        .with_context(|| format!("bind {}", opt.listen))?;
    eprintln!(
        "pasu-proxy listening on {} -> upstream {} (provider: {})",
        opt.listen, opt.upstream, opt.provider
    );
    axum::serve(listener, router(state))
        .await
        .context("serve")?;
    Ok(())
}
