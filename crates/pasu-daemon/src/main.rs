//! pasu-daemon — one policy file, both layers.
//!
//! Reads the same rules YAML the proxy evaluates, lowers its `allow` rules
//! to the kernel egress allowlist (`Ruleset::egress_allowlist`), and runs the
//! eBPF guard. Rules the kernel cannot express (suffix hosts) are reported and
//! stay enforced at the hook layer — the kernel remains default-deny, so the
//! lowering can only be narrower than the policy, never wider.

use anyhow::Context as _;
use clap::Parser;
use pasu_egress::guard::{self, GuardConfig};
use pasu_rules::Ruleset;

#[derive(Debug, Parser)]
struct Opt {
    /// The pasu policy YAML — the SAME file the proxy loads.
    #[clap(short, long)]
    policy: std::path::PathBuf,
    /// cgroup v2 path to attach to. Must be a DEDICATED cgroup: default-deny on
    /// the root cgroup would cut the host's own egress (SSH included).
    #[clap(short, long)]
    cgroup_path: std::path::PathBuf,
    /// Domain re-resolution interval, seconds.
    #[clap(long, default_value_t = 30)]
    refresh_secs: u64,
    /// Serve the control-plane admin API on this unix socket (status + live
    /// allow/deny). Omit to disable.
    #[clap(long)]
    admin_socket: Option<std::path::PathBuf>,
}

fn load(opt: Opt) -> anyhow::Result<GuardConfig> {
    let yaml = std::fs::read_to_string(&opt.policy)
        .with_context(|| format!("read policy {}", opt.policy.display()))?;
    let ruleset = Ruleset::from_yaml(&yaml)
        .with_context(|| format!("parse policy {}", opt.policy.display()))?;
    let allowlist = ruleset.egress_allowlist()?;

    println!("policy: {}", opt.policy.display());
    for ip in &allowlist.ips {
        println!("  kernel allow ip     {ip}");
    }
    for ip6 in &allowlist.ips6 {
        println!("  kernel allow ip     {ip6}");
    }
    for d in &allowlist.domains {
        println!("  kernel allow domain {d}");
    }
    for s in &allowlist.skipped {
        println!("  hook-layer only     {} ({})", s.rule, s.reason);
    }
    if allowlist.ips.is_empty() && allowlist.ips6.is_empty() && allowlist.domains.is_empty() {
        println!("  (no kernel-expressible allow rules: everything is dropped)");
    }

    Ok(GuardConfig {
        cgroup_path: opt.cgroup_path,
        allow: allowlist.ips,
        allow6: allowlist.ips6,
        allow_domain: allowlist.domains,
        refresh_secs: opt.refresh_secs,
        admin_socket: opt.admin_socket,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let cfg = load(Opt::parse())?;
    guard::run(cfg).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opt(policy: &std::path::Path) -> Opt {
        Opt {
            policy: policy.to_path_buf(),
            cgroup_path: "/sys/fs/cgroup/pasu-agent".into(),
            refresh_secs: 30,
            admin_socket: None,
        }
    }

    #[test]
    fn loads_policy_into_guard_config() {
        let dir = std::env::temp_dir().join("pasu-daemon-test-load");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        std::fs::write(
            &path,
            "rules:\n\
             \x20 - name: allow-dns\n\
             \x20   match: { host: \"1.1.1.1\" }\n\
             \x20   action: allow\n\
             \x20 - name: allow-llm\n\
             \x20   match: { host: \"api.openai.com\" }\n\
             \x20   action: allow\n\
             default: deny\n",
        )
        .unwrap();

        let cfg = load(opt(&path)).unwrap();
        assert_eq!(cfg.allow, vec![std::net::Ipv4Addr::new(1, 1, 1, 1)]);
        assert_eq!(cfg.allow_domain, vec!["api.openai.com".to_string()]);
    }

    #[test]
    fn default_allow_policy_is_rejected() {
        // fail-closed: refuse to run rather than silently invert the default.
        let dir = std::env::temp_dir().join("pasu-daemon-test-default");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        std::fs::write(&path, "rules: []\ndefault: allow\n").unwrap();
        assert!(load(opt(&path)).is_err());
    }
}
