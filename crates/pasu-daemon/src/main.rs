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
    /// A single pasu policy YAML — the SAME file the proxy loads. Mutually
    /// exclusive with `--policy-dir`.
    #[clap(short, long)]
    policy: Option<std::path::PathBuf>,
    /// A policy directory with `default/` (project-shipped, overwritten on
    /// upgrade) and `user/` (customization, preserved) subdirs of `*.yaml`
    /// rules. The user rules layer on top (take precedence). Mutually exclusive
    /// with `--policy`.
    #[clap(long)]
    policy_dir: Option<std::path::PathBuf>,
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

/// Load the ruleset from exactly one of `--policy <file>` or `--policy-dir
/// <dir>` (the latter layers `user/` over `default/`).
fn load_ruleset(opt: &Opt) -> anyhow::Result<Ruleset> {
    match (&opt.policy, &opt.policy_dir) {
        (Some(file), None) => {
            let yaml = std::fs::read_to_string(file)
                .with_context(|| format!("read policy {}", file.display()))?;
            Ruleset::from_yaml(&yaml).with_context(|| format!("parse policy {}", file.display()))
        }
        (None, Some(dir)) => {
            let base = Ruleset::from_dir(&dir.join("default"))
                .with_context(|| format!("read {}/default", dir.display()))?;
            let user = Ruleset::from_dir(&dir.join("user"))
                .with_context(|| format!("read {}/user", dir.display()))?;
            Ok(base.layered(user))
        }
        (Some(_), Some(_)) => anyhow::bail!("use only one of --policy or --policy-dir"),
        (None, None) => anyhow::bail!("provide --policy <file> or --policy-dir <dir>"),
    }
}

fn load(opt: Opt) -> anyhow::Result<GuardConfig> {
    let ruleset = load_ruleset(&opt)?;
    let allowlist = ruleset.egress_allowlist()?;

    let source = match (&opt.policy, &opt.policy_dir) {
        (Some(file), _) => file.display().to_string(),
        (_, Some(dir)) => format!("{}/{{default,user}}", dir.display()),
        _ => String::new(),
    };
    println!("policy: {source}");
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
            policy: Some(policy.to_path_buf()),
            policy_dir: None,
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

    #[test]
    fn policy_dir_layers_user_over_default() {
        let root = std::env::temp_dir().join("pasu-daemon-test-policydir");
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("default")).unwrap();
        std::fs::create_dir_all(root.join("user")).unwrap();
        // Project baseline allows 1.1.1.1; user adds 9.9.9.9. Both reach the kernel.
        std::fs::write(
            root.join("default/00-base.yaml"),
            "rules:\n  - name: base\n    match: { host: \"1.1.1.1\" }\n    action: allow\ndefault: deny\n",
        )
        .unwrap();
        std::fs::write(
            root.join("user/10-mine.yaml"),
            "rules:\n  - name: mine\n    match: { host: \"9.9.9.9\" }\n    action: allow\ndefault: deny\n",
        )
        .unwrap();

        let o = Opt {
            policy: None,
            policy_dir: Some(root.clone()),
            cgroup_path: "/sys/fs/cgroup/pasu-agent".into(),
            refresh_secs: 30,
            admin_socket: None,
        };
        let cfg = load(o).unwrap();
        let mut ips = cfg.allow.clone();
        ips.sort();
        assert_eq!(
            ips,
            vec![
                std::net::Ipv4Addr::new(1, 1, 1, 1),
                std::net::Ipv4Addr::new(9, 9, 9, 9)
            ]
        );
    }

    #[test]
    fn requires_exactly_one_policy_source() {
        let o = Opt {
            policy: None,
            policy_dir: None,
            cgroup_path: "/sys/fs/cgroup/pasu-agent".into(),
            refresh_secs: 30,
            admin_socket: None,
        };
        assert!(load(o).is_err());
    }
}
