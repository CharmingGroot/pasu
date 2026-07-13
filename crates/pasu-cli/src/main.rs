//! pasu — wrap any agent in the kernel egress guard, one command, no code
//! changes:
//!
//! ```text
//! sudo pasu run --policy rules.yaml -- python crew.py
//! sudo pasu run --policy rules.yaml -- claude -p "fix the tests"
//! ```
//!
//! `run` creates a dedicated cgroup, attaches the eBPF guard to it (lowered
//! from the same policy YAML the in-process hooks read), starts the command
//! INSIDE that cgroup, and enforces until it exits. Fail-closed: if the guard
//! cannot attach, the command never starts.

use std::os::unix::process::{CommandExt as _, ExitStatusExt as _};
use std::path::PathBuf;

use anyhow::Context as _;
use clap::Parser;
use pasu_egress::guard::{Guard, GuardConfig};
use pasu_rules::Ruleset;

#[derive(Debug, Parser)]
#[clap(name = "pasu", about = "a security guard for AI agents")]
enum Cmd {
    /// Run a command inside a dedicated, kernel-guarded cgroup.
    Run(RunArgs),
}

#[derive(Debug, Parser)]
struct RunArgs {
    /// The pasu policy YAML — the same file your agent's hooks can load.
    #[clap(short, long)]
    policy: PathBuf,
    /// Where to create the dedicated cgroup (cgroup v2 hierarchy).
    #[clap(long, default_value = "/sys/fs/cgroup")]
    cgroup_root: PathBuf,
    /// Domain re-resolution interval, seconds.
    #[clap(long, default_value_t = 30)]
    refresh_secs: u64,
    /// Serve the control-plane admin API on this unix socket while running.
    #[clap(long)]
    admin_socket: Option<PathBuf>,
    /// The agent command to guard (everything after `--`).
    #[clap(last = true, required = true)]
    command: Vec<String>,
}

/// Lower the policy to a guard config for `cgroup_path` (fail-closed on
/// default-allow), printing the lowering report.
fn lower(args: &RunArgs, cgroup_path: PathBuf) -> anyhow::Result<GuardConfig> {
    let yaml = std::fs::read_to_string(&args.policy)
        .with_context(|| format!("read policy {}", args.policy.display()))?;
    let ruleset = Ruleset::from_yaml(&yaml)
        .with_context(|| format!("parse policy {}", args.policy.display()))?;
    let allowlist = ruleset.egress_allowlist()?;

    println!("policy: {}", args.policy.display());
    for ip in &allowlist.ips {
        println!("  kernel allow ip     {ip}");
    }
    for d in &allowlist.domains {
        println!("  kernel allow domain {d}");
    }
    for s in &allowlist.skipped {
        println!("  hook-layer only     {} ({})", s.rule, s.reason);
    }
    if allowlist.ips.is_empty() && allowlist.domains.is_empty() {
        println!("  (no kernel-expressible allow rules: everything is dropped)");
    }

    Ok(GuardConfig {
        cgroup_path,
        allow: allowlist.ips,
        allow_domain: allowlist.domains,
        refresh_secs: args.refresh_secs,
        admin_socket: args.admin_socket.clone(),
    })
}

/// The dedicated cgroup for this run (unique per pasu pid).
fn run_cgroup(root: &std::path::Path) -> PathBuf {
    root.join(format!("pasu-run-{}", std::process::id()))
}

/// Spawn `command` with the child placed into `cgroup` before exec, so its
/// very first syscall is already guarded.
fn spawn_in_cgroup(
    command: &[String],
    cgroup: &std::path::Path,
) -> anyhow::Result<std::process::Child> {
    let procs = cgroup.join("cgroup.procs");
    let mut cmd = std::process::Command::new(&command[0]);
    cmd.args(&command[1..]);
    unsafe {
        cmd.pre_exec(move || {
            let pid = libc::getpid().to_string();
            std::fs::write(&procs, pid)?;
            Ok(())
        });
    }
    cmd.spawn()
        .with_context(|| format!("spawn `{}`", command.join(" ")))
}

async fn run(args: RunArgs) -> anyhow::Result<i32> {
    let cgroup = run_cgroup(&args.cgroup_root);
    std::fs::create_dir(&cgroup)
        .with_context(|| format!("create cgroup {} (root? cgroup v2?)", cgroup.display()))?;
    println!("cgroup: {}", cgroup.display());

    // Attach BEFORE the agent starts — from its first instruction it is guarded.
    let cfg = lower(&args, cgroup.clone())?;
    let guard = Guard::attach(cfg).await?;

    // Spawn the agent into the guarded cgroup, then run the guard (DNS refresh +
    // admin) concurrently until the agent exits. Keeping the guard in this task
    // (not tokio::spawn) avoids requiring the eBPF handle to be `Send`; when the
    // agent finishes, the `hold` future is dropped, detaching the program.
    let child = match spawn_in_cgroup(&args.command, &cgroup) {
        Ok(child) => child,
        Err(e) => {
            drop(guard);
            let _ = std::fs::remove_dir(&cgroup);
            return Err(e);
        }
    };
    let wait = tokio::task::spawn_blocking(move || {
        let mut child = child;
        child.wait()
    });

    let status = tokio::select! {
        _ = guard.hold(std::future::pending::<()>()) => unreachable!("hold never returns on a pending shutdown"),
        r = wait => r??,
    };
    // guard dropped here (hold future dropped) -> eBPF detaches.
    let _ = std::fs::remove_dir(&cgroup);

    let code = status
        .code()
        .unwrap_or_else(|| 128 + status.signal().unwrap_or(0));
    println!("guarded command exited: {status}");
    Ok(code)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    env_logger::init();
    let Cmd::Run(args) = Cmd::parse();
    let code = run(args).await?;
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(policy: &std::path::Path) -> RunArgs {
        RunArgs {
            policy: policy.to_path_buf(),
            cgroup_root: "/sys/fs/cgroup".into(),
            refresh_secs: 30,
            admin_socket: None,
            command: vec!["true".into()],
        }
    }

    #[test]
    fn run_cgroup_is_dedicated_and_unique_per_pid() {
        let p = run_cgroup(std::path::Path::new("/sys/fs/cgroup"));
        assert!(p.starts_with("/sys/fs/cgroup"));
        assert_ne!(p, std::path::Path::new("/sys/fs/cgroup")); // never the root
        assert!(
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pasu-run-")
        );
    }

    #[test]
    fn lowers_policy_like_the_daemon() {
        let dir = std::env::temp_dir().join("pasu-cli-test-lower");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        std::fs::write(
            &path,
            "rules:\n  - name: allow-dns\n    match: { host: \"1.1.1.1\" }\n    action: allow\ndefault: deny\n",
        )
        .unwrap();
        let cfg = lower(&args(&path), "/sys/fs/cgroup/x".into()).unwrap();
        assert_eq!(cfg.allow, vec![std::net::Ipv4Addr::new(1, 1, 1, 1)]);
        assert!(cfg.allow_domain.is_empty());
    }

    #[test]
    fn default_allow_policy_is_rejected() {
        let dir = std::env::temp_dir().join("pasu-cli-test-default");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.yaml");
        std::fs::write(&path, "rules: []\ndefault: allow\n").unwrap();
        assert!(lower(&args(&path), "/sys/fs/cgroup/x".into()).is_err());
    }
}
