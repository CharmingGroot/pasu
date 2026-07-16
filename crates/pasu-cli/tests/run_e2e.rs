//! End-to-end test for the `pasu run` product CLI — the README's first
//! quickstart. Proves the whole path on a real kernel: policy YAML → lowering →
//! dedicated cgroup → eBPF attach → the wrapped command's egress is enforced —
//! and that a rejected policy fails closed (the command never starts).
//!
//! Same opt-in gating as the egress E2E: PASU_E2E_KERNEL + root, self-skips
//! elsewhere. Run:
//!   sudo env PASU_E2E_KERNEL=1 cargo test -p pasu-cli --test run_e2e -- --test-threads=1

use std::process::Command;

/// The `pasu` binary, injected by cargo for integration tests of this package.
const PASU_BIN: &str = env!("CARGO_BIN_EXE_pasu");
/// Allowlisted destination (Cloudflare) — must connect from inside the guard.
const ALLOWED_IP: &str = "1.0.0.1";
/// Not in the allowlist — must be dropped under default-deny.
const DENIED_IP: &str = "1.1.1.1";

/// Policy whose only kernel-expressible allow is ALLOWED_IP (default deny).
const POLICY: &str = "rules:\n  - name: allow-cf\n    match: { host: \"1.0.0.1\" }\n    action: allow\ndefault: deny\n";

/// A policy pasu must refuse to lower (fail-open default).
const BAD_POLICY: &str = "rules: []\ndefault: allow\n";

fn e2e_enabled() -> bool {
    std::env::var_os("PASU_E2E_KERNEL").is_some()
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

fn should_skip() -> bool {
    if !e2e_enabled() {
        eprintln!("SKIP: kernel e2e is opt-in — set PASU_E2E_KERNEL=1 on a root-capable host.");
        return true;
    }
    if !is_root() {
        eprintln!("SKIP: PASU_E2E_KERNEL set but euid != 0 (BPF attach + cgroup need root).");
        return true;
    }
    false
}

/// Baseline TCP connect (no guard) so "offline" isn't mistaken for "blocked".
fn baseline_connects(ip: &str) -> bool {
    Command::new("bash")
        .args([
            "-c",
            &format!("timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/443'"),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn write_policy(name: &str, yaml: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join("pasu-run-e2e");
    std::fs::create_dir_all(&dir).expect("create policy dir");
    let path = dir.join(name);
    std::fs::write(&path, yaml).expect("write policy");
    path
}

/// `pasu run --policy <policy> -- <command...>` — returns the exit status.
fn pasu_run(policy: &std::path::Path, command: &[&str]) -> std::process::ExitStatus {
    let mut cmd = Command::new(PASU_BIN);
    cmd.arg("run").arg("--policy").arg(policy).arg("--");
    cmd.args(command);
    cmd.status().expect("spawn pasu run")
}

#[test]
fn run_permits_allowlisted_ip_and_drops_others() {
    if should_skip() {
        return;
    }
    if !baseline_connects(ALLOWED_IP) || !baseline_connects(DENIED_IP) {
        eprintln!("SKIP: no baseline connectivity (offline?).");
        return;
    }
    let policy = write_policy("rules.yaml", POLICY);

    // True negative: the policy-allowed IP is reachable from the guarded command.
    let allowed = pasu_run(
        &policy,
        &[
            "timeout",
            "5",
            "bash",
            "-c",
            &format!("exec 3<>/dev/tcp/{ALLOWED_IP}/443"),
        ],
    );
    assert!(
        allowed.success(),
        "policy-allowed {ALLOWED_IP} must be reachable under `pasu run`: {allowed}"
    );

    // True positive: a non-allowlisted IP is dropped (the connect times out).
    let denied = pasu_run(
        &policy,
        &[
            "timeout",
            "5",
            "bash",
            "-c",
            &format!("exec 3<>/dev/tcp/{DENIED_IP}/443"),
        ],
    );
    assert!(
        !denied.success(),
        "non-allowlisted {DENIED_IP} must be DROPPED under `pasu run`"
    );
}

#[test]
fn run_fails_closed_on_default_allow_policy() {
    if should_skip() {
        return;
    }
    let policy = write_policy("bad.yaml", BAD_POLICY);
    let marker = std::env::temp_dir().join("pasu-run-e2e/should-not-exist");
    let _ = std::fs::remove_file(&marker);

    // Fail-closed contract: a fail-open policy is rejected BEFORE the command
    // runs — pasu exits non-zero and the command has no side effect.
    let status = pasu_run(&policy, &["touch", marker.to_str().expect("utf8 path")]);
    assert!(
        !status.success(),
        "`pasu run` must refuse a default-allow policy"
    );
    assert!(
        !marker.exists(),
        "the guarded command must never start when the policy is rejected"
    );
}
