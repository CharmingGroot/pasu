//! End-to-end test for the **default-deny allowlist** eBPF egress guard.
//!
//! Creates a DEDICATED cgroup (never the root cgroup — that would cut the host's
//! own egress), attaches the guard with an allowlist, then runs a child process
//! *inside that cgroup* and checks its egress: an allowlisted IP connects, a
//! non-allowlisted IP is dropped. Only the child joins the cgroup, so the test
//! runner's own egress is never governed.
//!
//! Kernel e2e is opt-in via PASU_E2E_KERNEL, and self-skips without root or
//! baseline connectivity — so plain `ubuntu-latest` stays green and only the
//! privileged job actually exercises the kernel path. Run:
//!   sudo env PASU_E2E_KERNEL=1 cargo test -p pasu-egress --test egress_e2e -- --test-threads=1

use std::process::{Child, Command};
use std::time::Duration;

/// Guard binary, injected by cargo for integration tests of this package.
const GUARD_BIN: &str = env!("CARGO_BIN_EXE_pasu-egress");
/// Dedicated cgroup v2 path for the test (NOT the root cgroup).
const CGROUP: &str = "/sys/fs/cgroup/pasu-e2e";
/// Allowlisted destination (Cloudflare) — must connect.
const ALLOWED_IP: &str = "1.0.0.1";
/// Non-allowlisted destination — must be dropped under default-deny.
const DENIED_IP: &str = "1.1.1.1";

fn e2e_enabled() -> bool {
    std::env::var_os("PASU_E2E_KERNEL").is_some()
}

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Try to TCP-connect to `ip:443` from a plain child (no cgroup). Used for a
/// baseline so we don't mistake "offline" for "blocked".
fn baseline_connects(ip: &str) -> bool {
    tcp_check(&format!("timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/443'"))
}

/// Try to TCP-connect to `ip:443` from a child that first joins CGROUP, so the
/// guard governs exactly this connection (echo $$ moves the child in).
fn child_connects_in_cgroup(ip: &str) -> bool {
    tcp_check(&format!(
        "echo $$ > {CGROUP}/cgroup.procs && timeout 3 bash -c 'exec 3<>/dev/tcp/{ip}/443'"
    ))
}

fn tcp_check(script: &str) -> bool {
    Command::new("bash")
        .arg("-c")
        .arg(script)
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Kills the guard and removes the test cgroup on drop (RAII cleanup even on panic).
struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
        let _ = std::fs::remove_dir(CGROUP);
    }
}

/// Create the dedicated cgroup and spawn the guard attached to it with `allow`.
fn attach_guard(allow: &[&str]) -> Guard {
    std::fs::create_dir_all(CGROUP).expect("create dedicated test cgroup");
    let mut cmd = Command::new(GUARD_BIN);
    cmd.args(["--cgroup-path", CGROUP]);
    for ip in allow {
        cmd.args(["--allow", ip]);
    }
    cmd.env("RUST_LOG", "info");
    let guard = Guard(cmd.spawn().expect("spawn guard binary"));
    std::thread::sleep(Duration::from_secs(2)); // let attach + map injection settle
    guard
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

#[test]
fn allowlist_permits_listed_denies_others() {
    if should_skip() {
        return;
    }
    if !baseline_connects(ALLOWED_IP) || !baseline_connects(DENIED_IP) {
        eprintln!("SKIP: no baseline connectivity to test IPs (offline?).");
        return;
    }

    let _guard = attach_guard(&[ALLOWED_IP]);

    // True negative: the allowlisted IP still connects (no over-blocking).
    assert!(
        child_connects_in_cgroup(ALLOWED_IP),
        "allowlisted {ALLOWED_IP} must remain reachable inside the guarded cgroup"
    );
    // True positive: a non-allowlisted IP is dropped by default-deny.
    assert!(
        !child_connects_in_cgroup(DENIED_IP),
        "non-allowlisted {DENIED_IP} must be DROPPED under default-deny"
    );
}

#[test]
fn empty_allowlist_denies_all_egress() {
    if should_skip() {
        return;
    }
    if !baseline_connects(ALLOWED_IP) {
        eprintln!("SKIP: no baseline connectivity (offline?).");
        return;
    }

    let _guard = attach_guard(&[]); // nothing allowed

    // default-deny: with an empty allowlist, even ALLOWED_IP is dropped.
    assert!(
        !child_connects_in_cgroup(ALLOWED_IP),
        "empty allowlist must drop all non-loopback egress (default-deny)"
    );
}
