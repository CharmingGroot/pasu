//! End-to-end test for the eBPF egress guard.
//!
//! Mirrors Prempti's `E2eHarness` pattern: spawn the guard binary (which attaches the
//! `cgroup_skb` egress program on the root cgroup), then assert that traffic to the
//! blocked IP is dropped while a different destination still flows.
//!
//! Like Prempti's `require_falco!` and SkillSpector's `skipif(geteuid != 0)`, this
//! test self-skips when it cannot run (no root, or no baseline connectivity) instead
//! of failing — so the plain `ubuntu-latest` CI stays green and only the self-hosted
//! runner (root + cgroup_skb kernel) actually exercises the kernel path.
//!
//! Kernel e2e is opt-in via the PASU_E2E_KERNEL env var, so the default `ubuntu-latest`
//! CI (no kernel/root) stays green by skipping, and only the self-hosted runner enables
//! it explicitly — same idea as SkillSpector's `-m integration` opt-in marker.
//!
//! Run on a root-capable host (the PoC's `.cargo/config.toml` sets `runner = "sudo -E"`,
//! which elevates the test binary to root and preserves the env var):
//!   PASU_E2E_KERNEL=1 cargo test -p pasu-egress --test egress_e2e -- --nocapture

use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

/// Path to the guard binary, injected by cargo for integration tests of this package.
const GUARD_BIN: &str = env!("CARGO_BIN_EXE_pasu-egress");

/// Destination hardcoded as BLOCKED in the PoC eBPF program (1.1.1.1).
const BLOCKED: &str = "1.1.1.1:443";
/// Same provider, different IP — must stay reachable (true negative: no over-blocking).
const ALLOWED: &str = "1.0.0.1:443";

/// Kernel e2e is opt-in: set PASU_E2E_KERNEL=1 to actually exercise the kernel path.
/// Unset (the default, incl. plain `ubuntu-latest` CI) → the test skips and CI stays green.
fn e2e_enabled() -> bool {
    std::env::var_os("PASU_E2E_KERNEL").is_some()
}

fn is_root() -> bool {
    // geteuid is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

fn connects(addr: &str, timeout: Duration) -> bool {
    let sa: SocketAddr = addr.parse().expect("valid socket addr literal");
    TcpStream::connect_timeout(&sa, timeout).is_ok()
}

/// Kills the spawned guard on drop, so the cgroup program is always detached even if
/// an assertion panics mid-test (RAII cleanup, like Prempti's harness `Drop`).
struct GuardProc(Child);
impl Drop for GuardProc {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn blocks_target_ip_but_allows_others() {
    if !e2e_enabled() {
        eprintln!(
            "SKIP blocks_target_ip_but_allows_others: kernel e2e is opt-in. Set \
             PASU_E2E_KERNEL=1 on a root-capable host (e.g. the self-hosted runner) to run it."
        );
        return;
    }
    if !is_root() {
        eprintln!(
            "SKIP blocks_target_ip_but_allows_others: PASU_E2E_KERNEL is set but euid != 0; \
             BPF attach needs root (run via sudo, or cargo with runner = \"sudo -E\")."
        );
        return;
    }

    // Baseline: with no guard attached, both IPs must be reachable. If not, the runner
    // is offline — skip rather than mistake "no network" for "blocked".
    if !connects(BLOCKED, Duration::from_secs(4)) || !connects(ALLOWED, Duration::from_secs(4)) {
        eprintln!(
            "SKIP blocks_target_ip_but_allows_others: no baseline connectivity to test \
             IPs (offline?) — cannot verify blocking vs. dropping."
        );
        return;
    }

    // Start the guard; it attaches cgroup_skb egress on /sys/fs/cgroup (root cgroup),
    // which covers this test process and any child it spawns.
    let child = Command::new(GUARD_BIN)
        .args(["--block", "1.1.1.1"]) // control plane injects the blocklist into the eBPF map
        .env("RUST_LOG", "info")
        .spawn()
        .expect("failed to spawn guard binary");
    let _guard = GuardProc(child);

    // Wait until the block takes effect (attach completed). Polling instead of a fixed
    // sleep keeps the test fast when attach is quick and robust when it is slow.
    let deadline = Instant::now() + Duration::from_secs(12);
    let mut became_blocked = false;
    while Instant::now() < deadline {
        if !connects(BLOCKED, Duration::from_secs(2)) {
            became_blocked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }
    assert!(
        became_blocked,
        "egress to {BLOCKED} should be DROPPED once the guard is attached (true positive)"
    );

    // The other destination must still connect — proves the guard blocks surgically,
    // not everything (true negative).
    assert!(
        connects(ALLOWED, Duration::from_secs(5)),
        "egress to {ALLOWED} must remain reachable (true negative) — guard is over-blocking"
    );
}

/// Dynamic-map regression: with an EMPTY blocklist the guard must NOT block the IP
/// that the previous test blocks — proving the block is map-driven (control plane
/// injects it), not hardcoded into the eBPF program.
#[test]
fn empty_blocklist_does_not_block() {
    if !e2e_enabled() {
        eprintln!(
            "SKIP empty_blocklist_does_not_block: kernel e2e is opt-in. Set \
             PASU_E2E_KERNEL=1 on a root-capable host to run it."
        );
        return;
    }
    if !is_root() {
        eprintln!("SKIP empty_blocklist_does_not_block: PASU_E2E_KERNEL set but euid != 0.");
        return;
    }
    if !connects(BLOCKED, Duration::from_secs(4)) {
        eprintln!("SKIP empty_blocklist_does_not_block: no baseline connectivity.");
        return;
    }

    // Spawn with NO --block → empty map.
    let child = Command::new(GUARD_BIN)
        .env("RUST_LOG", "info")
        .spawn()
        .expect("failed to spawn guard binary");
    let _guard = GuardProc(child);

    // Give the attach time to take effect, then the IP must STILL connect.
    std::thread::sleep(Duration::from_secs(3));
    assert!(
        connects(BLOCKED, Duration::from_secs(5)),
        "empty blocklist must NOT block {BLOCKED} (a block here would mean hardcoded, not map-driven)"
    );
}
