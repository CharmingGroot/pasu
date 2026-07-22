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
/// Stable domain that resolves to Cloudflare IPs (1.1.1.1 / 1.0.0.1) — includes ALLOWED_IP.
const DOMAIN: &str = "one.one.one.one";
/// An IP NOT covered by DOMAIN — must stay dropped even when DOMAIN is allowlisted.
const OFF_DOMAIN_IP: &str = "8.8.8.8";
/// Unix socket for the control-plane admin API in the live-edit test.
const ADMIN_SOCK: &str = "/tmp/pasu-e2e-admin.sock";
/// Allowlisted IPv6 destination (Cloudflare one.one.one.one) — must connect.
const ALLOWED_V6: &str = "2606:4700:4700::1111";
/// Non-allowlisted IPv6 destination (Cloudflare) — must be dropped.
const DENIED_V6: &str = "2606:4700:4700::1001";

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
        let _ = std::fs::remove_file(ADMIN_SOCK);
    }
}

/// Create the dedicated cgroup and spawn the guard attached to it with `allow`.
/// `admin` (when set) serves the control-plane admin socket at that path.
fn attach_guard(allow: &[&str], domains: &[&str], admin: Option<&str>) -> Guard {
    std::fs::create_dir_all(CGROUP).expect("create dedicated test cgroup");
    let mut cmd = Command::new(GUARD_BIN);
    cmd.args(["--cgroup-path", CGROUP]);
    for ip in allow {
        cmd.args(["--allow", ip]);
    }
    for d in domains {
        cmd.args(["--allow-domain", d]);
    }
    if let Some(sock) = admin {
        cmd.args(["--admin-socket", sock]);
    }
    cmd.env("RUST_LOG", "info");
    let guard = Guard(cmd.spawn().expect("spawn guard binary"));
    std::thread::sleep(Duration::from_secs(3)); // attach + map injection + DNS resolve settle
    guard
}

/// Send one line to the guard's admin socket and return its reply.
fn admin_cmd(socket: &str, line: &str) -> String {
    use std::io::{Read, Write};
    let mut stream = std::os::unix::net::UnixStream::connect(socket).expect("connect admin socket");
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .expect("set read timeout");
    stream
        .write_all(format!("{line}\n").as_bytes())
        .expect("write admin command");
    let mut buf = [0u8; 512];
    let n = stream.read(&mut buf).unwrap_or(0);
    String::from_utf8_lossy(&buf[..n]).to_string()
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

    let _guard = attach_guard(&[ALLOWED_IP], &[], None);

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

    let _guard = attach_guard(&[], &[], None); // nothing allowed

    // default-deny: with an empty allowlist, even ALLOWED_IP is dropped.
    assert!(
        !child_connects_in_cgroup(ALLOWED_IP),
        "empty allowlist must drop all non-loopback egress (default-deny)"
    );
}

#[test]
fn allowlist_by_domain_permits_resolved_denies_others() {
    if should_skip() {
        return;
    }
    if !baseline_connects(ALLOWED_IP) || !baseline_connects(OFF_DOMAIN_IP) {
        eprintln!("SKIP: no baseline connectivity (offline?).");
        return;
    }

    // Allow by DOMAIN — the loader resolves it (→ 1.1.1.1 / 1.0.0.1) into the ALLOW map.
    let _guard = attach_guard(&[], &[DOMAIN], None);

    // A resolved IP of the domain is permitted.
    assert!(
        child_connects_in_cgroup(ALLOWED_IP),
        "a resolved IP of allowlisted domain {DOMAIN} must be reachable"
    );
    // An IP outside the domain is still default-denied.
    assert!(
        !child_connects_in_cgroup(OFF_DOMAIN_IP),
        "{OFF_DOMAIN_IP} (not part of {DOMAIN}) must be dropped"
    );
}

/// IPv6 probe over a literal address (bash /dev/tcp doesn't take v6 literals).
fn v6_baseline(ip6: &str) -> bool {
    tcp_check(&format!(
        "command -v curl >/dev/null && curl -6 -sS --max-time 4 -o /dev/null http://[{ip6}]/"
    ))
}
fn v6_child_connects_in_cgroup(ip6: &str) -> bool {
    tcp_check(&format!(
        "echo $$ > {CGROUP}/cgroup.procs && curl -6 -sS --max-time 6 -o /dev/null http://[{ip6}]/"
    ))
}

#[test]
fn ipv6_allowlist_permits_listed_denies_others() {
    if should_skip() {
        return;
    }
    // GitHub-hosted runners have no IPv6 egress; self-skip there. Exercises the
    // v6 kernel path on a v6-capable host. (The v4 tests already prove the
    // updated eBPF program — with the ALLOW6 map + v6 branch — loads/verifies.)
    if !v6_baseline(ALLOWED_V6) || !v6_baseline(DENIED_V6) {
        eprintln!("SKIP: no IPv6 baseline connectivity (runner has no v6?).");
        return;
    }
    let _guard = attach_guard(&[ALLOWED_V6], &[], None);
    assert!(
        v6_child_connects_in_cgroup(ALLOWED_V6),
        "allowlisted v6 {ALLOWED_V6} must remain reachable"
    );
    assert!(
        !v6_child_connects_in_cgroup(DENIED_V6),
        "non-allowlisted v6 {DENIED_V6} must be DROPPED under default-deny"
    );
}

#[test]
fn admin_socket_allow_then_deny_toggles_egress_live() {
    if should_skip() {
        return;
    }
    if !baseline_connects(ALLOWED_IP) {
        eprintln!("SKIP: no baseline connectivity (offline?).");
        return;
    }

    // Empty allowlist + admin socket. Default-deny: ALLOWED_IP is dropped before
    // any command touches the running guard.
    let _guard = attach_guard(&[], &[], Some(ADMIN_SOCK));
    assert!(
        !child_connects_in_cgroup(ALLOWED_IP),
        "empty allowlist must drop {ALLOWED_IP} before any admin command"
    );

    // Live-allow it over the admin socket — no restart, kernel map edited in place.
    let reply = admin_cmd(ADMIN_SOCK, &format!("allow {ALLOWED_IP}"));
    assert!(reply.contains("\"ok\":true"), "allow reply: {reply}");
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        child_connects_in_cgroup(ALLOWED_IP),
        "after live `allow {ALLOWED_IP}` the running guard must permit it"
    );

    // Live-deny it again — egress must stop without a restart.
    let reply = admin_cmd(ADMIN_SOCK, &format!("deny {ALLOWED_IP}"));
    assert!(reply.contains("\"ok\":true"), "deny reply: {reply}");
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        !child_connects_in_cgroup(ALLOWED_IP),
        "after live `deny {ALLOWED_IP}` the running guard must drop it again"
    );
}
