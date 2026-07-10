//! The kernel guard itself: load the eBPF program, populate the ALLOW map,
//! attach to a cgroup, and hold until shutdown.
//!
//! Extracted from the `pasu-egress` binary so composition roots (the binary,
//! `pasu-daemon`) can run the same guard from different policy sources.

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

/// Everything the guard needs to run: where to attach and what to allow.
#[derive(Debug)]
pub struct GuardConfig {
    /// Dedicated cgroup v2 path (never the root cgroup).
    pub cgroup_path: PathBuf,
    /// Static IPv4 allow entries.
    pub allow: Vec<Ipv4Addr>,
    /// Domains whose resolved IPv4s are allowed (re-resolved periodically).
    pub allow_domain: Vec<String>,
    /// Domain re-resolution interval, seconds.
    pub refresh_secs: u64,
}

/// Resolve a domain to its IPv4 addresses (best-effort; empty vec on failure).
async fn resolve_v4(domain: &str) -> Vec<Ipv4Addr> {
    match tokio::net::lookup_host(format!("{domain}:443")).await {
        Ok(addrs) => addrs
            .filter_map(|sa| match sa.ip() {
                IpAddr::V4(v4) => Some(v4),
                IpAddr::V6(_) => None,
            })
            .collect(),
        Err(e) => {
            warn!("resolve {domain} failed: {e}");
            Vec::new()
        }
    }
}

/// Resolve every domain and inject the resulting IPv4s into the ALLOW map.
/// Resolution (await) happens before the map borrow, so the borrow stays short.
async fn refresh_domains(ebpf: &mut aya::Ebpf, domains: &[String]) -> anyhow::Result<()> {
    let mut ips = Vec::new();
    for d in domains {
        ips.extend(resolve_v4(d).await);
    }
    let mut allow: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
    for ip in ips {
        allow.insert(u32::from(ip), 1u8, 0)?;
    }
    Ok(())
}

/// Load, populate, attach, and hold until Ctrl-C.
pub async fn run(cfg: GuardConfig) -> anyhow::Result<()> {
    // Bump the memlock rlimit for older kernels (https://lwn.net/Articles/837122/).
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    let mut ebpf = aya::Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/pasu-egress"
    )))?;
    match aya_log::EbpfLogger::init(&mut ebpf) {
        Err(e) => {
            warn!("failed to initialize eBPF logger: {e}");
        }
        Ok(logger) => {
            let mut logger =
                tokio::io::unix::AsyncFd::with_interest(logger, tokio::io::Interest::READABLE)?;
            tokio::task::spawn(async move {
                loop {
                    let mut guard = logger.readable_mut().await.unwrap();
                    guard.get_inner_mut().flush();
                    guard.clear_ready();
                }
            });
        }
    }

    // Control plane → eBPF: inject static IPs into the ALLOW map.
    {
        let mut allow: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
        for ip in &cfg.allow {
            allow.insert(u32::from(*ip), 1u8, 0)?;
            println!("allowlist += {ip}");
        }
    }
    // Resolve domains and inject their IPv4s (initial).
    if !cfg.allow_domain.is_empty() {
        refresh_domains(&mut ebpf, &cfg.allow_domain).await?;
        for d in &cfg.allow_domain {
            println!("allowlist += {d} (resolved, refresh {}s)", cfg.refresh_secs);
        }
    }

    let cgroup = std::fs::File::open(&cfg.cgroup_path)
        .with_context(|| format!("{}", cfg.cgroup_path.display()))?;
    let program: &mut CgroupSkb = ebpf.program_mut("pasu_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(
        cgroup,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::default(),
    )?;

    println!("Waiting for Ctrl-C...");
    if cfg.allow_domain.is_empty() {
        signal::ctrl_c().await?;
    } else {
        // Periodically re-resolve domains so DNS changes are tracked.
        let mut interval = tokio::time::interval(Duration::from_secs(cfg.refresh_secs));
        interval.tick().await; // consume the immediate first tick (already resolved above)
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    if let Err(e) = refresh_domains(&mut ebpf, &cfg.allow_domain).await {
                        warn!("domain refresh failed: {e}");
                    }
                }
                _ = signal::ctrl_c() => break,
            }
        }
    }
    println!("Exiting...");

    Ok(())
}
