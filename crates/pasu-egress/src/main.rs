use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    /// Load settings from a TOML config file (daemon mode; see
    /// packaging/pasu-egress.toml). When set, the flags below are ignored.
    #[clap(long)]
    config: Option<std::path::PathBuf>,
    /// cgroup v2 path to attach to. Required unless `--config` is given, and must
    /// be a DEDICATED cgroup: default-deny on the root cgroup would cut the host's
    /// own egress (SSH included).
    #[clap(short, long)]
    cgroup_path: Option<std::path::PathBuf>,
    /// Destination IPv4 allowed to egress (repeatable). Everything else is dropped.
    #[clap(short, long = "allow")]
    allow: Vec<Ipv4Addr>,
    /// Domain whose resolved IPv4 addresses are allowed (repeatable). Best-effort,
    /// control-plane resolution (precise DNS-response sniffing is future work, M2b).
    #[clap(short = 'd', long = "allow-domain")]
    allow_domain: Vec<String>,
    /// Domain re-resolution interval, seconds.
    #[clap(long, default_value_t = 30)]
    refresh_secs: u64,
}

fn default_refresh_secs() -> u64 {
    30
}

/// Effective settings, from a TOML config file (daemon) or the CLI flags.
#[derive(Debug, serde::Deserialize)]
struct Config {
    /// Dedicated cgroup v2 path (never the root cgroup).
    cgroup_path: std::path::PathBuf,
    #[serde(default)]
    allow: Vec<Ipv4Addr>,
    #[serde(default)]
    allow_domain: Vec<String>,
    #[serde(default = "default_refresh_secs")]
    refresh_secs: u64,
}

impl Opt {
    fn into_config(self) -> anyhow::Result<Config> {
        if let Some(path) = self.config {
            let text = std::fs::read_to_string(&path)
                .with_context(|| format!("read config {}", path.display()))?;
            toml::from_str(&text).with_context(|| format!("parse config {}", path.display()))
        } else {
            let cgroup_path = self
                .cgroup_path
                .context("--cgroup-path is required (or pass --config <file>)")?;
            Ok(Config {
                cgroup_path,
                allow: self.allow,
                allow_domain: self.allow_domain,
                refresh_secs: self.refresh_secs,
            })
        }
    }
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Opt::parse().into_config()?;

    env_logger::init();

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_toml_parses_with_defaults() {
        let cfg: Config = toml::from_str(
            "cgroup_path = \"/sys/fs/cgroup/pasu-agent\"\n\
             allow = [\"1.0.0.1\"]\n\
             allow_domain = [\"api.openai.com\"]\n",
        )
        .expect("valid config");
        assert_eq!(
            cfg.cgroup_path,
            std::path::PathBuf::from("/sys/fs/cgroup/pasu-agent")
        );
        assert_eq!(cfg.allow, vec![Ipv4Addr::new(1, 0, 0, 1)]);
        assert_eq!(cfg.allow_domain, vec!["api.openai.com".to_string()]);
        assert_eq!(cfg.refresh_secs, 30); // serde default
    }

    #[test]
    fn config_requires_cgroup_path() {
        // cgroup_path is mandatory — no accidental root-cgroup default.
        let parsed: Result<Config, _> = toml::from_str("allow = []\n");
        assert!(parsed.is_err());
    }
}
