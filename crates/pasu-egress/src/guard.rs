//! The kernel guard itself: load the eBPF program, populate the ALLOW map,
//! attach to a cgroup, optionally serve the control-plane admin socket, and
//! hold until shutdown.
//!
//! Extracted from the `pasu-egress` binary so composition roots (the binary,
//! `pasu-daemon`) can run the same guard from different policy sources.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::{mpsc, oneshot};

use crate::admin::{self, Command, Status};

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
    /// Optional control-plane admin socket (unix). None disables it.
    pub admin_socket: Option<PathBuf>,
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

fn allow_insert(ebpf: &mut aya::Ebpf, ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut allow: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
    allow.insert(u32::from(ip), 1u8, 0)?;
    Ok(())
}

fn allow_remove(ebpf: &mut aya::Ebpf, ip: Ipv4Addr) -> anyhow::Result<()> {
    let mut allow: AyaHashMap<_, u32, u8> =
        AyaHashMap::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
    allow.remove(&u32::from(ip))?;
    Ok(())
}

/// Read the current ALLOW map keys as sorted IPv4 strings.
fn allow_list(ebpf: &aya::Ebpf) -> Vec<String> {
    let Some(map) = ebpf.map("ALLOW") else {
        return Vec::new();
    };
    let Ok(allow): Result<AyaHashMap<_, u32, u8>, _> = AyaHashMap::try_from(map) else {
        return Vec::new();
    };
    let mut ips: Vec<Ipv4Addr> = allow
        .keys()
        .filter_map(Result::ok)
        .map(Ipv4Addr::from)
        .collect();
    ips.sort();
    ips.into_iter().map(|ip| ip.to_string()).collect()
}

/// Accept connections on the admin socket and forward parsed requests to the
/// guard loop over `tx`. One request/response per line.
async fn serve_admin(listener: UnixListener, tx: mpsc::Sender<Command>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let tx = tx.clone();
        tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = handle_line(&line, &tx).await;
                if write
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}

/// Turn one request line into a JSON reply (sending it through the guard loop).
async fn handle_line(line: &str, tx: &mpsc::Sender<Command>) -> String {
    let req = match admin::parse_request(line) {
        Ok(r) => r,
        Err(e) => return err_json(&e),
    };
    match req {
        admin::Request::Status => {
            let (rtx, rrx) = oneshot::channel();
            if tx.send(Command::Status(rtx)).await.is_err() {
                return err_json("guard is shutting down");
            }
            match rrx.await {
                Ok(status) => {
                    serde_json::to_string(&status).unwrap_or_else(|e| err_json(&e.to_string()))
                }
                Err(_) => err_json("no reply from guard"),
            }
        }
        admin::Request::Allow(ip) | admin::Request::Deny(ip) => {
            let (rtx, rrx) = oneshot::channel();
            let cmd = if matches!(req, admin::Request::Allow(_)) {
                Command::Allow(ip, rtx)
            } else {
                Command::Deny(ip, rtx)
            };
            if tx.send(cmd).await.is_err() {
                return err_json("guard is shutting down");
            }
            match rrx.await {
                Ok(Ok(())) => "{\"ok\":true}".to_string(),
                Ok(Err(e)) => err_json(&e),
                Err(_) => err_json("no reply from guard"),
            }
        }
    }
}

fn err_json(msg: &str) -> String {
    serde_json::json!({ "ok": false, "error": msg }).to_string()
}

/// An attached guard: the eBPF program is loaded, populated, and attached to
/// the cgroup. Egress is enforced from the moment `attach` returns — callers
/// (`pasu-egress`, `pasu-daemon`, `pasu run`) then [`Guard::hold`] it for as
/// long as protection should last.
pub struct Guard {
    ebpf: aya::Ebpf,
    cfg: GuardConfig,
    admin_rx: mpsc::Receiver<Command>,
    admin_enabled: bool,
}

impl Guard {
    /// Load the eBPF program, fill the ALLOW map, attach to the cgroup, and
    /// start the admin socket (when configured). Fail-closed: any error means
    /// nothing runs guarded.
    pub async fn attach(cfg: GuardConfig) -> anyhow::Result<Self> {
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
            Err(e) => warn!("failed to initialize eBPF logger: {e}"),
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
        for ip in &cfg.allow {
            allow_insert(&mut ebpf, *ip)?;
            println!("allowlist += {ip}");
        }
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

        // Optional admin socket. Keep a receiver even when disabled so the
        // select arm compiles; it just never fires.
        let (admin_tx, admin_rx) = mpsc::channel::<Command>(16);
        let admin_enabled = cfg.admin_socket.is_some();
        if let Some(path) = &cfg.admin_socket {
            let _ = std::fs::remove_file(path); // clear a stale socket
            let listener = UnixListener::bind(path)
                .with_context(|| format!("bind admin socket {}", path.display()))?;
            println!("admin socket: {}", path.display());
            tokio::spawn(serve_admin(listener, admin_tx));
        } else {
            drop(admin_tx);
        }

        Ok(Self {
            ebpf,
            cfg,
            admin_rx,
            admin_enabled,
        })
    }

    /// Keep enforcing (DNS refresh + admin commands) until `shutdown` resolves.
    /// Dropping the guard afterwards detaches the eBPF program.
    pub async fn hold<F: Future<Output = ()>>(mut self, shutdown: F) -> anyhow::Result<()> {
        let mut interval = tokio::time::interval(Duration::from_secs(self.cfg.refresh_secs));
        interval.tick().await; // consume the immediate first tick
        let refreshing = !self.cfg.allow_domain.is_empty();
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = interval.tick(), if refreshing => {
                    if let Err(e) = refresh_domains(&mut self.ebpf, &self.cfg.allow_domain).await {
                        warn!("domain refresh failed: {e}");
                    }
                }
                cmd = self.admin_rx.recv(), if self.admin_enabled => {
                    match cmd {
                        Some(Command::Status(reply)) => {
                            let _ = reply.send(Status {
                                cgroup_path: self.cfg.cgroup_path.display().to_string(),
                                attached: true,
                                refresh_secs: self.cfg.refresh_secs,
                                allow_ips: allow_list(&self.ebpf),
                                allow_domains: self.cfg.allow_domain.clone(),
                            });
                        }
                        Some(Command::Allow(ip, reply)) => {
                            let _ = reply.send(allow_insert(&mut self.ebpf, ip).map_err(|e| e.to_string()));
                        }
                        Some(Command::Deny(ip, reply)) => {
                            let _ = reply.send(allow_remove(&mut self.ebpf, ip).map_err(|e| e.to_string()));
                        }
                        None => {}
                    }
                }
                _ = &mut shutdown => break,
            }
        }
        if let Some(path) = &self.cfg.admin_socket {
            let _ = std::fs::remove_file(path);
        }
        Ok(())
    }
}

/// Load, populate, attach, optionally serve admin, and hold until Ctrl-C.
pub async fn run(cfg: GuardConfig) -> anyhow::Result<()> {
    let guard = Guard::attach(cfg).await?;
    println!("Waiting for Ctrl-C...");
    guard
        .hold(async {
            let _ = signal::ctrl_c().await;
        })
        .await?;
    println!("Exiting...");
    Ok(())
}
