//! The kernel guard itself: load the eBPF program, populate the ALLOW map,
//! attach to a cgroup, optionally serve the control-plane admin socket, and
//! hold until shutdown.
//!
//! Extracted from the `pasu-egress` binary so composition roots (the binary,
//! `pasu-daemon`) can run the same guard from different policy sources.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use aya::maps::{
    RingBuf,
    lpm_trie::{Key, LpmTrie},
};
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
#[rustfmt::skip]
use log::{debug, warn};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixListener;
use tokio::signal;
use tokio::sync::{mpsc, oneshot};

use pasu_core::{AuditRecord, AuditSink, Cidr, CidrBytes, Event, EventKind, Verdict};
use pasu_ebpf_common::DropEvent;

use crate::admin::{self, Command, Status};

/// Everything the guard needs to run: where to attach and what to allow.
pub struct GuardConfig {
    /// Dedicated cgroup v2 path (never the root cgroup).
    pub cgroup_path: PathBuf,
    /// Destinations allowed to egress, as ranges. A bare address is a host
    /// route (`/32`, `/128`), so exact entries and CIDR ranges share one list
    /// and both families live in it.
    pub allow: Vec<Cidr>,
    /// Domains whose resolved IPv4s are allowed (re-resolved periodically).
    pub allow_domain: Vec<String>,
    /// Domain re-resolution interval, seconds.
    pub refresh_secs: u64,
    /// Optional control-plane admin socket (unix). None disables it.
    pub admin_socket: Option<PathBuf>,
    /// Where kernel drops are recorded. None keeps the previous behaviour
    /// (the kernel blocks silently).
    ///
    /// 강제 계층이 아무 기록을 남기지 않으면 운영자는 "왜 못 나갔는지"를
    /// 감사 로그로 답할 수 없다. 협조 계층(proxy)은 이미 기록하고 있었다.
    pub audit: Option<Arc<dyn AuditSink>>,
}

impl std::fmt::Debug for GuardConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardConfig")
            .field("cgroup_path", &self.cgroup_path)
            .field("allow", &self.allow)
            .field("allow_domain", &self.allow_domain)
            .field("refresh_secs", &self.refresh_secs)
            .field("admin_socket", &self.admin_socket)
            .field("audit", &self.audit.is_some())
            .finish()
    }
}

/// Resolve a domain to its IP addresses (best-effort; empty on failure). Both
/// families — v4 goes to the ALLOW map, v6 to ALLOW6.
async fn resolve(domain: &str) -> Vec<IpAddr> {
    match tokio::net::lookup_host(format!("{domain}:443")).await {
        Ok(addrs) => addrs.map(|sa| sa.ip()).collect(),
        Err(e) => {
            warn!("resolve {domain} failed: {e}");
            Vec::new()
        }
    }
}

/// Resolve every domain and inject the resulting IPs into the ALLOW/ALLOW6 maps.
async fn refresh_domains(ebpf: &mut aya::Ebpf, domains: &[String]) -> anyhow::Result<()> {
    let mut ips = Vec::new();
    for d in domains {
        ips.extend(resolve(d).await);
    }
    for ip in ips {
        // 해석된 주소는 호스트 라우트(/32·/128)로 넣는다.
        allow_insert(ebpf, Cidr::new(ip, if ip.is_ipv4() { 32 } else { 128 })?)?;
    }
    Ok(())
}

fn allow_insert(ebpf: &mut aya::Ebpf, net: Cidr) -> anyhow::Result<()> {
    let prefix = u32::from(net.prefix_len());
    match net.network_bytes() {
        CidrBytes::V4(bytes) => {
            let mut allow: LpmTrie<_, [u8; 4], u8> =
                LpmTrie::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
            allow.insert(&Key::new(prefix, bytes), 1u8, 0)?;
        }
        CidrBytes::V6(bytes) => {
            let mut allow: LpmTrie<_, [u8; 16], u8> =
                LpmTrie::try_from(ebpf.map_mut("ALLOW6").context("ALLOW6 map not found")?)?;
            allow.insert(&Key::new(prefix, bytes), 1u8, 0)?;
        }
    }
    Ok(())
}

fn allow_remove(ebpf: &mut aya::Ebpf, net: Cidr) -> anyhow::Result<()> {
    let prefix = u32::from(net.prefix_len());
    match net.network_bytes() {
        CidrBytes::V4(bytes) => {
            let mut allow: LpmTrie<_, [u8; 4], u8> =
                LpmTrie::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
            allow.remove(&Key::new(prefix, bytes))?;
        }
        CidrBytes::V6(bytes) => {
            let mut allow: LpmTrie<_, [u8; 16], u8> =
                LpmTrie::try_from(ebpf.map_mut("ALLOW6").context("ALLOW6 map not found")?)?;
            allow.remove(&Key::new(prefix, bytes))?;
        }
    }
    Ok(())
}

/// Live contents of the kernel allowlist, formatted for the admin socket.
///
/// LPM tries iterate as `(prefix_len, bytes)` pairs, so entries come back the
/// way they were written: a range stays a range, a host stays a bare address.
fn allow_list(ebpf: &aya::Ebpf) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(map) = ebpf.map("ALLOW") {
        if let Ok(allow) = <LpmTrie<_, [u8; 4], u8>>::try_from(map) {
            for (key, _) in allow.iter().filter_map(Result::ok) {
                let addr = IpAddr::V4(Ipv4Addr::from(key.data()));
                if let Ok(c) = Cidr::new(addr, key.prefix_len() as u8) {
                    out.push(c.to_string());
                }
            }
        }
    }
    if let Some(map) = ebpf.map("ALLOW6") {
        if let Ok(allow) = <LpmTrie<_, [u8; 16], u8>>::try_from(map) {
            for (key, _) in allow.iter().filter_map(Result::ok) {
                let addr = IpAddr::V6(Ipv6Addr::from(key.data()));
                if let Ok(c) = Cidr::new(addr, key.prefix_len() as u8) {
                    out.push(c.to_string());
                }
            }
        }
    }
    out.sort();
    out
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
/// ring buffer 에서 읽은 바이트를 감사 레코드로 옮긴다.
///
/// 억제된 건수가 있으면 사유에 함께 적는다 — 커널이 창 안의 반복을 눌렀다는
/// 사실 자체가 운영 정보다.
fn record_drop(sink: &dyn AuditSink, ev: &DropEvent) {
    let host = match ev.family {
        4 => Ipv4Addr::new(ev.addr[0], ev.addr[1], ev.addr[2], ev.addr[3]).to_string(),
        6 => Ipv6Addr::from(ev.addr).to_string(),
        other => format!("unknown-family-{other}"),
    };
    let reason = if ev.suppressed > 0 {
        format!(
            "kernel egress drop (not in allowlist); {} more suppressed in the last window",
            ev.suppressed
        )
    } else {
        "kernel egress drop (not in allowlist)".to_string()
    };
    let event = Event {
        kind: EventKind::Egress {
            host,
            port: ev.port,
        },
    };
    sink.record(&AuditRecord::new(
        "ebpf-egress",
        &event,
        &Verdict::Deny(reason),
    ));
}

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

        // Control plane → eBPF: inject the allowed ranges into the LPM tries.
        for net in &cfg.allow {
            allow_insert(&mut ebpf, *net)?;
            println!("allowlist += {net}");
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

        // 커널이 올리는 드롭 이벤트를 감사로 흘린다. sink 가 없으면 맵을
        // 열지 않는다 — 기존 동작(조용한 차단) 그대로다.
        //
        // ring buffer 는 읽을 것이 있을 때만 readable 이 되므로 AsyncFd 로 감싸
        // select 안에 둔다. 여기서 실패해도 차단에는 영향이 없다 — 기록을
        // 잃을지언정 통과시키지 않는다.
        //
        // sink 와 fd 를 따로 두는 이유: select 안에서 fd 를 가변 대여하는 동안
        // 같은 변수를 다시 대여할 수 없다.
        let audit = self.cfg.audit.clone();
        let mut drops = match &audit {
            Some(_) => match self.ebpf.take_map("DROPS") {
                Some(map) => match RingBuf::try_from(map) {
                    Ok(rb) => match tokio::io::unix::AsyncFd::new(rb) {
                        Ok(fd) => Some(fd),
                        Err(e) => {
                            warn!("kernel drop audit disabled (async fd): {e}");
                            None
                        }
                    },
                    Err(e) => {
                        warn!("kernel drop audit disabled (ring buffer): {e}");
                        None
                    }
                },
                None => {
                    warn!("kernel drop audit disabled: DROPS map not found");
                    None
                }
            },
            None => None,
        };

        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                // 드롭 이벤트 배치를 읽어 감사로 남긴다.
                ready = async {
                    match drops.as_mut() {
                        Some(fd) => fd.readable_mut().await.ok(),
                        // sink 가 없으면 이 갈래는 영원히 대기한다.
                        None => std::future::pending().await,
                    }
                }, if drops.is_some() => {
                    if let (Some(mut guard), Some(sink)) = (ready, audit.as_ref()) {
                        let rb = guard.get_inner_mut();
                        while let Some(item) = rb.next() {
                            if item.len() >= core::mem::size_of::<DropEvent>() {
                                // SAFETY: 길이를 확인했고 DropEvent 는 repr(C) Pod 이라
                                // 커널이 쓴 바이트를 그대로 읽어도 된다. 정렬은
                                // read_unaligned 가 처리한다.
                                let ev: DropEvent = unsafe {
                                    core::ptr::read_unaligned(item.as_ptr().cast())
                                };
                                record_drop(sink.as_ref(), &ev);
                            }
                        }
                        guard.clear_ready();
                    }
                }
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

/// Load, populate, attach, optionally serve admin, and hold until a shutdown signal.
pub async fn run(cfg: GuardConfig) -> anyhow::Result<()> {
    let guard = Guard::attach(cfg).await?;
    println!("Waiting for SIGINT/SIGTERM...");
    guard.hold(shutdown_signal()).await?;
    println!("Exiting...");
    Ok(())
}

/// Wait for SIGINT (Ctrl-C) or SIGTERM, whichever comes first.
///
/// Containers and systemd send **SIGTERM**, then SIGKILL after a grace period.
/// Waiting only on SIGINT means the eBPF program is never detached through the
/// normal path — the guard is killed with the cgroup program still attached.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => {}
        () = terminate => {}
    }
}
