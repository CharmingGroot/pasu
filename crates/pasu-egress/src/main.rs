use std::net::Ipv4Addr;

use anyhow::Context as _;
use aya::maps::HashMap as AyaHashMap;
use aya::programs::{CgroupSkb, CgroupSkbAttachType, links::CgroupAttachMode};
use clap::Parser;
#[rustfmt::skip]
use log::{debug, warn};
use tokio::signal;

#[derive(Debug, Parser)]
struct Opt {
    /// cgroup v2 path to attach to. REQUIRED, and must be a dedicated cgroup:
    /// attaching default-deny to the root cgroup would cut the host's own egress
    /// (SSH included). No default on purpose.
    #[clap(short, long)]
    cgroup_path: std::path::PathBuf,
    /// Destination IPv4 allowed to egress (repeatable). Injected into the ALLOW
    /// map (control plane → eBPF). Everything else is dropped (default-deny).
    #[clap(short, long = "allow")]
    allow: Vec<Ipv4Addr>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opt = Opt::parse();

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

    // Control plane → eBPF: inject the allowlist into the ALLOW map.
    {
        let mut allow: AyaHashMap<_, u32, u8> =
            AyaHashMap::try_from(ebpf.map_mut("ALLOW").context("ALLOW map not found")?)?;
        for ip in &opt.allow {
            allow.insert(u32::from(*ip), 1u8, 0)?;
            println!("allowlist += {ip}");
        }
    }

    let cgroup = std::fs::File::open(&opt.cgroup_path)
        .with_context(|| format!("{}", opt.cgroup_path.display()))?;
    let program: &mut CgroupSkb = ebpf.program_mut("pasu_egress").unwrap().try_into()?;
    program.load()?;
    program.attach(
        cgroup,
        CgroupSkbAttachType::Egress,
        CgroupAttachMode::default(),
    )?;

    println!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    println!("Exiting...");

    Ok(())
}
