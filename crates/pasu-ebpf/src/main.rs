#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

// M1: dynamic blocklist. Destination IPv4 addresses (host byte order) are injected
// from user space (control plane), replacing the hardcoded single IP. Next step:
// flip to default-deny allowlist under a dedicated test cgroup.
#[map]
static BLOCK: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn pasu_egress(ctx: SkBuffContext) -> i32 {
    match try_pasu_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => 1, // parse error → pass (blocklist blocks only known IPs)
    }
}

fn try_pasu_egress(ctx: SkBuffContext) -> Result<i32, ()> {
    // cgroup_skb egress: the packet begins at the IPv4 header (L3, no ethernet frame).
    // byte 0 = version/IHL; bytes 16..20 = destination address.
    let ver_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    if ver_ihl >> 4 != 4 {
        return Ok(1); // non-IPv4 → pass (M1 scope: IPv4 only)
    }

    let dst_be: u32 = ctx.load(16).map_err(|_| ())?;
    let dst = u32::from_be(dst_be); // host byte order, matches u32::from(Ipv4Addr) in user space

    if unsafe { BLOCK.get(&dst) }.is_some() {
        info!(&ctx, "pasu: blocked egress (dst in BLOCK map)");
        return Ok(0); // drop
    }

    Ok(1) // pass
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
