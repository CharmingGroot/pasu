#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

// M1: default-deny allowlist. IPv4 destinations allowed to egress (host byte order)
// are injected from user space (control plane); anything else is dropped.
//
// Because unlisted traffic is dropped, this MUST be attached to a dedicated cgroup,
// NEVER the root cgroup (that would cut the host's own egress, including SSH).
#[map]
static ALLOW: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);

#[cgroup_skb]
pub fn pasu_egress(ctx: SkBuffContext) -> i32 {
    match try_pasu_egress(ctx) {
        Ok(ret) => ret,
        Err(_) => 0, // parse failure → drop (default-deny: fail closed)
    }
}

fn try_pasu_egress(ctx: SkBuffContext) -> Result<i32, ()> {
    // cgroup_skb egress: the packet begins at the IPv4 header (L3, no ethernet frame).
    // byte 0 = version/IHL; bytes 16..20 = destination address.
    let ver_ihl: u8 = ctx.load(0).map_err(|_| ())?;
    if ver_ihl >> 4 != 4 {
        // Non-IPv4 (IPv6, etc.) passes — M1 scope is IPv4. (IPv6 egress control is
        // out of scope for now; documented as a known gap.)
        return Ok(1);
    }

    let dst_be: u32 = ctx.load(16).map_err(|_| ())?;
    let dst = u32::from_be(dst_be); // host byte order, matches u32::from(Ipv4Addr)

    // Loopback (127.0.0.0/8) always passes: never break localhost or the DNS
    // resolver, even under default-deny.
    if dst >> 24 == 127 {
        return Ok(1);
    }

    if unsafe { ALLOW.get(&dst) }.is_some() {
        return Ok(1); // allowlisted → pass
    }

    info!(&ctx, "pasu: dropped egress (dst not in ALLOW map)");
    Ok(0) // default-deny → drop
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
