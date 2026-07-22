#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{cgroup_skb, map},
    maps::HashMap,
    programs::SkBuffContext,
};
use aya_log_ebpf::info;

// default-deny allowlist. Destinations allowed to egress are injected from user
// space (control plane); anything else is dropped. IPv4 keys are host-order u32;
// IPv6 keys are the 16-byte address as a big-endian u128 (matches u128::from(Ipv6Addr)).
//
// Because unlisted traffic is dropped, this MUST be attached to a dedicated cgroup,
// NEVER the root cgroup (that would cut the host's own egress, including SSH).
#[map]
static ALLOW: HashMap<u32, u8> = HashMap::with_max_entries(1024, 0);
#[map]
static ALLOW6: HashMap<u128, u8> = HashMap::with_max_entries(1024, 0);

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
    let version: u8 = ctx.load::<u8>(0).map_err(|_| ())? >> 4;
    match version {
        4 => try_v4(&ctx),
        6 => try_v6(&ctx),
        // Neither IPv4 nor IPv6 (ARP already handled below L3; anything else) →
        // drop under default-deny (fail-closed).
        _ => Ok(0),
    }
}

fn try_v4(ctx: &SkBuffContext) -> Result<i32, ()> {
    // IPv4 header (L3, no ethernet frame): bytes 16..20 = destination address.
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
    info!(ctx, "pasu: dropped IPv4 egress (dst not in ALLOW map)");
    Ok(0) // default-deny → drop
}

fn try_v6(ctx: &SkBuffContext) -> Result<i32, ()> {
    // IPv6 header (L3): bytes 24..40 = 16-byte destination address (network order).
    // Load as two u64 halves to keep the verifier happy (64-bit ops only).
    let hi = u64::from_be(ctx.load::<u64>(24).map_err(|_| ())?);
    let lo = u64::from_be(ctx.load::<u64>(32).map_err(|_| ())?);

    // Infrastructure prefixes always pass — dropping them breaks basic v6
    // operation (NDP, on-link), same spirit as the v4 loopback exception:
    //   ::1        loopback
    //   fe80::/10  link-local (NDP, router)
    //   ff00::/8   multicast (NDP solicitations, etc.)
    if (hi == 0 && lo == 1) || (hi >> 54 == 0x3FA) || (hi >> 56 == 0xff) {
        return Ok(1);
    }

    let key: u128 = ((hi as u128) << 64) | (lo as u128); // == u128::from(Ipv6Addr)
    if unsafe { ALLOW6.get(&key) }.is_some() {
        return Ok(1); // allowlisted → pass
    }
    info!(ctx, "pasu: dropped IPv6 egress (dst not in ALLOW6 map)");
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
