#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::bpf_ktime_get_ns,
    macros::{cgroup_skb, map},
    maps::{HashMap, LruHashMap, RingBuf},
    programs::SkBuffContext,
};
use aya_log_ebpf::info;
use pasu_ebpf_common::DropEvent;

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

// 막은 egress 를 유저스페이스로 올린다. 감사(audit) 용도이며, 여기서 실패해도
// 차단 판정에는 영향이 없다 — 기록을 잃을지언정 통과시키지 않는다.
#[map]
static DROPS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// 목적지별 마지막 보고 시각(ns)과 그 뒤 억제한 건수.
//
// 드롭은 패킷마다 난다. 차단된 연결 하나가 SYN 을 재전송하면 같은 목적지로
// 수십 건이 쏟아진다. 목적지마다 짧은 창 안에서는 한 번만 올리고, 억제한
// 건수를 다음 이벤트에 실어 보낸다. LRU 라 맵이 가득 차도 오래된 항목이
// 밀려날 뿐 차단은 계속된다.
#[map]
static SEEN: LruHashMap<u64, SeenEntry> = LruHashMap::with_max_entries(1024, 0);

/// 목적지별 억제 상태.
#[repr(C)]
#[derive(Clone, Copy)]
struct SeenEntry {
    /// 마지막으로 유저스페이스에 올린 시각(ns).
    last_ns: u64,
    /// 그 뒤 억제한 건수.
    suppressed: u32,
    _pad: u32,
}

/// 같은 목적지를 다시 보고하기까지의 최소 간격. 5초.
const SUPPRESS_NS: u64 = 5_000_000_000;

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
    // IHL(하위 4비트)로 가변 길이 IPv4 헤더를 건너뛰어 L4 를 찾는다.
    let ihl = (ctx.load::<u8>(0).map_err(|_| ())? & 0x0f) as usize;
    let proto = ctx.load::<u8>(9).map_err(|_| ())?;
    let port = dst_port(ctx, proto, ihl * 4);

    let mut addr = [0u8; 16];
    let be = dst.to_be_bytes();
    addr[0] = be[0];
    addr[1] = be[1];
    addr[2] = be[2];
    addr[3] = be[3];
    report_drop(4, addr, proto, port);

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
    // IPv6 기본 헤더는 40바이트 고정. 확장 헤더가 있으면 next header 가
    // TCP/UDP 가 아니므로 포트는 0 으로 남는다(잘못된 값을 싣지 않는다).
    let proto = ctx.load::<u8>(6).map_err(|_| ())?;
    let port = dst_port(ctx, proto, 40);

    let mut addr = [0u8; 16];
    let hi_be = hi.to_be_bytes();
    let lo_be = lo.to_be_bytes();
    let mut i = 0;
    while i < 8 {
        addr[i] = hi_be[i];
        addr[i + 8] = lo_be[i];
        i += 1;
    }
    report_drop(6, addr, proto, port);

    info!(ctx, "pasu: dropped IPv6 egress (dst not in ALLOW6 map)");
    Ok(0) // default-deny → drop
}

/// L4 목적지 포트를 읽는다. TCP/UDP 가 아니거나 헤더를 못 읽으면 `(proto, 0)`.
///
/// TCP·UDP 모두 헤더 앞 4바이트가 `src_port(2) + dst_port(2)` 라 오프셋이 같다.
fn dst_port(ctx: &SkBuffContext, proto: u8, l4_off: usize) -> u16 {
    if proto != 6 && proto != 17 {
        return 0;
    }
    match ctx.load::<u16>(l4_off + 2) {
        Ok(p) => u16::from_be(p),
        Err(_) => 0,
    }
}

/// 막은 egress 를 유저스페이스로 올린다. 같은 목적지의 반복은 억제한다.
///
/// 이 함수는 실패해도 조용히 넘어간다 — 감사 기록을 잃는 것이 차단을 놓치는
/// 것보다 낫고, 여기서 에러를 올리면 드롭 경로가 복잡해진다.
fn report_drop(family: u8, addr: [u8; 16], protocol: u8, port: u16) {
    // 목적지를 하나의 키로 접는다(주소 16바이트 → u64 두 개를 XOR).
    let mut hi: u64 = 0;
    let mut lo: u64 = 0;
    let mut i = 0;
    while i < 8 {
        hi = (hi << 8) | addr[i] as u64;
        lo = (lo << 8) | addr[i + 8] as u64;
        i += 1;
    }
    let key = hi ^ lo ^ (port as u64);

    let now = unsafe { bpf_ktime_get_ns() };
    let mut suppressed = 0u32;

    if let Some(prev) = unsafe { SEEN.get(&key) } {
        if now.wrapping_sub(prev.last_ns) < SUPPRESS_NS {
            // 창 안이다: 올리지 않고 건수만 센다.
            let entry = SeenEntry {
                last_ns: prev.last_ns,
                suppressed: prev.suppressed.saturating_add(1),
                _pad: 0,
            };
            let _ = SEEN.insert(&key, &entry, 0);
            return;
        }
        suppressed = prev.suppressed;
    }

    let entry = SeenEntry {
        last_ns: now,
        suppressed: 0,
        _pad: 0,
    };
    let _ = SEEN.insert(&key, &entry, 0);

    if let Some(mut slot) = DROPS.reserve::<DropEvent>(0) {
        slot.write(DropEvent {
            family,
            protocol,
            port,
            addr,
            suppressed,
        });
        slot.submit(0);
    }
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";
