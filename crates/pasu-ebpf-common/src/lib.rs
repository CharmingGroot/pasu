#![no_std]

//! 커널 프로그램과 유저스페이스가 공유하는 타입.

/// 커널이 막은 egress 한 건. ring buffer 로 유저스페이스에 올라간다.
///
/// `#[repr(C)]` 이며 포인터를 담지 않는다 — 커널이 쓴 바이트를 그대로 읽는다.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DropEvent {
    /// 주소 계열: 4 또는 6.
    pub family: u8,
    /// L4 프로토콜 번호(6=TCP, 17=UDP). 그 외는 0.
    pub protocol: u8,
    /// 목적지 포트. TCP/UDP 가 아니거나 헤더를 못 읽으면 0.
    pub port: u16,
    /// 목적지 주소. IPv4 는 앞 4바이트만 쓴다(네트워크 바이트 순서).
    pub addr: [u8; 16],
    /// 이 이벤트 직전, 같은 목적지로 억제된 드롭 수.
    ///
    /// 커널은 목적지마다 짧은 창 안의 반복을 억제한다(재전송 SYN 하나가
    /// 수십 건의 감사 로그가 되는 것을 막는다). 억제된 건수를 함께 실어
    /// "몇 건이 더 있었는지"를 잃지 않는다.
    pub suppressed: u32,
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for DropEvent {}
