//! 종료 신호 대기.
//!
//! 컨테이너·systemd는 **SIGTERM**으로 종료를 알리고, 유예 시간이 지나면
//! SIGKILL로 죽인다. SIGINT(Ctrl-C)만 기다리면 정상 종료 경로를 타지 못한다.
//! (pasu-egress 의 경우 eBPF 프로그램 detach 가 일어나지 않는다.)
//!
//! 같은 헬퍼가 pasu-egress 에도 있다. 두 crate 는 서로 의존하지 않고
//! (egress 는 aya·eBPF 를 끌고 온다), pasu-core 는 순수하게 유지해야 하므로
//! 짧은 중복을 택했다.

/// SIGINT 또는 SIGTERM 중 먼저 오는 것을 기다린다.
pub async fn signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            // 신호를 걸 수 없으면 SIGINT 쪽만 기다린다(영원히 pending).
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
