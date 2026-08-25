//! Platform shutdown signal bridge.

use std::io;

use tokio_util::sync::CancellationToken;

/// Creates a token cancelled by Ctrl-C, Unix SIGTERM, or Windows Ctrl-Break.
/// This matches the Go process' `signal.NotifyContext` boundary while also
/// allowing a service manager or isolated test process group to stop only this
/// agent on Windows.
pub fn cancellation_token() -> CancellationToken {
    let token = CancellationToken::new();
    let signal_token = token.clone();
    tokio::spawn(async move {
        if let Err(error) = wait_for_signal().await {
            log::error!("监听停止信号失败：{error}");
        }
        signal_token.cancel();
    });
    token
}

#[cfg(unix)]
async fn wait_for_signal() -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(windows)]
async fn wait_for_signal() -> io::Result<()> {
    use tokio::signal::windows::{ctrl_break, ctrl_c};

    let mut interrupt = ctrl_c()?;
    let mut terminate = ctrl_break()?;
    tokio::select! {
        _ = interrupt.recv() => Ok(()),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(all(not(unix), not(windows)))]
async fn wait_for_signal() -> io::Result<()> {
    tokio::signal::ctrl_c().await
}
