//! Platform shutdown signal bridge.

use std::io;

use tokio_util::sync::CancellationToken;

/// Creates a token cancelled by Ctrl-C, Unix SIGTERM, or Windows Ctrl-Break.
/// This matches the Go process' `signal.NotifyContext` boundary while also
/// allowing a service manager or isolated test process group to stop only this
/// agent on Windows. A second signal forces exit if graceful shutdown is stuck.
pub fn cancellation_token() -> CancellationToken {
    let token = CancellationToken::new();
    let signal_token = token.clone();
    let signals = ShutdownSignals::new();
    tokio::spawn(async move {
        if let Err(error) = watch_signals(signals, &signal_token).await {
            log::error!("监听停止信号失败：{error}");
            signal_token.cancel();
        }
    });
    token
}

async fn watch_signals(
    signals: io::Result<ShutdownSignals>,
    token: &CancellationToken,
) -> io::Result<()> {
    let mut signals = signals?;
    signals.recv().await?;
    token.cancel();
    // Tokio keeps its process-wide handlers installed after a listener drops.
    // Retain the same listeners and explicitly implement Go's restored default
    // behavior instead of silently consuming a second shutdown signal.
    let exit_code = signals.recv().await?;
    std::process::exit(exit_code);
}

#[cfg(unix)]
struct ShutdownSignals {
    interrupt: tokio::signal::unix::Signal,
    terminate: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())?,
            terminate: signal(SignalKind::terminate())?,
        })
    }

    async fn recv(&mut self) -> io::Result<i32> {
        tokio::select! {
            signal = self.interrupt.recv() => signal.map(|()| 128 + libc::SIGINT),
            signal = self.terminate.recv() => signal.map(|()| 128 + libc::SIGTERM),
        }
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shutdown signal stream closed",
            )
        })
    }
}

#[cfg(windows)]
struct ShutdownSignals {
    interrupt: tokio::signal::windows::CtrlC,
    terminate: tokio::signal::windows::CtrlBreak,
}

#[cfg(windows)]
impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        use tokio::signal::windows::{ctrl_break, ctrl_c};
        Ok(Self {
            interrupt: ctrl_c()?,
            terminate: ctrl_break()?,
        })
    }

    async fn recv(&mut self) -> io::Result<i32> {
        tokio::select! {
            signal = self.interrupt.recv() => signal,
            signal = self.terminate.recv() => signal,
        }
        .map(|()| 130)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shutdown signal stream closed",
            )
        })
    }
}

#[cfg(all(not(unix), not(windows)))]
struct ShutdownSignals;

#[cfg(all(not(unix), not(windows)))]
impl ShutdownSignals {
    fn new() -> io::Result<Self> {
        Ok(Self)
    }

    async fn recv(&mut self) -> io::Result<i32> {
        tokio::signal::ctrl_c().await.map(|()| 130)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    struct ChildGuard(Child);

    impl Drop for ChildGuard {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn wait_for_file(path: &Path, child: &mut Child) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !path.exists() {
            assert!(
                child.try_wait().unwrap().is_none(),
                "signal child exited early"
            );
            assert!(
                Instant::now() < deadline,
                "signal child did not reach {}",
                path.display()
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[test]
    fn second_signal_forces_exit_after_graceful_shutdown_starts() {
        const CHILD_DIRECTORY: &str = "ACP_SECOND_SIGNAL_TEST_DIRECTORY";
        if let Some(directory) = std::env::var_os(CHILD_DIRECTORY) {
            let directory = std::path::PathBuf::from(directory);
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let token = super::cancellation_token();
                    std::fs::write(directory.join("ready"), "").unwrap();
                    token.cancelled().await;
                    std::fs::write(directory.join("stopping"), "").unwrap();
                    std::future::pending::<()>().await;
                });
            unreachable!();
        }

        for second_signal in [libc::SIGINT, libc::SIGTERM] {
            let directory = tempfile::tempdir().unwrap();
            let mut child = ChildGuard(
                Command::new(std::env::current_exe().unwrap())
                    .args([
                        "--exact",
                        "shutdown::tests::second_signal_forces_exit_after_graceful_shutdown_starts",
                    ])
                    .env(CHILD_DIRECTORY, directory.path())
                    .stdout(Stdio::null())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .unwrap(),
            );
            wait_for_file(&directory.path().join("ready"), &mut child.0);
            // Only the child PID is signalled; never the test runner's group.
            assert_eq!(
                unsafe { libc::kill(child.0.id() as libc::pid_t, libc::SIGTERM) },
                0
            );
            wait_for_file(&directory.path().join("stopping"), &mut child.0);
            assert!(child.0.try_wait().unwrap().is_none());
            assert_eq!(
                unsafe { libc::kill(child.0.id() as libc::pid_t, second_signal) },
                0
            );
            let deadline = Instant::now() + Duration::from_secs(5);
            let status = loop {
                if let Some(status) = child.0.try_wait().unwrap() {
                    break status;
                }
                assert!(
                    Instant::now() < deadline,
                    "second signal did not force exit"
                );
                std::thread::sleep(Duration::from_millis(10));
            };
            assert_eq!(status.code(), Some(128 + second_signal));
        }
    }
}
