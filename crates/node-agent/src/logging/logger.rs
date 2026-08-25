//! Process-wide logger feeding stdout, remote subscribers, then the local file.

use std::backtrace::Backtrace;
use std::io::{self, Write as _};
use std::panic::PanicHookInfo;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, RwLock, TryLockError};

use log::{Level, LevelFilter, Log, Metadata, Record};

use super::{
    DEFAULT_LOG_FILE_PATH, DEFAULT_MAX_LOG_BACKUPS, DEFAULT_MAX_LOG_FILE_BYTES, RotatingFile,
    publish_remote,
};

struct LoggerState {
    configured: bool,
    debug_enabled: bool,
    file: Option<Arc<RotatingFile>>,
}

struct AgentLogger {
    state: RwLock<LoggerState>,
}

static LOGGER: AgentLogger = AgentLogger {
    state: RwLock::new(LoggerState {
        configured: false,
        debug_enabled: false,
        file: None,
    }),
};
static INSTALL_LOCK: Mutex<bool> = Mutex::new(false);
static PANIC_HOOK: Once = Once::new();
static PANIC_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

/// Installs (once) and reconfigures the process logger. The local file is opened
/// before the active configuration is swapped, so a failed reconfiguration does
/// not disturb the working logger.
pub fn configure(debug_mode: bool, log_file_path: impl AsRef<Path>) -> io::Result<()> {
    let path = log_file_path.as_ref();
    let path = if path.as_os_str().is_empty() {
        Path::new(DEFAULT_LOG_FILE_PATH)
    } else {
        path
    };
    let file = Arc::new(RotatingFile::open(
        path,
        DEFAULT_MAX_LOG_FILE_BYTES,
        DEFAULT_MAX_LOG_BACKUPS,
    )?);
    install_logger()?;

    let old_file = {
        let mut state = LOGGER
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.configured = true;
        state.debug_enabled = debug_mode;
        state.file.replace(file)
    };
    log::set_max_level(if debug_mode {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    if let Some(old_file) = old_file {
        let _ = old_file.close();
    }
    Ok(())
}

pub fn close() {
    let old_file = {
        let mut state = LOGGER
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.configured = false;
        state.debug_enabled = false;
        state.file.take()
    };
    log::set_max_level(LevelFilter::Info);
    if let Some(file) = old_file {
        let _ = file.close();
    }
}

pub fn debug_enabled() -> bool {
    LOGGER
        .state
        .read()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .debug_enabled
}

/// Installs the process panic boundary used by the Go agent's
/// `RecoverAndExit` wrappers: record and sync the panic, then exit with status
/// 2 without running ordinary shutdown destructors.
///
/// Rust exposes a backtrace for the panicking thread, not a portable snapshot
/// of every process thread. The current thread name is therefore included as
/// the closest stable equivalent to the Go scope label.
pub fn install_panic_hook(default_scope: &'static str) {
    PANIC_HOOK.call_once(|| {
        std::panic::set_hook(Box::new(move |info| {
            if PANIC_IN_PROGRESS.swap(true, Ordering::AcqRel) {
                std::process::exit(2);
            }

            let thread = std::thread::current();
            let scope = thread.name().unwrap_or(default_scope);
            let payload = panic_payload(info);
            let location = info
                .location()
                .map(|location| {
                    format!(
                        "{}:{}:{}",
                        location.file(),
                        location.line(),
                        location.column()
                    )
                })
                .unwrap_or_else(|| "unknown".into());
            let backtrace = Backtrace::force_capture().to_string();
            let report = format_panic_report(scope, &payload, &location, &backtrace);
            LOGGER.write_panic(&report);
            std::process::exit(2);
        }));
    });
}

fn panic_payload(info: &PanicHookInfo<'_>) -> String {
    info.payload()
        .downcast_ref::<&str>()
        .map(|value| (*value).to_owned())
        .or_else(|| info.payload().downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "non-string panic payload".into())
}

fn format_panic_report(scope: &str, payload: &str, location: &str, backtrace: &str) -> String {
    format!("[panic] 范围={scope}，值={payload}\n位置={location}\n{backtrace}")
}

fn install_logger() -> io::Result<()> {
    let mut installed = INSTALL_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if !*installed {
        log::set_logger(&LOGGER)
            .map_err(|error| io::Error::other(format!("install process logger: {error}")))?;
        *installed = true;
    }
    Ok(())
}

impl Log for AgentLogger {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        let state = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        enabled(metadata.level(), state.debug_enabled)
    }

    fn log(&self, record: &Record<'_>) {
        let (configured, debug_mode, file) = {
            let state = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (state.configured, state.debug_enabled, state.file.clone())
        };
        if !enabled(record.level(), debug_mode) {
            return;
        }

        let timestamp = chrono::Local::now().format("%Y/%m/%d %H:%M:%S%.6f");
        let level_prefix = match record.level() {
            Level::Debug | Level::Trace => "[debug] ",
            _ => "",
        };
        let line = format!("{timestamp} {level_prefix}{}\n", record.args());

        // Keep the file last. A full or failed disk must not prevent stdout or
        // a live panel subscriber from receiving the line.
        let _ = io::stdout().lock().write_all(line.as_bytes());
        if configured {
            publish_remote("node-agent", &line);
            if let Some(file) = file
                && let Err(error) = file.write_all(line.as_bytes())
            {
                let _ = writeln!(io::stderr().lock(), "write log file: {error}");
            }
        }
    }

    fn flush(&self) {
        let file = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .file
            .clone();
        let _ = io::stdout().lock().flush();
        if let Some(file) = file {
            let _ = file.sync();
        }
    }
}

impl AgentLogger {
    fn write_panic(&self, report: &str) {
        let timestamp = chrono::Local::now().format("%Y/%m/%d %H:%M:%S%.6f");
        let line = format!("{timestamp} {report}\n");

        // Do not call the normal logger from a panic hook: the panic may have
        // occurred while it held one of these locks. Non-blocking lock attempts
        // preserve the important Go property that the process always exits.
        let _ = io::stdout().lock().write_all(line.as_bytes());
        let _ = io::stdout().lock().flush();
        let (configured, file) = match self.state.try_read() {
            Ok(state) => (state.configured, state.file.clone()),
            Err(TryLockError::Poisoned(poisoned)) => {
                let state = poisoned.into_inner();
                (state.configured, state.file.clone())
            }
            Err(TryLockError::WouldBlock) => {
                let _ = writeln!(
                    io::stderr().lock(),
                    "panic log unavailable: process logger is busy"
                );
                return;
            }
        };
        if !configured {
            let _ = io::stderr().lock().write_all(line.as_bytes());
            return;
        }
        let Some(file) = file else {
            let _ = io::stderr().lock().write_all(line.as_bytes());
            return;
        };
        if let Err(error) = file.try_write_all(line.as_bytes()) {
            let _ = writeln!(io::stderr().lock(), "write panic log file: {error}");
            return;
        }
        if let Err(error) = file.try_sync() {
            let _ = writeln!(io::stderr().lock(), "sync panic log file: {error}");
        }
    }
}

fn enabled(level: Level, debug_mode: bool) -> bool {
    match level {
        Level::Error | Level::Warn | Level::Info => true,
        Level::Debug => debug_mode,
        Level::Trace => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_filter_matches_go_debugf() {
        assert!(enabled(Level::Error, false));
        assert!(enabled(Level::Info, false));
        assert!(!enabled(Level::Debug, false));
        assert!(enabled(Level::Debug, true));
        assert!(!enabled(Level::Trace, true));
    }

    #[test]
    fn panic_report_keeps_the_go_prefix_and_rust_diagnostics() {
        let report = format_panic_report("main", "boom", "main.rs:4:2", "backtrace");
        assert!(report.starts_with("[panic] 范围=main，值=boom\n"));
        assert!(report.contains("位置=main.rs:4:2\n"));
        assert!(report.ends_with("backtrace"));
    }

    #[test]
    fn panic_hook_exits_with_two_and_flushes_log() {
        const CHILD_LOG_PATH: &str = "ACP_RUST_PANIC_TEST_LOG_PATH";
        if let Some(path) = std::env::var_os(CHILD_LOG_PATH) {
            configure(false, Path::new(&path)).unwrap();
            install_panic_hook("main");
            panic!("panic hook child marker");
        }

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("panic.log");
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "logging::logger::tests::panic_hook_exits_with_two_and_flushes_log",
                "--nocapture",
            ])
            .env(CHILD_LOG_PATH, &path)
            .output()
            .unwrap();

        assert_eq!(output.status.code(), Some(2), "child output: {output:?}");
        let log = std::fs::read_to_string(path).unwrap();
        assert!(log.contains("[panic] 范围="));
        assert!(log.contains("，值=panic hook child marker"));
        assert!(log.contains("位置="));
    }
}
