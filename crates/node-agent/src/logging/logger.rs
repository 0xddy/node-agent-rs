//! Process-wide logger with bounded, asynchronous local output.

use std::backtrace::Backtrace;
use std::fmt::{self, Write as _};
use std::io::{self, Write as _};
use std::panic::PanicHookInfo;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, RwLock, TryLockError};
use std::time::Duration;

use log::{Level, LevelFilter, Log, Metadata, Record};

use super::writer::{CLOSE_WAIT, LocalWriter, MAX_LINE_BYTES};
use super::{
    DEFAULT_LOG_FILE_PATH, DEFAULT_MAX_LOG_BACKUPS, DEFAULT_MAX_LOG_FILE_BYTES, RotatingFile,
    publish_remote,
};

struct LoggerState {
    configured: bool,
    debug_enabled: bool,
    file: Option<Arc<RotatingFile>>,
    writer: Option<Arc<LocalWriter>>,
}

struct AgentLogger {
    state: RwLock<LoggerState>,
}

static LOGGER: AgentLogger = AgentLogger {
    state: RwLock::new(LoggerState {
        configured: false,
        debug_enabled: false,
        file: None,
        writer: None,
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

    {
        let mut state = LOGGER
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let writer = match state.writer.as_ref() {
            Some(writer) if !writer.finished() => {
                writer.replace_file(Arc::clone(&file))?;
                Arc::clone(writer)
            }
            _ => LocalWriter::spawn(io::stdout(), Some(Arc::clone(&file)))?,
        };
        state.writer = Some(writer);
        state.file = Some(file);
        state.configured = true;
        state.debug_enabled = debug_mode;
    }
    log::set_max_level(if debug_mode {
        LevelFilter::Debug
    } else {
        LevelFilter::Info
    });
    Ok(())
}

/// Stops admission and waits up to two seconds for queued local logs. A stalled
/// writer remains the sole writer until it exits; configuration will return
/// `WouldBlock` instead of creating additional blocked threads.
pub fn close() {
    let writer = {
        let mut state = LOGGER
            .state
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.configured = false;
        state.debug_enabled = false;
        let writer = state.writer.clone();
        if let Some(writer) = &writer {
            writer.seal();
        }
        state.file.take();
        writer
    };
    log::set_max_level(LevelFilter::Info);
    if let Some(writer) = writer {
        writer.wait_finished(CLOSE_WAIT);
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
        let (configured, debug_mode, writer) = {
            let state = self
                .state
                .read()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            (state.configured, state.debug_enabled, state.writer.clone())
        };
        if !enabled(record.level(), debug_mode) {
            return;
        }

        let now = chrono::Local::now();
        let timestamp = now.format("%Y/%m/%d %H:%M:%S%.6f");
        let level_prefix = match record.level() {
            Level::Debug | Level::Trace => "[debug] ",
            _ => "",
        };
        let mut line = BoundedLine::new();
        let _ = write!(line, "{timestamp} {level_prefix}{}", record.args());
        let line = line.finish();

        // A stalled local sink cannot block a live panel subscriber. Both queues
        // have independent bounds, and no output I/O runs on this calling thread.
        if configured {
            publish_remote("node-agent", &line);
        }
        if let Some(writer) = writer {
            writer.enqueue(line);
        }
    }

    fn flush(&self) {
        let writer = self
            .state
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .writer
            .clone();
        // Coalesce flush requests; normal callers never wait behind output I/O.
        // `close` is the bounded, draining shutdown operation.
        if let Some(writer) = writer {
            writer.request_flush();
        }
    }
}

impl AgentLogger {
    fn write_panic(&self, report: &str) {
        let timestamp = chrono::Local::now().format("%Y/%m/%d %H:%M:%S%.6f");
        let line = format!("{timestamp} {report}\n");

        // A panic may happen under a logger/file lock. Even an unlocked file or
        // pipe can stall in the OS, so emergency I/O gets a separate thread and a
        // short deadline before the hook exits the process.
        let file = match self.state.try_read() {
            Ok(state) => state.file.clone(),
            Err(TryLockError::Poisoned(poisoned)) => {
                let state = poisoned.into_inner();
                state.file.clone()
            }
            Err(TryLockError::WouldBlock) => None,
        };
        let (done, finished) = std::sync::mpsc::sync_channel(1);
        let spawned = std::thread::Builder::new()
            .name("node-agent-panic-log".into())
            .spawn(move || {
                if let Some(file) = file {
                    let _ = file.try_write_all(line.as_bytes());
                    let _ = file.try_sync();
                }
                let _ = io::stderr().lock().write_all(line.as_bytes());
                let _ = io::stderr().lock().flush();
                let _ = done.send(());
            });
        if spawned.is_ok() {
            let _ = finished.recv_timeout(Duration::from_millis(250));
        }
    }
}

/// Bound allocation while formatting, rather than allocating an arbitrary
/// `Display` result and truncating it afterwards.
struct BoundedLine {
    text: String,
    truncated: bool,
}

impl BoundedLine {
    fn new() -> Self {
        Self {
            text: String::new(),
            truncated: false,
        }
    }

    fn finish(mut self) -> String {
        if self.truncated {
            const SUFFIX: &str = " [truncated]";
            let mut end = self.text.len().min(MAX_LINE_BYTES - 1 - SUFFIX.len());
            while !self.text.is_char_boundary(end) {
                end -= 1;
            }
            self.text.truncate(end);
            self.reserve(SUFFIX.len() + 1);
            self.text.push_str(SUFFIX);
        }
        self.reserve(1);
        self.text.push('\n');
        self.text.into_boxed_str().into_string()
    }

    fn reserve(&mut self, additional: usize) {
        let required = self.text.len() + additional;
        if required > self.text.capacity() {
            let capacity = required
                .max(self.text.capacity().saturating_mul(2))
                .min(MAX_LINE_BYTES);
            self.text.reserve_exact(capacity - self.text.len());
        }
    }
}

impl fmt::Write for BoundedLine {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        let available = MAX_LINE_BYTES - 1 - self.text.len();
        let mut end = available.min(text.len());
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        self.reserve(end);
        self.text.push_str(&text[..end]);
        self.truncated |= end != text.len();
        Ok(())
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
    fn formatting_bounds_large_utf8_lines_before_queueing() {
        let mut line = BoundedLine::new();
        for _ in 0..MAX_LINE_BYTES {
            write!(line, "界").unwrap();
            assert!(line.text.capacity() <= MAX_LINE_BYTES);
        }
        let line = line.finish();
        assert!(line.len() <= MAX_LINE_BYTES);
        assert_eq!(line.len(), line.capacity());
        assert!(line.ends_with(" [truncated]\n"));

        let mut short = BoundedLine::new();
        write!(short, "hello {}", 42).unwrap();
        assert_eq!(short.finish(), "hello 42\n");
    }

    #[test]
    fn a_stalled_local_writer_does_not_block_remote_logs() {
        use std::sync::mpsc;

        struct BlockedOutput {
            entered: Option<mpsc::SyncSender<()>>,
            release: mpsc::Receiver<()>,
        }
        impl io::Write for BlockedOutput {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                if let Some(entered) = self.entered.take() {
                    entered.send(()).unwrap();
                    self.release.recv().unwrap();
                }
                Ok(bytes.len())
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let writer = LocalWriter::spawn(
            BlockedOutput {
                entered: Some(entered_tx),
                release: release_rx,
            },
            None,
        )
        .unwrap();
        writer.enqueue(String::from("blocked\n"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        let logger = AgentLogger {
            state: RwLock::new(LoggerState {
                configured: true,
                debug_enabled: false,
                file: None,
                writer: Some(Arc::clone(&writer)),
            }),
        };
        let subscription = super::super::subscribe_remote();
        logger.log(
            &Record::builder()
                .level(Level::Info)
                .args(format_args!("remote survives blocked local output"))
                .build(),
        );
        let (lines, _) = subscription.drain(1024, 1 << 20);
        assert!(
            lines
                .iter()
                .any(|line| line.text.contains("remote survives blocked local output"))
        );
        writer.seal();
        release_tx.send(()).unwrap();
        assert!(writer.wait_finished(Duration::from_secs(2)));
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
