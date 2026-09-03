//! One bounded producer queue and one blocking output thread.

use std::collections::VecDeque;
use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use super::RotatingFile;

pub(super) const MAX_LINES: usize = 1024;
pub(super) const MAX_BYTES: usize = 1 << 20;
pub(super) const MAX_LINE_BYTES: usize = 32 << 10;
const MAX_FILE_CHANGES: usize = 4;
pub(super) const CLOSE_WAIT: Duration = Duration::from_secs(2);

enum Command {
    Line(String),
    File(WorkerFile),
}

/// An admitted file is explicitly closed by its owning output thread, even if
/// a panic unwinds a command before it becomes the active file.
struct WorkerFile(Arc<RotatingFile>);

impl Drop for WorkerFile {
    fn drop(&mut self) {
        let _ = self.0.close();
    }
}

#[derive(Default)]
struct QueueState {
    commands: VecDeque<Command>,
    lines: usize,
    bytes: usize,
    file_changes: usize,
    dropped: u64,
    flush_requested: bool,
    closing: bool,
    finished: bool,
}

#[derive(Default)]
struct Shared {
    state: Mutex<QueueState>,
    changed: Condvar,
}

impl Shared {
    fn state(&self) -> MutexGuard<'_, QueueState> {
        self.state.lock().unwrap_or_else(|error| error.into_inner())
    }
}

/// The thread owns only `Shared`, never the logger or this handle. A closing
/// writer stays installed until `finished`, so repeated configure/close calls
/// cannot accumulate blocked output threads.
pub(super) struct LocalWriter {
    shared: Arc<Shared>,
}

impl LocalWriter {
    pub(super) fn spawn(
        output: impl Write + Send + 'static,
        file: Option<Arc<RotatingFile>>,
    ) -> io::Result<Arc<Self>> {
        let shared = Arc::new(Shared::default());
        let worker_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("node-agent-log-writer".into())
            .spawn(move || run_writer(worker_shared, output, file))?;
        Ok(Arc::new(Self { shared }))
    }

    pub(super) fn enqueue(&self, line: String) {
        debug_assert!(line.len() <= MAX_LINE_BYTES);
        debug_assert_eq!(line.capacity(), line.len());
        let mut state = self.shared.state();
        if state.closing || state.finished {
            return;
        }
        // Drop old local records instead of waiting for stdout or a full disk.
        // Control commands keep their order and are never discarded.
        while state.lines >= MAX_LINES || state.bytes + line.len() > MAX_BYTES {
            let Some(index) = state
                .commands
                .iter()
                .position(|command| matches!(command, Command::Line(_)))
            else {
                return;
            };
            if let Some(Command::Line(old)) = state.commands.remove(index) {
                state.lines -= 1;
                state.bytes -= old.len();
                state.dropped = state.dropped.saturating_add(1);
            }
        }
        state.bytes += line.len();
        state.lines += 1;
        state.commands.push_back(Command::Line(line));
        drop(state);
        self.shared.changed.notify_all();
    }

    pub(super) fn replace_file(&self, file: Arc<RotatingFile>) -> io::Result<()> {
        let mut state = self.shared.state();
        if state.closing || state.finished {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "previous log writer is still closing",
            ));
        }
        if state.file_changes >= MAX_FILE_CHANGES {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "log output is stalled; pending file changes are full",
            ));
        }
        state.commands.push_back(Command::File(WorkerFile(file)));
        state.file_changes += 1;
        drop(state);
        self.shared.changed.notify_all();
        Ok(())
    }

    pub(super) fn request_flush(&self) {
        let mut state = self.shared.state();
        state.flush_requested = true;
        drop(state);
        self.shared.changed.notify_all();
    }

    pub(super) fn seal(&self) {
        let mut state = self.shared.state();
        state.closing = true;
        drop(state);
        self.shared.changed.notify_all();
    }

    pub(super) fn finished(&self) -> bool {
        self.shared.state().finished
    }

    pub(super) fn wait_finished(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut state = self.shared.state();
        while !state.finished {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return false;
            };
            let (next, _) = self
                .shared
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(|error| error.into_inner());
            state = next;
        }
        true
    }
}

impl Drop for LocalWriter {
    fn drop(&mut self) {
        self.seal();
    }
}

/// Also runs while unwinding a writer panic. Close every admitted file here,
/// before publishing completion, even when the logger still holds a panic-path
/// Arc. Its eventual drop on a producer thread then has no file left to sync.
struct WorkerResources {
    shared: Arc<Shared>,
    file: Option<WorkerFile>,
}

impl Drop for WorkerResources {
    fn drop(&mut self) {
        let pending = {
            let mut state = self.shared.state();
            state.closing = true;
            state.lines = 0;
            state.bytes = 0;
            state.file_changes = 0;
            std::mem::take(&mut state.commands)
        };
        drop(self.file.take());
        drop(pending);
        self.shared.state().finished = true;
        self.shared.changed.notify_all();
    }
}

fn run_writer(shared: Arc<Shared>, mut output: impl Write, file: Option<Arc<RotatingFile>>) {
    let mut resources = WorkerResources {
        shared: Arc::clone(&shared),
        file: file.map(WorkerFile),
    };
    loop {
        let (command, dropped, flush, closing) = {
            let mut state = shared.state();
            while state.commands.is_empty() && !state.closing && !state.flush_requested {
                state = shared
                    .changed
                    .wait(state)
                    .unwrap_or_else(|error| error.into_inner());
            }
            let command = state.commands.pop_front();
            match &command {
                Some(Command::Line(line)) => {
                    state.lines -= 1;
                    state.bytes -= line.len();
                }
                Some(Command::File(_)) => state.file_changes -= 1,
                None => {}
            }
            let dropped = std::mem::take(&mut state.dropped);
            let flush = command.is_none() && std::mem::take(&mut state.flush_requested);
            let closing = command.is_none() && state.closing;
            (command, dropped, flush, closing)
        };

        // All actual output, rotation, sync and final file drops happen here,
        // after releasing the producer mutex.
        if dropped != 0 {
            write_line(
                &mut output,
                resources.file.as_ref().map(|file| file.0.as_ref()),
                &format!("[logging] dropped {dropped} local log lines: output queue full\n"),
            );
        }
        match command {
            Some(Command::Line(line)) => write_line(
                &mut output,
                resources.file.as_ref().map(|file| file.0.as_ref()),
                &line,
            ),
            Some(Command::File(next)) => {
                drop(resources.file.replace(next));
            }
            None => {}
        }
        if flush || closing {
            let _ = output.flush();
            if !closing && let Some(file) = &resources.file {
                let _ = file.0.sync();
            }
        }
        if closing {
            // WorkerResources closes/syncs once and then marks the thread done.
            return;
        }
    }
}

fn write_line(output: &mut impl Write, file: Option<&RotatingFile>, line: &str) {
    let _ = output.write_all(line.as_bytes());
    if let Some(file) = file
        && let Err(error) = file.write_all(line.as_bytes())
    {
        let _ = writeln!(io::stderr().lock(), "write log file: {error}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    struct BlockedOutput {
        entered: Option<mpsc::SyncSender<()>>,
        release: mpsc::Receiver<()>,
        bytes: Arc<Mutex<Vec<u8>>>,
    }

    impl Write for BlockedOutput {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            if let Some(entered) = self.entered.take() {
                entered.send(()).unwrap();
                self.release.recv().unwrap();
            }
            self.bytes.lock().unwrap().extend_from_slice(data);
            Ok(data.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    type BlockedWriter = (
        Arc<LocalWriter>,
        mpsc::Receiver<()>,
        mpsc::SyncSender<()>,
        Arc<Mutex<Vec<u8>>>,
    );

    fn blocked_writer() -> BlockedWriter {
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let writer = LocalWriter::spawn(
            BlockedOutput {
                entered: Some(entered_tx),
                release: release_rx,
                bytes: Arc::clone(&bytes),
            },
            None,
        )
        .unwrap();
        (writer, entered_rx, release_tx, bytes)
    }

    #[test]
    fn stalled_output_has_bounded_memory_and_does_not_block_producers() {
        let (writer, entered, release, bytes) = blocked_writer();
        writer.enqueue(String::from("first\n"));
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        for _ in 0..MAX_LINES * 2 {
            writer.enqueue("x".repeat(MAX_LINE_BYTES));
        }
        {
            let state = writer.shared.state();
            assert_eq!(state.bytes, MAX_BYTES);
            assert_eq!(state.lines, MAX_BYTES / MAX_LINE_BYTES);
            assert_eq!(state.dropped, (MAX_LINES * 2 - state.lines) as u64);
        }
        writer.seal();
        assert!(!writer.wait_finished(Duration::from_millis(10)));
        writer.enqueue(String::from("after close\n"));
        release.send(()).unwrap();
        assert!(writer.wait_finished(Duration::from_secs(2)));
        let bytes = bytes.lock().unwrap();
        let text = String::from_utf8_lossy(&bytes);
        assert!(text.starts_with("first\n"));
        assert!(text.contains("local log lines: output queue full"));
        assert!(!text.contains("after close"));
    }

    #[test]
    fn close_drains_queued_lines_and_file_changes_in_order() {
        let temp = tempfile::tempdir().unwrap();
        let first_path = temp.path().join("first.log");
        let second_path = temp.path().join("second.log");
        let first = Arc::new(RotatingFile::open(&first_path, 1024, 0).unwrap());
        let second = Arc::new(RotatingFile::open(&second_path, 1024, 0).unwrap());
        let writer = LocalWriter::spawn(io::sink(), Some(Arc::clone(&first))).unwrap();
        writer.enqueue(String::from("before\n"));
        writer.replace_file(Arc::clone(&second)).unwrap();
        writer.enqueue(String::from("after\n"));
        writer.seal();
        // Test durability/order, not host disk latency. The production close
        // timeout is tested separately with a deliberately blocked output.
        assert!(writer.wait_finished(Duration::from_secs(15)));
        assert_eq!(std::fs::read_to_string(first_path).unwrap(), "before\n");
        assert_eq!(std::fs::read_to_string(second_path).unwrap(), "after\n");
        assert_eq!(
            first.write_all(b"closed").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            second.write_all(b"closed").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }

    #[test]
    fn stalled_file_changes_are_bounded_and_closing_rejects_reconfiguration() {
        let (writer, entered, release, _) = blocked_writer();
        writer.enqueue(String::from("first\n"));
        entered.recv_timeout(Duration::from_secs(1)).unwrap();
        let temp = tempfile::tempdir().unwrap();
        let file = Arc::new(RotatingFile::open(temp.path().join("out.log"), 1024, 0).unwrap());
        for _ in 0..MAX_FILE_CHANGES {
            writer.replace_file(Arc::clone(&file)).unwrap();
        }
        assert_eq!(
            writer.replace_file(Arc::clone(&file)).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        writer.seal();
        assert_eq!(
            writer.replace_file(file).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );
        release.send(()).unwrap();
        assert!(writer.wait_finished(Duration::from_secs(15)));
    }

    #[test]
    fn writer_panic_closes_active_and_pending_files_and_publishes_completion() {
        struct PanicOutput {
            entered: mpsc::SyncSender<()>,
            release: mpsc::Receiver<()>,
        }
        impl Write for PanicOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                self.entered.send(()).unwrap();
                self.release.recv().unwrap();
                panic!("injected output panic");
            }

            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }

        let temp = tempfile::tempdir().unwrap();
        let active = Arc::new(RotatingFile::open(temp.path().join("active.log"), 1024, 0).unwrap());
        let pending =
            Arc::new(RotatingFile::open(temp.path().join("pending.log"), 1024, 0).unwrap());
        let (entered_tx, entered_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let writer = LocalWriter::spawn(
            PanicOutput {
                entered: entered_tx,
                release: release_rx,
            },
            Some(Arc::clone(&active)),
        )
        .unwrap();
        writer.enqueue(String::from("panic\n"));
        entered_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        writer.replace_file(Arc::clone(&pending)).unwrap();
        writer.enqueue(String::from("discarded\n"));
        release_tx.send(()).unwrap();
        assert!(writer.wait_finished(Duration::from_secs(15)));
        assert!(writer.finished());
        assert!(writer.shared.state().commands.is_empty());
        // These Arcs model the logger's panic-path handle. The writer must have
        // closed both files before their final owners can drop on another thread.
        assert_eq!(
            active.write_all(b"closed").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            pending.write_all(b"closed").unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
