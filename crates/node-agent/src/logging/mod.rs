//! Local and remotely streamed agent logs.

mod file;
mod logger;
mod remote;
mod stream;
#[cfg(windows)]
mod windows_permissions;
mod writer;

pub use file::{
    DEFAULT_LOG_FILE_PATH, DEFAULT_MAX_LOG_BACKUPS, DEFAULT_MAX_LOG_FILE_BYTES, RotatingFile,
};
pub use logger::{close, configure, debug_enabled, install_panic_hook};
pub use remote::{
    REMOTE_LINE_MAX_BYTES, REMOTE_QUEUE_MAX_BYTES, REMOTE_QUEUE_MAX_LINES, RemoteBroker,
    RemoteLine, RemoteSubscription, publish_remote, remote_source_id, subscribe_remote,
};
pub use stream::{LOG_BATCH_MAX_BYTES, LOG_BATCH_MAX_LINES, LOG_BATCH_WAIT, run_log_stream};
