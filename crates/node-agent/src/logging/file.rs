//! Synchronous bounded log file used by the process logger.
//!
//! Rotation copies into fixed `.1`, `.2`, ... files and truncates the active
//! handle in place. That is intentional: renaming an active file fails when a
//! Windows reader did not grant delete sharing.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, TryLockError};

pub const DEFAULT_LOG_FILE_PATH: &str = "runtime/node-agent.log";
pub const DEFAULT_MAX_LOG_FILE_BYTES: u64 = 16 << 20;
pub const DEFAULT_MAX_LOG_BACKUPS: usize = 3;

struct FileState {
    file: Option<File>,
    size: u64,
}

/// Append-only active log plus fixed numbered backups.
pub struct RotatingFile {
    path: PathBuf,
    max_bytes: u64,
    max_backups: usize,
    state: Mutex<FileState>,
}

impl RotatingFile {
    pub fn open(path: impl AsRef<Path>, max_bytes: u64, max_backups: usize) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        let mut file = open_secure(&path, true, true, false)?;
        let size = file.seek(SeekFrom::End(0))?;
        let rotating = Self {
            path,
            max_bytes,
            max_backups,
            state: Mutex::new(FileState {
                file: Some(file),
                size,
            }),
        };
        rotating.secure_existing_backups()?;
        Ok(rotating)
    }

    fn state(&self) -> MutexGuard<'_, FileState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    pub fn write(&self, data: &[u8]) -> io::Result<usize> {
        let mut state = self.state();
        self.prepare_write(&mut state, data.len())?;
        let file = state.file.as_mut().ok_or_else(closed_error)?;
        file.seek(SeekFrom::End(0))?;
        let written = file.write(data)?;
        state.size = state
            .size
            .saturating_add(u64::try_from(written).unwrap_or(u64::MAX));
        Ok(written)
    }

    pub fn write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut state = self.state();
        self.write_all_locked(&mut state, data)
    }

    /// Best-effort crash-path write that never waits for a lock held by the
    /// panicking thread.
    pub(crate) fn try_write_all(&self, data: &[u8]) -> io::Result<()> {
        let mut state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "log file is busy while recording a panic",
                ));
            }
        };
        self.write_all_locked(&mut state, data)
    }

    fn write_all_locked(&self, state: &mut FileState, data: &[u8]) -> io::Result<()> {
        self.prepare_write(state, data.len())?;
        let result = state
            .file
            .as_mut()
            .ok_or_else(closed_error)?
            .write_all(data);
        if result.is_ok() {
            state.size = state
                .size
                .saturating_add(u64::try_from(data.len()).unwrap_or(u64::MAX));
        } else if let Some(file) = state.file.as_mut()
            && let Ok(end) = file.seek(SeekFrom::End(0))
        {
            state.size = end;
        }
        result
    }

    pub fn sync(&self) -> io::Result<()> {
        let state = self.state();
        match state.file.as_ref() {
            Some(file) => file.sync_all(),
            None => Ok(()),
        }
    }

    /// Best-effort crash-path sync paired with [`Self::try_write_all`].
    pub(crate) fn try_sync(&self) -> io::Result<()> {
        let state = match self.state.try_lock() {
            Ok(state) => state,
            Err(TryLockError::Poisoned(poisoned)) => poisoned.into_inner(),
            Err(TryLockError::WouldBlock) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "log file is busy while syncing a panic",
                ));
            }
        };
        match state.file.as_ref() {
            Some(file) => file.sync_all(),
            None => Ok(()),
        }
    }

    pub fn close(&self) -> io::Result<()> {
        let mut state = self.state();
        if let Some(file) = state.file.take() {
            file.sync_all()?;
        }
        Ok(())
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn prepare_write(&self, state: &mut FileState, data_len: usize) -> io::Result<()> {
        let end = state
            .file
            .as_mut()
            .ok_or_else(closed_error)?
            .seek(SeekFrom::End(0))?;
        state.size = end;
        if self.max_bytes > 0
            && state.size > 0
            && state
                .size
                .saturating_add(u64::try_from(data_len).unwrap_or(u64::MAX))
                > self.max_bytes
        {
            let rotation_error = self.rotate_locked(state).err();
            if state.size != 0 {
                return Err(rotation_error.unwrap_or_else(|| {
                    io::Error::other("active log remains full after rotation")
                }));
            }
        }
        state
            .file
            .as_mut()
            .ok_or_else(closed_error)?
            .seek(SeekFrom::End(0))?;
        Ok(())
    }

    fn secure_existing_backups(&self) -> io::Result<()> {
        for index in 1..=self.max_backups {
            let path = backup_path(&self.path, index);
            match OpenOptions::new().read(true).open(&path) {
                Ok(file) => secure_regular(&path, &file)?,
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn rotate_locked(&self, state: &mut FileState) -> io::Result<()> {
        let Some(file) = state.file.as_mut() else {
            return Err(closed_error());
        };

        let mut first_error = file.sync_all().err();
        if let Err(error) = self.shift_backups() {
            first_error.get_or_insert(error);
        }
        if self.max_backups > 0
            && let Err(error) = copy_open_file(file, &backup_path(&self.path, 1))
        {
            first_error.get_or_insert(error);
        }
        match file.set_len(0) {
            Ok(()) => {
                state.size = 0;
                let _ = file.seek(SeekFrom::Start(0));
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }

    fn shift_backups(&self) -> io::Result<()> {
        let mut first_error = None;
        for index in (2..=self.max_backups).rev() {
            if let Err(error) = copy_if_exists(
                &backup_path(&self.path, index - 1),
                &backup_path(&self.path, index),
            ) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for RotatingFile {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

fn backup_path(path: &Path, index: usize) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(format!(".{index}"));
    PathBuf::from(value)
}

fn copy_if_exists(source: &Path, destination: &Path) -> io::Result<()> {
    match open_secure(source, true, false, false) {
        Ok(mut source) => replace_file(destination, &mut source),
        Err(error) if error.kind() == io::ErrorKind::NotFound => clear_if_exists(destination),
        Err(error) => Err(error),
    }
}

fn copy_open_file(source: &mut File, destination: &Path) -> io::Result<()> {
    let position = source.stream_position()?;
    source.seek(SeekFrom::Start(0))?;
    let result = replace_file(destination, source);
    let restore = source.seek(SeekFrom::Start(position)).map(|_| ());
    result.and(restore)
}

fn replace_file(path: &Path, source: &mut impl Read) -> io::Result<()> {
    let mut destination = open_secure(path, false, true, true)?;
    io::copy(source, &mut destination)?;
    destination.sync_all()
}

fn clear_if_exists(path: &Path) -> io::Result<()> {
    match OpenOptions::new().write(true).open(path) {
        Ok(file) => {
            secure_regular(path, &file)?;
            file.set_len(0)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn open_secure(path: &Path, read: bool, write: bool, truncate: bool) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(read).write(write).truncate(truncate);
    if write {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let file = options.open(path)?;
    secure_regular(path, &file)?;
    Ok(file)
}

fn secure_regular(path: &Path, file: &File) -> io::Result<()> {
    if !file.metadata()?.is_file() {
        return Err(io::Error::other(format!(
            "log path {} is not a regular file",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(windows)]
    super::windows_permissions::set_owner_only(path)?;
    Ok(())
}

fn closed_error() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "log file is closed")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn rotates_and_drops_the_oldest_backup() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let file = RotatingFile::open(&path, 16, 2).unwrap();
        for line in ["aaaaaaaa\n", "bbbbbbbb\n", "cccccccc\n", "dddddddd\n"] {
            file.write_all(line.as_bytes()).unwrap();
        }
        assert!(read(&path).contains("dddddddd"));
        assert!(read(&backup_path(&path, 1)).contains("cccccccc"));
        assert!(read(&backup_path(&path, 2)).contains("bbbbbbbb"));
        assert!(!backup_path(&path, 3).exists());
    }

    #[test]
    fn oversized_first_message_does_not_rotate_an_empty_file() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let file = RotatingFile::open(&path, 8, 2).unwrap();
        let oversized = format!("{}\n", "x".repeat(64));
        file.write_all(oversized.as_bytes()).unwrap();
        assert!(!backup_path(&path, 1).exists());
        assert_eq!(read(&path), oversized);
    }

    #[test]
    fn zero_backups_truncates_in_place() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let file = RotatingFile::open(&path, 16, 0).unwrap();
        file.write_all(b"aaaaaaaa\n").unwrap();
        file.write_all(b"bbbbbbbb\n").unwrap();
        assert_eq!(read(&path), "bbbbbbbb\n");
        assert!(!backup_path(&path, 1).exists());
    }

    #[test]
    fn latest_message_survives_a_backup_failure_and_rotation_recovers() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let file = RotatingFile::open(&path, 16, 1).unwrap();
        file.write_all(b"aaaaaaaa\n").unwrap();
        fs::create_dir(backup_path(&path, 1)).unwrap();
        file.write_all(b"bbbbbbbb\n").unwrap();
        assert_eq!(read(&path), "bbbbbbbb\n");

        fs::remove_dir(backup_path(&path, 1)).unwrap();
        file.write_all(b"cccccccc\n").unwrap();
        assert_eq!(read(&path), "cccccccc\n");
        assert_eq!(read(&backup_path(&path, 1)), "bbbbbbbb\n");
    }

    #[test]
    fn an_older_backup_failure_does_not_block_the_newest_backup() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        let file = RotatingFile::open(&path, 16, 2).unwrap();
        file.write_all(b"aaaaaaaa\n").unwrap();
        fs::create_dir(backup_path(&path, 2)).unwrap();
        file.write_all(b"bbbbbbbb\n").unwrap();
        assert_eq!(read(&path), "bbbbbbbb\n");
        assert_eq!(read(&backup_path(&path, 1)), "aaaaaaaa\n");
    }

    #[test]
    fn rejects_a_non_regular_active_path() {
        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        fs::create_dir(&path).unwrap();
        assert!(RotatingFile::open(path, 16, 2).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn active_and_existing_backup_permissions_are_owner_only() {
        use std::os::unix::fs::PermissionsExt as _;

        let temporary = tempfile::tempdir().unwrap();
        let path = temporary.path().join("agent.log");
        fs::write(backup_path(&path, 1), b"backup").unwrap();
        fs::set_permissions(backup_path(&path, 1), fs::Permissions::from_mode(0o644)).unwrap();
        let _file = RotatingFile::open(&path, 1024, 1).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            fs::metadata(backup_path(&path, 1))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
