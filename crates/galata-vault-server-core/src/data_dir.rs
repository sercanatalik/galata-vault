//! The data directory that `gv-server local` and the SDK's embedded
//! transport share: `vault.db` and a file journal under `journal-root/`, in
//! one directory of mode 0700, opened by one process at a time.
//!
//! The exclusive lock is advisory (`flock` on Unix, `LockFileEx` on
//! Windows). It keeps cooperating openers, a local server and an embedded
//! application say, from writing one database at once. It does not stop a
//! process that ignores it, and it binds only openers new enough to take it.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::path::{Path, PathBuf};

/// The database file.
pub const DATABASE: &str = "vault.db";
/// The file journal's root: records live under `journal-root/journal/`.
pub const JOURNAL_ROOT: &str = "journal-root";
/// The file whose exclusive lock marks the directory as open.
pub const LOCK: &str = "lock";

#[derive(Debug, thiserror::Error)]
pub enum DataDirError {
    /// Not a directory, reachable by its group or others, or unreadable.
    #[error("{0}")]
    Unusable(String),
    /// Another opener holds the directory's lock.
    #[error(
        "data_dir_in_use: {} is already open in another process (a `gv-server local` or an \
         embedded application); a data directory has one opener at a time",
        .0.display()
    )]
    InUse(PathBuf),
}

impl DataDirError {
    /// A stable code: `data_dir_in_use`, or `invalid_data_dir`.
    pub fn code(&self) -> &'static str {
        match self {
            DataDirError::Unusable(_) => "invalid_data_dir",
            DataDirError::InUse(_) => "data_dir_in_use",
        }
    }
}

/// An open data directory. While it lives, no other opener can have it; the
/// lock is released when it is dropped, or when the process exits.
#[derive(Debug)]
pub struct DataDir {
    path: PathBuf,
    _lock: File,
}

impl DataDir {
    /// Create `path` with mode 0700, or check an existing one, then take its
    /// exclusive lock. When the lock is held elsewhere, nothing in the
    /// directory is changed and the answer is [`DataDirError::InUse`].
    pub fn open(path: &Path) -> Result<DataDir, DataDirError> {
        prepare(path).map_err(DataDirError::Unusable)?;
        let lock_path = path.join(LOCK);
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(&lock_path).map_err(|e| {
            DataDirError::Unusable(format!("cannot open {}: {e}", lock_path.display()))
        })?;
        match file.try_lock() {
            Ok(()) => Ok(DataDir {
                path: path.to_path_buf(),
                _lock: file,
            }),
            Err(TryLockError::WouldBlock) => Err(DataDirError::InUse(path.to_path_buf())),
            Err(TryLockError::Error(e)) => Err(DataDirError::Unusable(format!(
                "cannot lock {}: {e}",
                lock_path.display()
            ))),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `vault.db`.
    pub fn database(&self) -> PathBuf {
        self.path.join(DATABASE)
    }

    /// The file journal's root.
    pub fn journal_root(&self) -> PathBuf {
        self.path.join(JOURNAL_ROOT)
    }
}

/// Create the data directory with mode 0700, or refuse an existing one that
/// its group or others can reach: it holds the database and the journal.
#[cfg(unix)]
pub fn prepare(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    match fs::metadata(dir) {
        Ok(meta) if !meta.is_dir() => {
            Err(format!("{} exists and is not a directory", dir.display()))
        }
        Ok(meta) => {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "{} has mode {mode:04o}; it holds the vault database and journal, so it must be 0700 (chmod 700 {})",
                    dir.display(),
                    dir.display()
                ));
            }
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("cannot create {}: {e}", dir.display()))
        }
        Err(e) => Err(format!("cannot read {}: {e}", dir.display())),
    }
}

/// Elsewhere the directory's permissions cannot be checked, so a data
/// directory is refused rather than trusted, as token files are.
#[cfg(not(unix))]
pub fn prepare(dir: &Path) -> Result<(), String> {
    let _ = fs::metadata(dir);
    Err(format!(
        "{}: a data directory's permissions cannot be verified on this platform, so it is refused",
        dir.display()
    ))
}

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn data_directory_permissions() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("nested/galata-vault");
        prepare(&dir).unwrap();
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        prepare(&dir).unwrap();

        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        let err = prepare(&dir).unwrap_err();
        assert!(err.contains("0755") && err.contains("0700"), "{err}");
    }

    #[test]
    fn one_opener_at_a_time() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("data");
        let first = DataDir::open(&dir).unwrap();
        assert_eq!(first.database(), dir.join("vault.db"));
        assert_eq!(first.journal_root(), dir.join("journal-root"));

        let second = DataDir::open(&dir).unwrap_err();
        assert_eq!(second.code(), "data_dir_in_use");
        assert!(second.to_string().contains("data_dir_in_use"), "{second}");

        drop(first);
        DataDir::open(&dir).expect("released when the first opener is dropped");
    }
}
