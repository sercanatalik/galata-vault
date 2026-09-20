//! Files the CLI writes: always atomically, always mode 0600, because a kit
//! or credentials file must never exist, even briefly, with looser access.

use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{Context, bail};

/// Write `bytes` to `path` via a 0600 temporary file and a rename.
pub fn write_private(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty());
    if let Some(dir) = dir {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    }
    let tmp = path.with_extension(format!(
        "{}.tmp",
        path.extension()
            .map(|e| e.to_string_lossy().into_owned())
            .unwrap_or_default()
    ));
    let _ = fs::remove_file(&tmp);
    {
        let mut f =
            new_private_file(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    fs::rename(&tmp, path).with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

/// Create a new file with mode 0600. Refuses to replace an existing file
/// unless `replace`, and then removes it first so the new one never
/// inherits looser permissions.
pub fn create_private(path: &Path, bytes: &[u8], replace: bool) -> anyhow::Result<()> {
    if path.exists() {
        if !replace {
            bail!(
                "{} already exists (pass --force to replace it)",
                path.display()
            );
        }
        fs::remove_file(path).with_context(|| format!("replacing {}", path.display()))?;
    }
    let mut f = new_private_file(path).with_context(|| format!("creating {}", path.display()))?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

/// A new file only its owner can read and write (mode 0600).
#[cfg(unix)]
fn new_private_file(path: &Path) -> std::io::Result<fs::File> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Off Unix there is no mode to set, and this crate checks no ACL, so a file
/// that would hold keys is refused, as the SDK refuses token files there.
/// The OS keychain still works.
#[cfg(not(unix))]
fn new_private_file(path: &Path) -> std::io::Result<fs::File> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        format!(
            "{} would hold keys, and its access control cannot be set on this platform",
            path.display()
        ),
    ))
}

/// Refuse a file holding key material unless only its owner can read it.
#[cfg(unix)]
pub fn require_private(path: &Path) -> anyhow::Result<()> {
    let mode = fs::metadata(path)
        .with_context(|| format!("reading {}", path.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 && mode != 0o400 {
        bail!(
            "{} has mode {mode:04o}; it holds keys, so it must be 0600 or 0400 (chmod 600 {})",
            path.display(),
            path.display()
        );
    }
    Ok(())
}

/// Off Unix a key file's access control cannot be checked, so it is refused.
#[cfg(not(unix))]
pub fn require_private(path: &Path) -> anyhow::Result<()> {
    bail!(
        "{} holds keys, and its access control cannot be checked on this platform; use the OS keychain",
        path.display()
    )
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn private_files_are_0600_and_checked() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub/creds.toml");
        write_private(&p, b"x").unwrap();
        assert_eq!(
            fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        require_private(&p).unwrap();
        fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
        let err = require_private(&p).unwrap_err().to_string();
        assert!(err.contains("0644") && err.contains("0600"), "{err}");

        let out = dir.path().join(".env");
        create_private(&out, b"a", false).unwrap();
        assert!(create_private(&out, b"b", false).is_err());
        fs::set_permissions(&out, fs::Permissions::from_mode(0o644)).unwrap();
        create_private(&out, b"b", true).unwrap();
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
