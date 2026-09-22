//! Where the CLI keeps its files. The local state itself (projects, trees,
//! bookkeeping) is the SDK's `FileStateStore` over this directory; the
//! credentials file and the MCP configuration live here too.

use std::path::PathBuf;

use anyhow::bail;

use crate::cli::branding::Branding;

/// The home directory: `$<home_env>`, else `$XDG_CONFIG_HOME/<bin_name>`,
/// else `~/.config/<bin_name>`.
#[derive(Debug, Clone)]
pub struct Home {
    /// The directory.
    pub dir: PathBuf,
}

impl Home {
    /// Find the home for `branding` from the environment.
    pub fn locate(branding: &Branding) -> anyhow::Result<Home> {
        let var = |k: &str| std::env::var_os(k).filter(|d| !d.is_empty());
        let dir = if let Some(d) = var(branding.home_env) {
            PathBuf::from(d)
        } else if let Some(d) = var("XDG_CONFIG_HOME") {
            PathBuf::from(d).join(branding.bin_name)
        } else if let Some(h) = var("HOME") {
            PathBuf::from(h).join(".config").join(branding.bin_name)
        } else {
            bail!(
                "cannot find a configuration directory: set {} or HOME",
                branding.home_env
            );
        };
        Ok(Home { dir })
    }

    /// The 0600 credentials file, used when there is no keychain.
    pub fn credentials_path(&self) -> PathBuf {
        self.dir.join("credentials.toml")
    }
}
