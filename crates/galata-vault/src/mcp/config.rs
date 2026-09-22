//! Loading `mcp.toml`, refusing anything that is not a meta-token map.
//!
//! The file holds tokens, so errors never quote it: they name the entry by
//! its path (or position) and say what is wrong.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::keys::TokenKeys;
use crate::proto::codec::FormatError;
use crate::proto::mcp::{MCP_CONFIG_FILE, McpEntry};
use crate::proto::path::EnvPath;
use crate::proto::url::validate_server_url;
use anyhow::{Context, bail};
use zeroize::Zeroizing;

/// One configured environment: its server and its (not yet verified) token.
pub struct Entry {
    pub path: EnvPath,
    pub server: String,
    pub token: TokenKeys,
}

/// `$GV_HOME/mcp.toml`, else `$XDG_CONFIG_HOME/gv/mcp.toml`, else
/// `~/.config/gv/mcp.toml`, the same directory `gv` uses.
pub fn default_path() -> anyhow::Result<PathBuf> {
    let var = |k: &str| {
        std::env::var_os(k)
            .filter(|v| !v.is_empty())
            .map(PathBuf::from)
    };
    let dir = if let Some(d) = var("GV_HOME") {
        d
    } else if let Some(d) = var("XDG_CONFIG_HOME") {
        d.join("gv")
    } else if let Some(h) = var("HOME") {
        h.join(".config").join("gv")
    } else {
        bail!("cannot find the configuration directory: set GV_HOME or pass --config");
    };
    Ok(dir.join(MCP_CONFIG_FILE))
}

/// Any node key.
fn holds_node_key(v: &toml::Value) -> bool {
    match v {
        toml::Value::String(s) => s.contains(crate::proto::codec::KEY_PREFIX),
        toml::Value::Array(a) => a.iter().any(holds_node_key),
        toml::Value::Table(t) => t.values().any(holds_node_key),
        _ => false,
    }
}

pub fn load(file: &Path) -> anyhow::Result<Vec<Entry>> {
    let shown = file.display();
    let mode = std::fs::metadata(file)
        .with_context(|| format!("reading {shown} (create it with `gv mcp setup <project>`)"))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o600 && mode != 0o400 {
        bail!("{shown} has mode {mode:04o}; it holds tokens, so it must be 0600 or 0400");
    }
    let text =
        Zeroizing::new(std::fs::read_to_string(file).with_context(|| format!("reading {shown}"))?);
    let table: toml::Table =
        toml::from_str(&text).map_err(|_| anyhow::anyhow!("{shown} is not valid TOML"))?;
    if let Some(key) = table.keys().find(|k| k.as_str() != "env") {
        bail!("{shown}: unexpected key `{key}`; the file holds only [[env]] entries");
    }
    let Some(toml::Value::Array(entries)) = table.get("env") else {
        bail!("{shown} configures no environments; run `gv mcp setup <project>`");
    };

    let mut out: Vec<Entry> = Vec::new();
    for (i, raw) in entries.iter().enumerate() {
        let label = raw
            .get("path")
            .and_then(toml::Value::as_str)
            .map_or_else(|| format!("entry {}", i + 1), str::to_owned);
        if holds_node_key(raw) {
            bail!(
                "{shown}: the entry for {label} holds a node key. gv-mcp never takes node keys, \
                 which could decrypt values; run `gv mcp setup` to configure meta tokens"
            );
        }
        let entry: McpEntry = raw
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("{shown}: the entry for {label} is malformed: {e}"))?;
        let server = validate_server_url(&entry.server)
            .map_err(|e| anyhow::anyhow!("{shown}: the entry for {label}: {e}"))?;
        let token = TokenKeys::parse(&entry.token).map_err(|e| match e {
            FormatError::UnknownVersion { found } => anyhow::anyhow!(
                "{shown}: the token for {label} carries version {found}, which this build does not \
                 know; run `gv mcp setup` again"
            ),
            _ => anyhow::anyhow!("{shown}: the token for {label} is not a valid gvt1_ token"),
        })?;
        if out.iter().any(|e| e.path == entry.path) {
            bail!("{shown}: {label} is configured twice");
        }
        out.push(Entry {
            path: entry.path.clone(),
            server,
            token,
        });
    }
    if out.is_empty() {
        bail!("{shown} configures no environments; run `gv mcp setup <project>`");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::ids::VaultId;

    fn write(dir: &Path, text: &str, mode: u32) -> PathBuf {
        let f = dir.join("mcp.toml");
        std::fs::write(&f, text).unwrap();
        std::fs::set_permissions(&f, std::fs::Permissions::from_mode(mode)).unwrap();
        f
    }

    fn entry(path: &str, token: &str) -> String {
        format!(
            "[[env]]\npath = \"{path}\"\nserver = \"https://vault.example\"\ntoken = \"{token}\"\n"
        )
    }

    fn token() -> Zeroizing<String> {
        TokenKeys::generate(VaultId([1; 16])).token_string()
    }

    #[test]
    fn a_valid_file_loads() {
        let dir = tempfile::tempdir().unwrap();
        let (t1, t2) = (token(), token());
        let f = write(
            dir.path(),
            &(entry("acme", &t1) + &entry("acme/dev", &t2)),
            0o600,
        );
        let loaded = load(&f).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[1].path.to_string(), "acme/dev");
    }

    #[test]
    fn node_keys_modes_and_bad_tokens_are_refused_without_quoting() {
        let dir = tempfile::tempdir().unwrap();
        let key = crate::keys::NodeKey::generate().encode();
        let t = token();

        let f = write(
            dir.path(),
            &(entry("acme", &t) + &entry("acme/prod", &key)),
            0o600,
        );
        let err = format!("{:#}", load(&f).err().unwrap());
        assert!(
            err.contains("acme/prod") && err.contains("node key"),
            "{err}"
        );
        assert!(!err.contains(&key[5..]), "never quotes the key");

        let f = write(dir.path(), &entry("acme", &t), 0o644);
        assert!(format!("{:#}", load(&f).err().unwrap()).contains("0600"));

        let f = write(dir.path(), &entry("acme", &t[..t.len() - 1]), 0o600);
        let err = format!("{:#}", load(&f).err().unwrap());
        assert!(
            err.contains("not a valid gvt1_ token") && !err.contains(&t[5..30]),
            "{err}"
        );

        let other = crate::proto::codec::encode_checked("gvt2_", &[3u8; 48]);
        let f = write(dir.path(), &entry("acme", &other), 0o600);
        let err = format!("{:#}", load(&f).err().unwrap());
        assert!(
            err.contains("version 2") && !err.contains(&other[5..30]),
            "{err}"
        );

        let f = write(
            dir.path(),
            &entry("acme", &t).replace("https://vault.example", "http://evil.example"),
            0o600,
        );
        assert!(load(&f).is_err());
        let f = write(dir.path(), &(entry("acme", &t) + "extra = 1\n"), 0o600);
        assert!(load(&f).is_err());
    }
}
