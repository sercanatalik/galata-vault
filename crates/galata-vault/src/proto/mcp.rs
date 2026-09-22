//! The gv-mcp configuration file (`mcp.toml`): environment path → server and
//! meta token. `gv mcp setup` writes it with mode 0600; `gv-mcp` reads it.
//!
//! It never holds a node key: gv-mcp refuses a file that contains one.

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::proto::path::EnvPath;

/// The file name inside the gv configuration directory.
pub const MCP_CONFIG_FILE: &str = "mcp.toml";

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpConfig {
    #[serde(default)]
    pub env: Vec<McpEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct McpEntry {
    pub path: EnvPath,
    /// The project's pinned server.
    pub server: String,
    /// A `gvt1_` meta token for this environment's vault.
    pub token: String,
}

impl std::fmt::Debug for McpEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpEntry")
            .field("path", &self.path)
            .field("server", &self.server)
            .field("token", &"<redacted>")
            .finish()
    }
}

impl Drop for McpEntry {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_token() {
        let e = McpEntry {
            path: "acme/dev".parse().unwrap(),
            server: "https://vault.example".into(),
            token: "gvt1_secret".into(),
        };
        let shown = format!("{:?}", McpConfig { env: vec![e] });
        assert!(
            shown.contains("<redacted>") && !shown.contains("gvt1_"),
            "{shown}"
        );
    }
}
