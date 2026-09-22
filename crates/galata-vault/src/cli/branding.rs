//! What names the tool: one value, so another binary can run `gv`'s commands
//! as itself.

/// Everything that names the tool. [`Branding::GV`] reproduces `gv` exactly;
/// a product builds its own and passes it to [`crate::cli::run_with`] or
/// [`crate::cli::Context::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Branding {
    /// The binary's name: usage lines, and command hints in messages
    /// (`gv env repair …`).
    pub bin_name: &'static str,
    /// The about line of `--help`.
    pub about: &'static str,
    /// The variable naming the home directory; without it the home is
    /// `$XDG_CONFIG_HOME/<bin_name>`, else `~/.config/<bin_name>`.
    pub home_env: &'static str,
    /// The prefix of the environment, token, server and credential-store
    /// variables: `GV_` gives `GV_ENV`, `GV_TOKEN`, `GV_SERVER` and
    /// `GV_CREDENTIAL_STORE`.
    pub env_prefix: &'static str,
    /// The directory file that names an environment (`.gv.toml`).
    pub dir_file: &'static str,
    /// The OS keychain service node keys are stored under.
    pub keychain_service: &'static str,
    /// The product named in the first line of a recovery or delegation kit.
    pub kit_header: &'static str,
    /// The prefix of every message (`gv: …`).
    pub message_prefix: &'static str,
    /// The metadata-only MCP server binary that `mcp` runs.
    pub mcp_binary: &'static str,
}

impl Branding {
    /// `gv`.
    pub const GV: Branding = Branding {
        bin_name: "gv",
        about: "galata-vault: end-to-end encrypted secrets, no account needed",
        home_env: "GV_HOME",
        env_prefix: "GV_",
        dir_file: ".gv.toml",
        keychain_service: "galata-vault",
        kit_header: "galata-vault",
        message_prefix: "gv",
        mcp_binary: "gv-mcp",
    };

    /// The variable `<env_prefix><name>`, e.g. `var("TOKEN")` is `GV_TOKEN`.
    pub fn var(&self, name: &str) -> String {
        format!("{}{name}", self.env_prefix)
    }
}
