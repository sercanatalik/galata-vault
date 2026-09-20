//! The command line. No argument anywhere carries a secret value.
//!
//! [`Command`] is public so another binary can flatten it into its own tree
//! (`#[command(flatten)] Vault(galata_vault_cli::Command)`) and dispatch it with
//! [`crate::dispatch`]; [`Cli`] adds the global `--env` and takes its name
//! and about text from a [`Branding`].

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{CommandFactory, FromArgMatches, Parser, Subcommand, ValueEnum};

use crate::branding::Branding;

/// The whole command line: the global `--env` and one command.
#[derive(Debug, Parser)]
#[command(version)]
pub struct Cli {
    /// Environment path, e.g. acme/dev (else the environment variable, else
    /// the nearest directory file).
    #[arg(long, global = true)]
    pub env: Option<String>,
    /// The command.
    #[command(subcommand)]
    pub command: Command,
}

impl Cli {
    /// The clap command for `branding`: its binary name, about text and
    /// variable names. Its help ends with the review-status statement
    /// ([`galata_vault::REVIEW_STATUS`]), whatever the branding: a branded
    /// binary runs the same unaudited code.
    pub fn command_for(branding: &Branding) -> clap::Command {
        <Cli as CommandFactory>::command()
            .name(branding.bin_name)
            .bin_name(branding.bin_name)
            .about(branding.about)
            .after_help(galata_vault::REVIEW_STATUS)
            .mut_arg("env", |a| {
                a.help(format!(
                    "Environment path, e.g. acme/dev (else {}, else the nearest {})",
                    branding.var("ENV"),
                    branding.dir_file
                ))
            })
    }

    /// Parse `args` (the first is the program name), exiting as clap does on
    /// `--help`, `--version` or a usage error.
    pub fn parse_with<I, T>(branding: &Branding, args: I) -> Cli
    where
        I: IntoIterator<Item = T>,
        T: Into<OsString> + Clone,
    {
        let matches = Cli::command_for(branding).get_matches_from(args);
        Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
    }
}

/// Every vault command.
// These doc comments are clap's help text, where `<project>` is a
// placeholder the user reads, not an HTML tag.
#[allow(rustdoc::invalid_html_tags)]
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Create a project: its key, its vault and its recovery kit.
    Init {
        /// The project's name.
        project: String,
        /// The server to pin this project to.
        #[arg(long)]
        server: String,
        /// Where to write the recovery kit (default: ./<project>-recovery.gvkit).
        #[arg(long)]
        kit: Option<PathBuf>,
    },
    /// Manage environments: add, ls, rm, repair.
    #[command(subcommand)]
    Env(EnvCommand),
    /// Export or import a node key (delegation).
    #[command(subcommand)]
    Key(KeyCommand),
    /// Restore a project on this machine from its recovery kit.
    Recover {
        /// The recovery kit.
        kit: PathBuf,
    },
    /// Set a secret. The value comes from stdin or a no-echo prompt.
    Set {
        /// The secret's name.
        name: String,
    },
    /// Print a secret's value.
    Get {
        /// The secret's name.
        name: String,
        /// A version other than the latest.
        #[arg(long)]
        version: Option<u64>,
    },
    /// List secret names.
    Ls {
        /// Include deleted secrets.
        #[arg(long)]
        all: bool,
    },
    /// Show a secret's versions.
    History {
        /// The secret's name.
        name: String,
    },
    /// Delete a secret (a tombstone version; history is kept).
    Rm {
        /// The secret's name.
        name: String,
    },
    /// Config documents: set, get, ls, history, rm. A `config` token can read
    /// them and never a secret.
    #[command(subcommand)]
    Config(ConfigCommand),
    /// Run a command with the environment's secrets in its environment.
    Run {
        /// Inject only these names.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
        /// The command and its arguments.
        #[arg(last = true, required = true, value_name = "COMMAND")]
        command: Vec<OsString>,
    },
    /// Write decrypted secrets to stdout or a new 0600 file.
    Export {
        /// dotenv, json or yaml.
        #[arg(long, value_enum)]
        format: Format,
        /// The file to write (default: stdout).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Replace an existing --out file.
        #[arg(long)]
        force: bool,
        /// Export only these names.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    /// Mint, list, revoke and report access tokens.
    #[command(subcommand)]
    Token(TokenCommand),
    /// Move the environment's vault to a new generation: fresh keys, every
    /// record re-encrypted and re-signed. Owner only.
    Rotate,
    /// Re-root a node (default: the selected environment): a fresh key and
    /// fresh vaults for it and every environment below it. Nothing held
    /// before (the old key, an ancestor's key, any token) reaches the new
    /// vaults; every token there dies and must be minted again.
    Rekey {
        /// The node to re-root.
        path: Option<String>,
        /// Where to write the new kit.
        #[arg(long)]
        kit: Option<PathBuf>,
        /// Finish a rekey that was interrupted.
        #[arg(long)]
        resume: bool,
        /// Undo a rekey that was interrupted before its parent was relinked.
        #[arg(long)]
        abort: bool,
    },
    /// Fetch and verify the environment's audit chain.
    Audit,
    /// Show the environment's vault status.
    Status,
    /// Open the vault in a browser, served by this process on loopback. Keys
    /// stay here; tokens, revocations and deletions are confirmed in this
    /// terminal.
    Ui {
        /// Print the link without opening a browser.
        #[arg(long)]
        no_open: bool,
    },
    /// The metadata-only MCP server: `mcp setup <project>`, then `mcp`.
    Mcp {
        /// `setup`, or nothing to serve.
        #[command(subcommand)]
        command: Option<McpCommand>,
        /// The MCP server's configuration (default: <config dir>/mcp.toml).
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

/// Config document commands.
#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Set a config document. The body comes from --file or stdin, never
    /// from an argument, and is checked before it is sent.
    Set {
        /// The config's name.
        name: String,
        /// toml, json, yaml or text.
        #[arg(long, value_enum)]
        format: ConfigFormatArg,
        /// Read the body from this file instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        /// Write it even if it holds a credential literal (a key, a token, a
        /// PEM block). Every config reader could read that literal.
        #[arg(long)]
        allow_literals: bool,
    },
    /// Print a config document's body, exactly as stored.
    Get {
        /// The config's name.
        name: String,
        /// A version other than the latest.
        #[arg(long)]
        version: Option<u64>,
    },
    /// List config names.
    Ls {
        /// Include deleted configs.
        #[arg(long)]
        all: bool,
    },
    /// Show a config's versions.
    History {
        /// The config's name.
        name: String,
    },
    /// Delete a config (a tombstone version; history is kept).
    Rm {
        /// The config's name.
        name: String,
    },
}

/// A config document's declared format.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ConfigFormatArg {
    /// TOML, checked to parse.
    Toml,
    /// JSON, checked to parse.
    Json,
    /// YAML, checked for UTF-8.
    Yaml,
    /// Text, checked for UTF-8.
    Text,
}

impl From<ConfigFormatArg> for galata_vault::ConfigFormat {
    fn from(f: ConfigFormatArg) -> Self {
        match f {
            ConfigFormatArg::Toml => Self::Toml,
            ConfigFormatArg::Json => Self::Json,
            ConfigFormatArg::Yaml => Self::Yaml,
            ConfigFormatArg::Text => Self::Text,
        }
    }
}

/// MCP server commands.
#[derive(Debug, Subcommand)]
pub enum McpCommand {
    /// Mint a meta token for every environment of a project and write the
    /// MCP server's configuration (mode 0600). Meta tokens cannot decrypt
    /// values.
    Setup {
        /// The project.
        project: String,
        /// Token lifetime, e.g. 90d (the default).
        #[arg(long)]
        ttl: Option<String>,
    },
}

/// Environment commands.
#[derive(Debug, Subcommand)]
pub enum EnvCommand {
    /// Create an environment below a known node.
    Add {
        /// The environment's path.
        path: String,
    },
    /// Show the known tree, refreshed by rediscovery.
    Ls {
        /// Only this project or subtree.
        path: Option<String>,
    },
    /// Delete an environment's vault.
    Rm {
        /// The environment's path.
        path: String,
        /// Also delete every environment below it.
        #[arg(long)]
        recursive: bool,
    },
    /// Re-create an expired vault at its vault id and rebuild its children.
    Repair {
        /// The environment's path.
        path: String,
    },
}

/// Key commands.
#[derive(Debug, Subcommand)]
pub enum KeyCommand {
    /// Write a delegation kit for a node. Its holder owns the whole subtree.
    Export {
        /// The node's path.
        path: String,
        /// Where to write the kit.
        #[arg(long)]
        out: Option<PathBuf>,
        /// Skip the confirmation.
        #[arg(long)]
        yes: bool,
    },
    /// Import a recovery or delegation kit and discover its subtree.
    Import {
        /// The kit.
        kit: PathBuf,
    },
}

/// Token commands.
#[derive(Debug, Subcommand)]
pub enum TokenCommand {
    /// Mint a token for the environment (owner only); it is printed exactly once.
    Mint {
        /// meta, append, read, admin, config or config-write.
        #[arg(long)]
        scope: String,
        /// Lifetime, e.g. 30d, 12h (default: 90d; admin 1d).
        #[arg(long)]
        ttl: Option<String>,
        /// Read tokens only: the names this token may read.
        #[arg(long, value_delimiter = ',')]
        only: Vec<String>,
    },
    /// List the environment's tokens.
    Ls,
    /// Revoke a token. --rotate also moves the vault to fresh keys in the
    /// same step (owner only).
    Revoke {
        /// The token's id.
        id: String,
        /// Rotate the vault in the same step.
        #[arg(long)]
        rotate: bool,
    },
    /// Report a leaked token so the server revokes it. The token comes from
    /// --file or stdin, never an argument, and is never sent: only a
    /// signature proving possession is.
    Report {
        /// Read the token from this file instead of stdin.
        #[arg(long)]
        file: Option<PathBuf>,
        /// The token's server (default: the server variable, else the
        /// project here that knows the token's vault).
        #[arg(long)]
        server: Option<String>,
    },
}

/// An export format.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum Format {
    /// `NAME="value"` lines.
    Dotenv,
    /// One JSON object.
    Json,
    /// YAML double-quoted scalars.
    Yaml,
}
