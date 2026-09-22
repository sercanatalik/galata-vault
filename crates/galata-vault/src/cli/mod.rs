//! The `gv` client, as a binary and as a library.
//!
//! Every vault operation is the SDK's (`galata_vault`: the token client and
//! the owner API); this crate parses the command line, asks and confirms on
//! the terminal, keeps keys in the OS keychain (or a 0600 file), and prints.
//! It is the one place those host effects live.
//!
//! Another binary can reuse the commands as itself:
//!
//! ```no_run
//! use clap::{Parser, Subcommand};
//! use galata_vault::cli::{Branding, Context};
//!
//! const ACME: Branding = Branding {
//!     bin_name: "acme",
//!     about: "acme: deploys and their secrets",
//!     home_env: "ACME_HOME",
//!     env_prefix: "ACME_",
//!     dir_file: ".acme.toml",
//!     keychain_service: "acme",
//!     kit_header: "acme",
//!     message_prefix: "acme",
//!     mcp_binary: "acme-mcp",
//! };
//!
//! #[derive(Parser)]
//! struct Acme {
//!     #[arg(long, global = true)]
//!     env: Option<String>,
//!     #[command(subcommand)]
//!     command: Cmd,
//! }
//!
//! #[derive(Subcommand)]
//! enum Cmd {
//!     #[command(flatten)]
//!     Vault(galata_vault::cli::Command),
//!     /// Deploy the current build.
//!     Deploy { target: String },
//! }
//!
//! let cli = Acme::parse();
//! let mut ctx = Context::new(ACME);
//! match cli.command {
//!     Cmd::Vault(command) => galata_vault::cli::dispatch(&mut ctx, cli.env.as_deref(), command)?,
//!     Cmd::Deploy { target } => ctx.say(&format!("deploying to {target}")),
//! }
//! # Ok::<(), anyhow::Error>(())
//! ```
//!
//! This is the one binary that holds keys and sees plaintext, so it is also
//! the one that must never put a value on a command line, in a log, or in a
//! file it did not create with mode 0600.

mod branding;
mod command_line;
mod config;
mod configs;
mod context;
mod fsutil;
mod keystore;
mod kit;
mod mcp;
mod projects;
mod secrets;
mod select;
mod style;
mod tokens;
#[cfg(feature = "ui")]
pub mod ui;
mod util;

use std::ffi::OsString;

pub use branding::Branding;
pub use command_line::{
    Cli, Command, ConfigCommand, ConfigFormatArg, EnvCommand, Format, KeyCommand, McpCommand,
    TokenCommand,
};
pub use context::{
    CapturedOutput, Context, ContextBuilder, Output, Prompter, ScriptedPrompter, render_error,
};

/// A crash must not leave keys or values in a core file. Unix only: there is
/// no core-size limit to set elsewhere.
#[cfg(not(unix))]
fn disable_core_dumps(_branding: &Branding) {}

/// A crash must not leave keys or values in a core file.
#[cfg(unix)]
fn disable_core_dumps(branding: &Branding) {
    if let Err(e) = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0) {
        eprintln!(
            "{}: warning: could not disable core dumps: {e}",
            branding.message_prefix
        );
    }
}

/// Run one parsed command against `ctx`. `env` is the global `--env`, if
/// the caller has one. Errors are for the caller to print, with
/// [`render_error`].
pub fn dispatch(ctx: &mut Context, env: Option<&str>, command: Command) -> anyhow::Result<()> {
    match command {
        Command::Init {
            project,
            server,
            kit,
        } => projects::init(ctx, &project, &server, kit.as_deref()),
        Command::Env(EnvCommand::Add { path }) => projects::env_add(ctx, &path),
        Command::Env(EnvCommand::Ls { path }) => projects::env_ls(ctx, path.as_deref()),
        Command::Env(EnvCommand::Rm { path, recursive }) => projects::env_rm(ctx, &path, recursive),
        Command::Env(EnvCommand::Repair { path }) => projects::env_repair(ctx, &path),
        Command::Key(KeyCommand::Export { path, out, yes }) => {
            projects::key_export(ctx, &path, out.as_deref(), yes)
        }
        Command::Key(KeyCommand::Import { kit }) => projects::key_import(ctx, &kit),
        Command::Recover { kit } => projects::recover(ctx, &kit),
        Command::Set { name } => secrets::set(ctx, env, &name),
        Command::Get { name, version } => secrets::get(ctx, env, &name, version),
        Command::Ls { all } => secrets::ls(ctx, env, all),
        Command::History { name } => secrets::history(ctx, env, &name),
        Command::Rm { name } => secrets::rm(ctx, env, &name),
        Command::Config(command) => match command {
            ConfigCommand::Set {
                name,
                format,
                file,
                allow_literals,
            } => configs::set(
                ctx,
                env,
                &name,
                format.into(),
                file.as_deref(),
                allow_literals,
            ),
            ConfigCommand::Get { name, version } => configs::get(ctx, env, &name, version),
            ConfigCommand::Ls { all } => configs::ls(ctx, env, all),
            ConfigCommand::History { name } => configs::history(ctx, env, &name),
            ConfigCommand::Rm { name } => configs::rm(ctx, env, &name),
        },
        Command::Run { only, command } => secrets::run(ctx, env, &only, &command),
        Command::Export {
            format,
            out,
            force,
            only,
        } => secrets::export(ctx, env, format, out.as_deref(), force, &only),
        Command::Token(TokenCommand::Mint { scope, ttl, only }) => {
            tokens::mint(ctx, env, &scope, ttl.as_deref(), &only)
        }
        Command::Token(TokenCommand::Ls) => tokens::ls(ctx, env),
        Command::Token(TokenCommand::Revoke { id, rotate }) => {
            tokens::revoke(ctx, env, &id, rotate)
        }
        Command::Token(TokenCommand::Report { file, server }) => {
            tokens::report(ctx, file.as_deref(), server.as_deref())
        }
        Command::Rotate => tokens::rotate(ctx, env),
        Command::Rekey {
            path,
            kit,
            resume,
            abort,
        } => tokens::rekey(ctx, env, path.as_deref(), kit.as_deref(), resume, abort),
        Command::Audit => secrets::audit(ctx, env),
        Command::Status => secrets::status(ctx, env),
        Command::Mcp {
            command: Some(McpCommand::Setup { project, ttl }),
            ..
        } => mcp::setup(ctx, &project, ttl.as_deref()),
        Command::Mcp {
            command: None,
            config,
        } => mcp::exec(ctx, config.as_deref()),
        Command::Ui { no_open } => ui_command(ctx, !no_open),
    }
}

#[cfg(feature = "ui")]
fn ui_command(ctx: &mut Context, open_browser: bool) -> anyhow::Result<()> {
    ui::run_cli(ctx, open_browser)
}

#[cfg(not(feature = "ui"))]
fn ui_command(ctx: &mut Context, _open_browser: bool) -> anyhow::Result<()> {
    let bin = ctx.branding().bin_name;
    anyhow::bail!("this {bin} was built without the `ui` feature, so {bin} ui is not available")
}

/// The whole command for `branding`, from an argument list (the first is
/// the program name), returning its exit status: core dumps off, the host's
/// [`Context`], the command dispatched, and its error printed. `run` never
/// returns for `run` and `mcp`: they exec.
pub fn run_with<I, T>(branding: &Branding, args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    disable_core_dumps(branding);
    let cli = Cli::parse_with(branding, args);
    let mut ctx = Context::new(*branding);
    match dispatch(&mut ctx, cli.env.as_deref(), cli.command) {
        Ok(()) => 0,
        Err(e) => {
            // Every message is built from allow-listed parts: paths the
            // user typed, versions, error kinds. Never values or keys.
            let paint = style::Paint::for_terminal(ctx.output().stderr_is_terminal());
            let _ = ctx.output().stderr(
                format!(
                    "{} {}\n",
                    paint.apply(style::Role::Muted, &format!("{}:", branding.message_prefix)),
                    paint.apply(style::Role::Warn, &render_error(&e, branding))
                )
                .as_bytes(),
            );
            1
        }
    }
}

/// `gv`: [`run_with`] and [`Branding::GV`]. The Python console script calls
/// this.
pub fn run<I, T>(args: I) -> u8
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    run_with(&Branding::GV, args)
}

#[cfg(all(test, not(feature = "ui")))]
mod tests {
    use std::sync::Arc;

    use super::*;

    /// A `gv` built without `ui` refuses `gv ui`, naming the feature.
    #[test]
    fn gv_ui_without_the_feature_names_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut ctx = Context::builder(Branding::GV)
            .home(dir.path())
            .output(Arc::new(CapturedOutput::new()))
            .build();
        let e = dispatch(&mut ctx, None, Command::Ui { no_open: true }).unwrap_err();
        assert!(e.to_string().contains("`ui` feature"), "{e}");
    }
}
