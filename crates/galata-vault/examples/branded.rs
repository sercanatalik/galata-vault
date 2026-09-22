//! A product binary that reuses `gv`'s vault commands under its own name,
//! beside a command of its own.
//!
//! `acme init`, `acme set`, `acme token mint` … behave as `gv`'s do, but read
//! `ACME_HOME`, `ACME_ENV`, `ACME_TOKEN` and `.acme.toml`, keep keys under the
//! keychain service `acme-cloud`, and say `acme: …`. `acme deploy` is the
//! product's own.
//!
//! ```text
//! cargo run -p galata-vault-cli --example branded -- init acme --server https://vault.example
//! ```

use std::process::ExitCode;

use clap::{Parser, Subcommand};
use galata_vault::cli::{Branding, Context};

/// Everything that names this binary.
pub const ACME: Branding = Branding {
    bin_name: "acme",
    about: "acme: deploys, and the secrets they need",
    home_env: "ACME_HOME",
    env_prefix: "ACME_",
    dir_file: ".acme.toml",
    keychain_service: "acme-cloud",
    kit_header: "acme-cloud",
    message_prefix: "acme",
    mcp_binary: "acme-mcp",
};

/// The product's command line: the vault commands, flattened, and its own.
#[derive(Parser)]
#[command(
    name = "acme",
    about = "acme: deploys, and the secrets they need",
    version
)]
pub struct Acme {
    /// Environment path, e.g. acme/prod (else ACME_ENV, else the nearest
    /// .acme.toml).
    #[arg(long, global = true)]
    pub env: Option<String>,
    /// The command.
    #[command(subcommand)]
    pub command: Cmd,
}

/// Every command of the product.
#[derive(Subcommand)]
pub enum Cmd {
    /// The vault commands, exactly as `gv` has them.
    #[command(flatten)]
    Vault(galata_vault::cli::Command),
    /// Deploy the current build to a target.
    Deploy {
        /// Where to deploy.
        target: String,
    },
}

/// Run one parsed command.
pub fn dispatch(ctx: &mut Context, cli: Acme) -> anyhow::Result<()> {
    match cli.command {
        Cmd::Vault(command) => galata_vault::cli::dispatch(ctx, cli.env.as_deref(), command),
        Cmd::Deploy { target } => {
            ctx.say(&format!("deploying to {target}"));
            Ok(())
        }
    }
}

fn main() -> ExitCode {
    let cli = Acme::parse();
    let mut ctx = Context::new(ACME);
    match dispatch(&mut ctx, cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            ctx.say(&galata_vault::cli::render_error(&e, &ACME));
            ExitCode::FAILURE
        }
    }
}
