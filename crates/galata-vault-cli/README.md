# galata-vault-cli

`gv`, the command line for galata-vault: end-to-end-encrypted secrets and
config documents with no accounts. Everything is encrypted on your machine
before it leaves, and everything you read is verified against keys the
server does not hold. It is also a library: another binary can flatten the
`gv` command tree into its own, under its own name.

> galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.

## Install

```sh
cargo binstall galata-vault-cli                  # a prebuilt gv, with `gv ui`
cargo install galata-vault-cli --features ui     # or build it
```

The release binaries enable the `ui` feature. The crate leaves it off by
default, so a binary that embeds the command tree links no web server unless
it asks for one.

## A short tour

```sh
gv init acme --server http://127.0.0.1:8750      # writes acme-recovery.gvkit; keep it safe
gv env add acme/prod
printf %s "$DATABASE_URL" | gv set DATABASE_URL --env acme/prod
gv run --env acme/prod -- ./deploy               # secrets arrive as environment variables
gv token mint --scope read --env acme/prod       # for CI: GV_TOKEN + GV_SERVER
gv config set app --format toml --env acme/prod < app.toml
gv ui                                            # the vault in your browser, on loopback
```

## As a library

```rust,no_run
use clap::{Parser, Subcommand};
use galata_vault_cli::{Branding, Context};

const ACME: Branding = Branding {
    bin_name: "acme",
    about: "acme: deploys and their secrets",
    home_env: "ACME_HOME",
    env_prefix: "ACME_",
    dir_file: ".acme.toml",
    keychain_service: "acme",
    kit_header: "acme",
    message_prefix: "acme",
    mcp_binary: "acme-mcp",
};

#[derive(Parser)]
struct Acme {
    #[arg(long, global = true)]
    env: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(flatten)]
    Vault(galata_vault_cli::Command),
    /// Deploy the current build.
    Deploy { target: String },
}

fn main() -> anyhow::Result<()> {
    let cli = Acme::parse();
    let mut ctx = Context::new(ACME);
    match cli.command {
        Cmd::Vault(command) => galata_vault_cli::dispatch(&mut ctx, cli.env.as_deref(), command)?,
        Cmd::Deploy { target } => ctx.say(&format!("deploying to {target}")),
    }
    Ok(())
}
```

See `examples/branded.rs`. Every vault operation is the `galata-vault` SDK's;
this crate adds the terminal, the OS keychain (or a 0600 file) and printing.

## Platforms

Linux and macOS are supported. Windows builds, and is build-only for 0.1:
where a token file's permissions cannot be checked, it is refused.

Licensed under the MIT licence. The fonts bundled for `gv ui` (IBM Plex Sans, IBM Plex Mono and
Newsreader, the same faces as the docs site) are under the SIL Open Font License
(`src/ui/assets/OFL.txt`).
