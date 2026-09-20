//! `gv-mcp [--config <mcp.toml>]`: serve MCP on stdin/stdout.
//!
//! stdout is the protocol channel, so every diagnostic goes to stderr. No
//! socket is ever opened for listening.

use std::path::PathBuf;
use std::process::ExitCode;

use galata_vault_mcp::{McpServer, config, open_all};
use rmcp::ServiceExt;
use rmcp::transport::stdio;

fn config_path() -> anyhow::Result<PathBuf> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.as_slice() {
        [] => config::default_path(),
        [flag, path] if flag == "--config" => Ok(PathBuf::from(path)),
        _ => anyhow::bail!("usage: gv-mcp [--config <mcp.toml>]"),
    }
}

fn run() -> anyhow::Result<()> {
    // It holds tokens and name keys: no core files.
    if let Err(e) = rlimit::setrlimit(rlimit::Resource::CORE, 0, 0) {
        eprintln!("gv-mcp: warning: could not disable core dumps: {e}");
    }
    let path = config_path()?;
    let envs = open_all(config::load(&path)?)?;
    let server = McpServer::new(envs);
    eprintln!(
        "gv-mcp: serving metadata for {} over stdio",
        server.paths().join(", ")
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let service = server.serve(stdio()).await?;
        service.waiting().await?;
        anyhow::Ok(())
    })
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("gv-mcp: {e:#}");
            ExitCode::FAILURE
        }
    }
}
