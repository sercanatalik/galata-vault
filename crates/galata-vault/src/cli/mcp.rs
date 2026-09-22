//! `mcp setup <project>`, which gives the MCP server one meta token per
//! environment, and `mcp`, which execs the MCP server.
//!
//! The MCP server never receives a node key: only meta tokens, whose bundles
//! hold the name key and not the vault private key.

use std::path::{Path, PathBuf};

use crate::Scope;
use crate::keys::TokenKeys;
use crate::proto::mcp::{MCP_CONFIG_FILE, McpConfig, McpEntry};
use crate::proto::path::{EnvPath, Segment};
use anyhow::{Context as _, bail};
use zeroize::Zeroizing;

use crate::cli::context::Context;
use crate::cli::fsutil::{require_private, write_private};
use crate::cli::util::{fmt_time, parse_ttl};

fn load_existing(file: &Path) -> anyhow::Result<McpConfig> {
    if !file.exists() {
        return Ok(McpConfig::default());
    }
    require_private(file)?;
    let text = Zeroizing::new(std::fs::read_to_string(file)?);
    // Never quote the file in an error: it holds tokens.
    toml::from_str(&text).map_err(|_| {
        anyhow::anyhow!(
            "{} is not a valid MCP server configuration; move it aside and run setup again",
            file.display()
        )
    })
}

pub fn setup(ctx: &mut Context, project: &str, ttl: Option<&str>) -> anyhow::Result<()> {
    let root = EnvPath::project(
        Segment::new(project)
            .map_err(|e| anyhow::anyhow!("{project:?} is not a project name: {e}"))?,
    );
    let ttl = ttl.map(parse_ttl).transpose()?.unwrap_or(0);
    let mut owner = ctx.owner()?;
    let server = owner.state().project(&root)?.server.clone();
    if let Err(e) = owner.refresh(&root) {
        ctx.say(&format!(
            "warning: using the cached tree for {project}: {}",
            ctx.describe(&e)
        ));
    }
    let file = ctx.home()?.join(MCP_CONFIG_FILE);
    let mut config = load_existing(&file)?;

    let mut paths: Vec<EnvPath> = owner
        .state()
        .project(&root)?
        .tree
        .keys()
        .filter_map(|k| k.parse().ok())
        .collect();
    paths.sort();
    let mut fresh = Vec::new();
    for path in &paths {
        let vault = match owner.environment(path) {
            Ok(v) => v,
            Err(e) => {
                ctx.say(&format!("warning: skipping {path}: {}", ctx.describe(&e)));
                continue;
            }
        };
        let token = vault.mint(Scope::Meta, ttl, &[])?;
        // The token this path had before is no longer needed.
        if let Some(previous) = config.env.iter().find(|e| &e.path == path)
            && let Ok(old) = TokenKeys::parse(&previous.token)
            && vault.revoke(&old.id(), false).is_err()
        {
            ctx.say(&format!(
                "note: {path}: could not revoke the previous meta token {}",
                old.id()
            ));
        }
        ctx.say(&format!(
            "{path}: meta token {} (expires {})",
            token.id(),
            fmt_time(token.expires_at())
        ));
        fresh.push(McpEntry {
            path: path.clone(),
            server: server.clone(),
            token: token.expose().to_owned(),
        });
    }
    if fresh.is_empty() {
        bail!("no environment of {project} could be opened; nothing was written");
    }

    config
        .env
        .retain(|e| e.path.project_name() != root.project_name());
    config.env.extend(fresh);
    config.env.sort_by(|a, b| a.path.cmp(&b.path));
    let bin = ctx.branding().bin_name;
    let text = Zeroizing::new(format!(
        "# {} configuration, written by `{bin} mcp setup`. Mode 0600.\n\
         # Each entry is a meta token: it lists one environment's names and audit\n\
         # log, and cannot decrypt any value.\n\n{}",
        ctx.branding().mcp_binary,
        toml::to_string(&config)?
    ));
    write_private(&file, text.as_bytes())?;
    owner.save()?;
    ctx.say(&format!(
        "wrote {} (mode 0600).\n\
         point your MCP client at: {{\"command\": \"{bin}\", \"args\": [\"mcp\"]}}",
        file.display()
    ));
    Ok(())
}

/// Replace this process with the MCP server: the one next to this binary,
/// else on PATH.
pub fn exec(ctx: &Context, config: Option<&Path>) -> anyhow::Result<()> {
    let name = ctx.branding().mcp_binary;
    let beside = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join(name)))
        .filter(|p| p.is_file());
    let bin = beside.unwrap_or_else(|| PathBuf::from(name));
    let mut cmd = std::process::Command::new(&bin);
    if let Some(config) = config {
        cmd.arg("--config").arg(config);
    }
    let err = crate::cli::util::replace_process(cmd);
    Err(err).with_context(|| {
        format!(
            "could not run {} (install {name} next to {} or on PATH)",
            bin.display(),
            ctx.branding().bin_name
        )
    })
}
