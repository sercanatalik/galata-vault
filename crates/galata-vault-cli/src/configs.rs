//! Config document commands for the selected environment, as its owner or
//! (in token mode) as a token holder: the same selection, pinned server and
//! hygiene as the secret commands. A body comes from a file or stdin, never
//! from an argument.

use std::path::Path;

use anyhow::{Context as _, bail};
use galata_vault::{ConfigFormat, Error, NewConfig, scan_literals, validate};
use zeroize::Zeroizing;

use crate::context::Context;
use crate::secrets::{Target, conflict_text, refuse_reserved, writer_text};
use crate::util::fmt_time;

fn read_body(
    ctx: &mut Context,
    name: &str,
    file: Option<&Path>,
) -> anyhow::Result<Zeroizing<Vec<u8>>> {
    let body = match file {
        Some(path) => Zeroizing::new(
            std::fs::read(path).with_context(|| format!("reading {}", path.display()))?,
        ),
        None => {
            if ctx.prompter().stdin_is_terminal() {
                bail!("pipe the body of config {name} on stdin, or pass --file");
            }
            ctx.prompter().read_to_end()?
        }
    };
    if body.is_empty() {
        bail!("the body of config {name} is empty");
    }
    Ok(body)
}

pub fn set(
    ctx: &mut Context,
    env: Option<&str>,
    name: &str,
    format: ConfigFormat,
    file: Option<&Path>,
    allow_literals: bool,
) -> anyhow::Result<()> {
    refuse_reserved(ctx.branding(), name)?;
    let body = read_body(ctx, name, file)?;
    // Checked before any request. Errors name a line, never the text.
    validate(format, &body).with_context(|| format!("config {name}"))?;
    if !allow_literals {
        scan_literals(&body)
            .map_err(|e| anyhow::anyhow!("config {name}: {e} (--allow-literals)"))?;
    }
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let mut config = NewConfig::new(format, body.to_vec());
    if allow_literals {
        config = config.allow_literals();
    }
    let result = vault.set_config(name, config);
    let label = vault.label().to_owned();
    target.done(vault)?;
    match result {
        Ok(v) => {
            ctx.say(&format!(
                "set config {name} in {label} (version {v}, {format})"
            ));
            Ok(())
        }
        Err(Error::Conflict {
            name: n,
            expected,
            current,
            ..
        }) => bail!(
            "{label}: {}; nothing was overwritten — check the new body and run {} config set again",
            conflict_text(&n, &expected, current),
            ctx.branding().bin_name
        ),
        Err(e) => Err(e.into()),
    }
}

pub fn get(
    ctx: &mut Context,
    env: Option<&str>,
    name: &str,
    version: Option<u64>,
) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let doc = match version {
        None => vault.config(name)?,
        Some(v) => vault.config_version(name, v)?,
    };
    target.done(vault)?;
    // The stored bytes exactly. Only a terminal gets a final newline, so the
    // prompt does not run on.
    ctx.out(doc.expose())?;
    if ctx.output().stdout_is_terminal() && !doc.expose().ends_with(b"\n") {
        ctx.out(b"\n")?;
    }
    Ok(())
}

pub fn ls(ctx: &mut Context, env: Option<&str>, all: bool) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let items = if all {
        vault.list_configs_all()?
    } else {
        vault.list_configs()?
    };
    target.done(vault)?;
    let width = items.iter().map(|i| i.name.len()).max().unwrap_or(0);
    for i in items {
        let deleted = if i.deleted { "  (deleted)" } else { "" };
        ctx.out_line(&format!(
            "{:<width$}  v{:<4} {}{deleted}",
            i.name,
            i.version,
            fmt_time(i.updated_at)
        ))?;
    }
    Ok(())
}

pub fn history(ctx: &mut Context, env: Option<&str>, name: &str) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let versions = vault.config_history(name)?;
    let label = vault.label().to_owned();
    target.done(vault)?;
    if versions.is_empty() {
        bail!("{label}: no config named {name}");
    }
    for v in versions {
        let what = if v.tombstone {
            "deleted".to_owned()
        } else {
            format!("{} bytes", v.size)
        };
        ctx.out_line(&format!(
            "v{:<4} {}  {:<14} {what}",
            v.version,
            fmt_time(v.written_at),
            writer_text(&v.written_by)
        ))?;
    }
    Ok(())
}

pub fn rm(ctx: &mut Context, env: Option<&str>, name: &str) -> anyhow::Result<()> {
    refuse_reserved(ctx.branding(), name)?;
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let label = vault.label().to_owned();
    let result = vault.delete_config(name, None);
    target.done(vault)?;
    match result {
        Ok(v) => {
            ctx.say(&format!(
                "deleted config {name} in {label} (tombstone version {v})"
            ));
            Ok(())
        }
        Err(Error::Conflict {
            name: n,
            expected,
            current,
            ..
        }) => bail!(
            "{label}: {}; nothing was deleted",
            conflict_text(&n, &expected, current)
        ),
        Err(e) => Err(e.into()),
    }
}
