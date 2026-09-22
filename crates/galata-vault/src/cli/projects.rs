//! Projects and environments: init, env add/ls/rm/repair, key export and
//! import, recover. Each handler parses, calls the owner API, and says what
//! happened.

use std::path::{Path, PathBuf};

use crate::owner::{Discovery, GrantsSubtreeOwnership, Kit, KitKind};
use crate::proto::path::EnvPath;
use anyhow::bail;

use crate::cli::context::Context;
use crate::cli::kit;

fn parse_path(s: &str) -> anyhow::Result<EnvPath> {
    s.parse::<EnvPath>()
        .map_err(|e| anyhow::anyhow!("{s:?} is not an environment path: {e}"))
}

pub fn init(
    ctx: &mut Context,
    project: &str,
    server: &str,
    kit_out: Option<&Path>,
) -> anyhow::Result<()> {
    let branding = *ctx.branding();
    let mut owner = ctx.owner()?;
    // The kit exists, and the user has confirmed it is safe, before anything
    // exists on the server.
    let pending = owner.begin_init(project, server)?;
    let kit_path = kit_out.map_or_else(
        || PathBuf::from(pending.recovery_kit().file_name()),
        Path::to_path_buf,
    );
    kit::write(&branding, pending.recovery_kit(), &kit_path)?;
    ctx.say(&format!(
        "wrote the recovery kit for {project} to {} (mode 0600).\n\
         it is the ONLY way to recover {project}: there is no account and no reset.\n\
         store it offline or in a password manager, then delete this copy.",
        kit_path.display()
    ));
    if let Err(e) = ctx.confirm("Type \"saved\" once the kit is stored safely:", "saved") {
        let _ = std::fs::remove_file(&kit_path);
        return Err(e);
    }
    match pending.confirm_kit_stored() {
        Ok(info) => {
            ctx.say(&format!("created project {project} on {}", info.server));
            Ok(())
        }
        Err(e) => {
            // Once the vault exists the kit is the only copy of its key.
            if !e.vault_created() {
                let _ = std::fs::remove_file(&kit_path);
            }
            Err(e.into_error().into())
        }
    }
}

pub fn env_add(ctx: &mut Context, path: &str) -> anyhow::Result<()> {
    let path = parse_path(path)?;
    ctx.owner()?.env_add(&path)?;
    ctx.say(&format!("created {path}"));
    Ok(())
}

pub fn env_ls(ctx: &mut Context, filter: Option<&str>) -> anyhow::Result<()> {
    let filter = filter.map(parse_path).transpose()?;
    let mut owner = ctx.owner()?;
    let projects: Vec<EnvPath> = match &filter {
        Some(p) => {
            owner.state().project(p)?;
            vec![EnvPath::project(p.project_name().clone())]
        }
        None => owner
            .state()
            .projects
            .keys()
            .filter_map(|k| k.parse().ok())
            .collect(),
    };
    for project in &projects {
        if let Err(e) = owner.refresh(project) {
            ctx.say(&format!(
                "warning: showing the cached tree for {project}: {}",
                ctx.describe(&e)
            ));
        }
    }
    owner.save()?;
    for project in &projects {
        let p = owner.state().project(project)?;
        for (path, node) in &p.tree {
            let parsed = parse_path(path)?;
            if filter.as_ref().is_some_and(|f| !parsed.starts_with(f)) {
                continue;
            }
            let mut notes = Vec::new();
            if p.held.contains(path) {
                notes.push("key held");
            }
            if node.sealed {
                notes.push("rekeyed");
            }
            if notes.is_empty() {
                ctx.out_line(path)?;
            } else {
                ctx.out_line(&format!("{path}  ({})", notes.join(", ")))?;
            }
        }
    }
    Ok(())
}

pub fn env_rm(ctx: &mut Context, path: &str, recursive: bool) -> anyhow::Result<()> {
    let path = parse_path(path)?;
    // Each deletion is said as it happens, through the owner's events.
    let removal = ctx.owner()?.env_remove(&path, recursive)?;
    if let Some(parent) = removal.parent_not_updated {
        ctx.say(&format!(
            "note: the key for {parent} is not held here, so its children record still lists {}",
            path.last()
        ));
    }
    Ok(())
}

pub fn env_repair(ctx: &mut Context, path: &str) -> anyhow::Result<()> {
    let path = parse_path(path)?;
    let repair = ctx.owner()?.env_repair(&path)?;
    if repair.created {
        ctx.say(&format!(
            "re-created {path} at its vault id; its secrets did not survive expiry, its {} child environment(s) are listed again",
            repair.children
        ));
    } else {
        ctx.say(&format!(
            "{path} exists; its children record lists the {} cached child environment(s)",
            repair.children
        ));
    }
    for child in repair.lost {
        ctx.say(&format!(
            "warning: {child} was rekeyed and its key was only in the expired record; import its kit with {} key import",
            ctx.branding().bin_name
        ));
    }
    Ok(())
}

pub fn key_export(
    ctx: &mut Context,
    path: &str,
    out: Option<&Path>,
    yes: bool,
) -> anyhow::Result<()> {
    let path = parse_path(path)?;
    let mut owner = ctx.owner()?;
    owner.require_known(&path)?;
    ctx.say(&format!(
        "whoever holds this kit will OWN {path} and everything beneath it: they can read,\n\
         change and delete every secret there, mint tokens, and rekey it away from you.\n\
         it gives no access to anything above {path}."
    ));
    if !yes {
        ctx.confirm(&format!("Type {path} to write the kit:"), &path.to_string())?;
    }
    let kit = owner.export_kit(&path, GrantsSubtreeOwnership)?;
    let out = out.map_or_else(|| PathBuf::from(kit.file_name()), Path::to_path_buf);
    kit::write(ctx.branding(), &kit, &out)?;
    ctx.say(&format!("wrote {} (mode 0600)", out.display()));
    Ok(())
}

fn imported(ctx: &Context, kit: &Kit, found: &Discovery) {
    ctx.say(&format!(
        "imported {} from {}; found:",
        found.root,
        kit.server()
    ));
    for p in &found.found {
        ctx.say_raw(&format!("  {p}"));
    }
}

pub fn key_import(ctx: &mut Context, kit_path: &Path) -> anyhow::Result<()> {
    let kit = kit::read(kit_path)?;
    let found = ctx.owner()?.import(&kit)?;
    imported(ctx, &kit, &found);
    Ok(())
}

pub fn recover(ctx: &mut Context, kit_path: &Path) -> anyhow::Result<()> {
    let kit = kit::read(kit_path)?;
    if kit.kind() != KitKind::Recovery {
        bail!(
            "this is a delegation kit for {}; import it with {} key import",
            kit.path(),
            ctx.branding().bin_name
        );
    }
    let found = ctx
        .owner()?
        .recover(&kit)
        .map_err(|e| anyhow::Error::new(e).context("recovering the project"))?;
    imported(ctx, &kit, &found);
    Ok(())
}
