//! Tokens, rotation and re-rooting.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, bail};
use galata_vault::owner::{Owner, RekeyOutcome, RetiresAllTokens};
use galata_vault::{Scope, StateStore};
use galata_vault_keys::TokenKeys;
use galata_vault_proto::codec::FormatError;
use galata_vault_proto::ids::TokenId;
use galata_vault_proto::path::EnvPath;
use zeroize::Zeroizing;

use crate::context::Context;
use crate::kit;
use crate::secrets::{Opened, Target};
use crate::select::selected_env;
use crate::util::{fmt_time, parse_ttl};

pub fn mint(
    ctx: &mut Context,
    env: Option<&str>,
    scope: &str,
    ttl: Option<&str>,
    only: &[String],
) -> anyhow::Result<()> {
    let scope = Scope::parse(scope)
        .context("--scope must be meta, append, read, admin, config or config-write")?;
    if !only.is_empty() && scope != Scope::Read {
        bail!("--only applies to read tokens");
    }
    let ttl = ttl.map(parse_ttl).transpose()?.unwrap_or(0);
    let mut target = Target::select(ctx, env)?;
    target.owner_only(ctx, "minting a token")?;
    let vault = target.open_owner()?;
    let token = vault.mint(scope, ttl, only)?;
    let label = vault.label().to_owned();
    target.done_owner(vault)?;
    ctx.say(&format!(
        "minted {scope} token {} for {label}, expiring {}.\n\
         this is the only time it is shown; store it now.",
        token.id(),
        fmt_time(token.expires_at())
    ));
    ctx.out_line(token.expose())?;
    Ok(())
}

pub fn ls(ctx: &mut Context, env: Option<&str>) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    // Not owner-only: the protocol gives the token list to the owner and to
    // an admin token (docs/spec/http-api.md#2), and the SDK refuses every
    // other scope by name.
    let opened = target.open()?;
    let rows = match &opened {
        Opened::Owner(env) => env.tokens()?,
        Opened::Token(vault) => vault.tokens()?,
    };
    target.done(opened)?;
    for t in rows {
        let only = t
            .only
            .map_or(String::new(), |l| format!("  only {}", l.join(",")));
        ctx.out_line(&format!(
            "{}  {:<6}  created {}  expires {}{only}",
            t.id,
            t.scope.to_string(),
            fmt_time(t.created_at),
            fmt_time(t.expires_at)
        ))?;
    }
    Ok(())
}

pub fn revoke(ctx: &mut Context, env: Option<&str>, id: &str, rotate: bool) -> anyhow::Result<()> {
    let bin = ctx.branding().bin_name;
    let id = TokenId::from_hex(id).map_err(|_| {
        anyhow::anyhow!("a token id is 32 hexadecimal characters (see {bin} token ls)")
    })?;
    let mut target = Target::select(ctx, env)?;
    // Not owner-only: `admin` may revoke (docs/spec/http-api.md#2). Rotating
    // still is, so an admin token is told which half it cannot do rather
    // than being refused the whole command.
    let opened = target.open()?;
    let label = opened.label().to_owned();
    let revocation = match &opened {
        Opened::Owner(env) => env.revoke(&id, rotate)?,
        Opened::Token(vault) => {
            if rotate {
                bail!(
                    "--rotate needs the environment's owner key: rotation re-encrypts every \
                     record and reseals every bundle, which only the owner can do. An admin \
                     token may revoke without it (unset {} to act as the owner).",
                    ctx.branding().var("TOKEN")
                );
            }
            vault.revoke(&id)?
        }
    };
    target.done(opened)?;
    if let Some(generation) = revocation.rotated_to {
        ctx.say(&format!(
            "revoked token {id} and rotated {label} to generation {generation}.\n\
             values the token could already read are still known to its holder; change them."
        ));
        return Ok(());
    }
    ctx.say(&format!("revoked token {id} in {label}."));
    // Every scope but meta holds a key that outlives revocation: a key that
    // decrypts what its holder copied, or a writer key whose signatures
    // verify until the vault moves to a new generation.
    if revocation.forward_only() {
        ctx.say(&format!(
            "warning: revocation is forward-only. This {} token held {}, so its holder\n\
             can still decrypt any ciphertext of {label} they already copied, and records signed with a\n\
             writer key it held still verify. Run `{bin} rotate --env {label}` (or next time\n\
             `{bin} token revoke <id> --rotate`) to move to fresh keys, and change any secret you believe\n\
             was exposed.",
            revocation.scope,
            revocation.held_keys()
        ));
    }
    Ok(())
}

pub fn rotate(ctx: &mut Context, env: Option<&str>) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    target.owner_only(ctx, "rotating a vault")?;
    let vault = target.open_owner()?;
    let generation = vault.rotate()?;
    let label = vault.label().to_owned();
    target.done_owner(vault)?;
    ctx.say(&format!("rotated {label} to generation {generation}"));
    Ok(())
}

/// Report a leaked token: the server revokes it on proof of possession. The
/// token string comes from a file or stdin, never an argument, and only a
/// signature made with it is sent.
pub fn report(ctx: &mut Context, file: Option<&Path>, server: Option<&str>) -> anyhow::Result<()> {
    let raw = match file {
        Some(f) => {
            Zeroizing::new(std::fs::read(f).with_context(|| format!("reading {}", f.display()))?)
        }
        None => ctx.read_value("the leaked token")?,
    };
    let text = std::str::from_utf8(&raw)
        .map_err(|_| anyhow::anyhow!("that is not a gvt1_ token"))?
        .trim();
    let token = TokenKeys::parse(text).map_err(|e| match e {
        FormatError::UnknownVersion { found } => {
            anyhow::anyhow!("that token carries version {found}, which this build does not know")
        }
        _ => anyhow::anyhow!("that is not a valid gvt1_ token (its checksum does not match)"),
    })?;
    let server = match server {
        Some(s) => s.to_owned(),
        None => match ctx.var("SERVER") {
            Some(s) => s,
            None => ctx
                .owner()?
                .state()
                .server_for_vault(&token.vault_id())
                .map(str::to_owned)
                .with_context(|| {
                    format!(
                        "no project here knows the token's vault; pass --server (or set {})",
                        ctx.branding().var("SERVER")
                    )
                })?,
        },
    };
    let api = ctx.api(&server)?;
    let report = galata_vault::report_leaked_token(&api, text)?;
    let id = report.token_id;
    if report.revoked {
        ctx.say(&format!("reported token {id}; {server} revoked it."));
    } else {
        ctx.say(&format!(
            "reported token {id}; {server} already had nothing to revoke."
        ));
    }
    ctx.say("its owner should still rotate the vault and change what the token could read.");
    Ok(())
}

// ---------------------------------------------------------------- rekey

/// The test hook of debug builds only: stop a rekey right after the named
/// step is recorded, as a crash would, so `--resume` and `--abort` are
/// exercised against a real half-done rekey. It fails the state save that
/// records the step, after the save is done. A release `gv` has no hook.
#[cfg(debug_assertions)]
mod interrupt {
    use std::sync::{Arc, Mutex};

    use galata_vault::state::{LocalState, RekeyStep};
    use galata_vault::{StateStore, StoreError};

    pub struct Interrupt {
        pub inner: Arc<dyn StateStore>,
        pub step: String,
        pub var: String,
        pub bin: &'static str,
        pub last: Mutex<Option<RekeyStep>>,
    }

    impl StateStore for Interrupt {
        fn load(&self) -> Result<LocalState, StoreError> {
            let state = self.inner.load()?;
            *self.last.lock().unwrap_or_else(|p| p.into_inner()) =
                state.rekey.as_ref().map(|p| p.step);
            Ok(state)
        }

        fn save(&self, state: &LocalState) -> Result<(), StoreError> {
            self.inner.save(state)?;
            let now = state.rekey.as_ref().map(|p| (p.step, p.path.clone()));
            let previous = std::mem::replace(
                &mut *self.last.lock().unwrap_or_else(|p| p.into_inner()),
                now.as_ref().map(|(s, _)| *s),
            );
            if let Some((step, path)) = now
                && step.as_str() == self.step
                && previous != Some(step)
            {
                return Err(StoreError::new(format!(
                    "the rekey of {path} stopped after its {} step ({}); `{} rekey --resume` finishes it",
                    step.as_str(),
                    self.var,
                    self.bin
                )));
            }
            Ok(())
        }
    }
}

/// The owner for a rekey: in a debug build, with the interruption hook when
/// `<prefix>TEST_REKEY_INTERRUPT` names a step.
fn rekey_owner(ctx: &Context) -> anyhow::Result<Owner> {
    let state: Arc<dyn StateStore> = ctx.state_store()?;
    #[cfg(debug_assertions)]
    if let Some(step) = ctx.var("TEST_REKEY_INTERRUPT") {
        return ctx.owner_over(Arc::new(interrupt::Interrupt {
            inner: state,
            step,
            var: ctx.branding().var("TEST_REKEY_INTERRUPT"),
            bin: ctx.branding().bin_name,
            last: std::sync::Mutex::new(None),
        }));
    }
    ctx.owner_over(state)
}

/// Re-root a node: a fresh random key
/// for it, keys derived from that for everything below, fresh vaults holding
/// copies of every record, and the old vaults (with every token in them)
/// deleted. The new kit is written before anything changes on the server;
/// each step is recorded before the next begins, so `--resume` finishes an
/// interrupted rekey and `--abort` undoes one that has not yet relinked its
/// parent.
pub fn rekey(
    ctx: &mut Context,
    env: Option<&str>,
    path: Option<&str>,
    kit_out: Option<&Path>,
    resume: bool,
    abort: bool,
) -> anyhow::Result<()> {
    let bin = ctx.branding().bin_name;
    if resume && abort {
        bail!("--resume and --abort cannot be combined");
    }
    let mut owner = rekey_owner(ctx)?;
    if resume || abort {
        let plan = owner
            .rekey_in_progress()
            .cloned()
            .context("no rekey is in progress here")?;
        if let Some(p) = path
            && p != plan.path
        {
            bail!("the rekey in progress is for {}, not {p}", plan.path);
        }
        if kit_out.is_some() {
            bail!(
                "--kit applies when a rekey starts; this one's kit is {}",
                plan.kit.display()
            );
        }
        if abort {
            let aborted = owner.rekey_abort(None)?;
            match std::fs::remove_file(&aborted.kit) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => ctx.say(&format!(
                    "warning: could not delete the unused kit {}: {e}",
                    aborted.kit.display()
                )),
            }
            let p = aborted.path;
            ctx.say(&format!(
                "aborted the rekey of {p}: its new vaults and kit are deleted, and {p} is unchanged"
            ));
            return Ok(());
        }
        let outcome = owner.rekey_resume(None)?;
        return finished(ctx, &outcome);
    }
    if let Some(plan) = owner.rekey_in_progress() {
        bail!(
            "a rekey of {} is in progress; finish it with `{bin} rekey --resume` or undo it with `{bin} rekey --abort`",
            plan.path
        );
    }
    let path: EnvPath = match path {
        Some(p) => p
            .parse()
            .map_err(|e| anyhow::anyhow!("{p:?} is not an environment path: {e}"))?,
        None => selected_env(ctx.branding(), env)?,
    };
    owner.require_known(&path)?;
    let pending = owner.begin_rekey(&path, RetiresAllTokens)?;
    let kit_path = kit_out.map_or_else(
        || {
            let base = pending.kit().file_name();
            let id = pending.new_vault_id();
            PathBuf::from(format!(
                "{}-{}.gvkit",
                base.trim_end_matches(".gvkit"),
                &id[..id.len().min(8)]
            ))
        },
        Path::to_path_buf,
    );
    // The new key is on disk before anything changes on the server: an
    // interruption can always be resumed.
    kit::write(ctx.branding(), pending.kit(), &kit_path)?;
    let kit_path = std::fs::canonicalize(&kit_path).unwrap_or(kit_path);
    let outcome = pending.confirm_kit_stored(kit_path)?;
    finished(ctx, &outcome)
}

fn finished(ctx: &Context, o: &RekeyOutcome) -> anyhow::Result<()> {
    let path = &o.path;
    ctx.say(&format!(
        "rekeyed {path}: {} environment(s) now live in fresh vaults (new vault id {}); the old vaults are deleted.\n\
         the new kit is {} (mode 0600); any earlier kit for {path} no longer works.",
        o.nodes,
        o.new_vault_id,
        o.kit.display()
    ));
    if o.remint.is_empty() {
        ctx.say("no token existed in the old vaults.");
    } else {
        ctx.say(&format!(
            "these tokens died with the old vaults; mint replacements with `{} token mint`:",
            ctx.branding().bin_name
        ));
        for t in &o.remint {
            ctx.say_raw(&format!("  {t}"));
        }
    }
    Ok(())
}
