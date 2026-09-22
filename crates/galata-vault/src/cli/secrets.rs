//! Secret commands for the selected environment, as its owner or (in token
//! mode) as a token holder.

use std::ffi::OsString;
use std::ops::Deref;
use std::path::Path;

use crate::keys::TokenKeys;
use crate::owner::{Environment, Owner};
use crate::proto::children::{RESERVED_PREFIX, is_reserved_name};
use crate::proto::codec::FormatError;
use crate::proto::path::EnvPath;
use crate::proto::tolerant::Tolerant;
use crate::{Actor, Api, Error, Expected, SecretSet, Vault};
use anyhow::{Context as _, bail};
use zeroize::Zeroizing;

use crate::cli::branding::Branding;
use crate::cli::command_line::Format;
use crate::cli::context::Context;
use crate::cli::fsutil::create_private;
use crate::cli::select::selected_env;
use crate::cli::util::fmt_time;

/// Where a command's vault comes from: a known environment and its owner
/// key, or `<prefix>TOKEN` + `<prefix>SERVER`.
pub(crate) struct Target {
    mode: Mode,
}

enum Mode {
    Token {
        api: Api,
        token: Option<Zeroizing<String>>,
    },
    Owner {
        owner: Box<Owner>,
        path: EnvPath,
    },
}

/// An opened vault: a token client, or an environment opened by its owner.
pub(crate) enum Opened {
    Token(Box<Vault>),
    Owner(Box<Environment>),
}

impl Deref for Opened {
    type Target = Vault;

    fn deref(&self) -> &Vault {
        match self {
            Opened::Token(v) => v,
            Opened::Owner(e) => e,
        }
    }
}

impl Target {
    pub fn select(ctx: &Context, env: Option<&str>) -> anyhow::Result<Target> {
        let b = ctx.branding();
        let (token_var, server_var) = (b.var("TOKEN"), b.var("SERVER"));
        if let Some(token) = std::env::var_os(&token_var).filter(|t| !t.is_empty()) {
            if env.is_some() {
                bail!(
                    "{token_var} is set: token mode acts on the token's own vault and takes no --env"
                );
            }
            let server = std::env::var(&server_var).with_context(|| {
                format!("{token_var} is set without {server_var}; token mode needs both")
            })?;
            let token = Zeroizing::new(token.to_string_lossy().into_owned());
            // Checked locally: a mistyped token never reaches the server,
            // and the error never repeats it.
            TokenKeys::parse(&token).map_err(|e| match e {
                FormatError::UnknownVersion { found } => anyhow::anyhow!(
                    "{token_var} carries version {found}, which this build does not know"
                ),
                _ => anyhow::anyhow!(
                    "{token_var} is not a valid gvt1_ token (its checksum does not match)"
                ),
            })?;
            return Ok(Target {
                mode: Mode::Token {
                    api: ctx.api(&server)?,
                    token: Some(token),
                },
            });
        }
        let path = selected_env(b, env)?;
        let owner = ctx.owner()?;
        owner.require_known(&path)?;
        Ok(Target {
            mode: Mode::Owner {
                owner: Box::new(owner),
                path,
            },
        })
    }

    pub fn owner_only(&self, ctx: &Context, what: &str) -> anyhow::Result<()> {
        if matches!(self.mode, Mode::Token { .. }) {
            bail!(
                "{what} needs the environment's owner key; a token cannot do it, whatever its scope (unset {} to act as the owner)",
                ctx.branding().var("TOKEN")
            );
        }
        Ok(())
    }

    pub fn open(&mut self) -> anyhow::Result<Opened> {
        match &mut self.mode {
            Mode::Token { api, token } => {
                let token = token
                    .take()
                    .context("the token was already used by this command")?;
                Ok(Opened::Token(Box::new(Vault::with_api(&token, api)?)))
            }
            Mode::Owner { owner, path } => Ok(Opened::Owner(Box::new(owner.environment(path)?))),
        }
    }

    /// The environment, opened by its owner (after [`Target::owner_only`]).
    pub fn open_owner(&mut self) -> anyhow::Result<Environment> {
        match self.open()? {
            Opened::Owner(env) => Ok(*env),
            Opened::Token(_) => bail!("this needs the environment's owner key"),
        }
    }

    pub fn owner(&mut self) -> Option<&mut Owner> {
        match &mut self.mode {
            Mode::Owner { owner, .. } => Some(owner),
            Mode::Token { .. } => None,
        }
    }

    /// Save local state. Token mode keeps none.
    pub fn finish(&mut self) -> anyhow::Result<()> {
        if let Some(owner) = self.owner() {
            owner.save()?;
        }
        Ok(())
    }

    /// Remember what the vault showed (its pins) and save local state.
    pub fn done(&mut self, opened: Opened) -> anyhow::Result<()> {
        match opened {
            Opened::Owner(env) => self.done_owner(*env),
            Opened::Token(_) => Ok(()),
        }
    }

    pub fn done_owner(&mut self, env: Environment) -> anyhow::Result<()> {
        if let Some(owner) = self.owner() {
            owner.close(env)?;
        }
        Ok(())
    }
}

pub(crate) fn refuse_reserved(branding: &Branding, name: &str) -> anyhow::Result<()> {
    if is_reserved_name(name) {
        bail!(
            "names beginning with {RESERVED_PREFIX:?} are reserved for {}'s own records",
            branding.bin_name
        );
    }
    if name.is_empty() {
        bail!("a secret name cannot be empty");
    }
    Ok(())
}

/// A conflict's text: `name changed on the server: expected …, the server
/// has version …`.
pub(crate) fn conflict_text(name: &str, expected: &Expected, current: Option<u64>) -> String {
    format!(
        "{name} changed on the server: expected {expected}, the server has version {}",
        current.map_or("none".to_owned(), |v| v.to_string())
    )
}

pub fn set(ctx: &mut Context, env: Option<&str>, name: &str) -> anyhow::Result<()> {
    refuse_reserved(ctx.branding(), name)?;
    let mut target = Target::select(ctx, env)?;
    let value = ctx.read_value(name)?;
    let vault = target.open()?;
    let result = vault.set_secret(name, &value);
    let label = vault.label().to_owned();
    target.done(vault)?;
    match result {
        Ok(v) => {
            ctx.say(&format!("set {name} in {label} (version {v})"));
            Ok(())
        }
        Err(Error::Conflict {
            name: n,
            expected,
            current,
            ..
        }) => bail!(
            "{label}: {}; nothing was overwritten — check the new value and run {} set again",
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
    let value = match version {
        None => vault.secret(name)?,
        Some(v) => vault.secret_version(name, v)?,
    };
    target.done(vault)?;
    ctx.out(value.expose())?;
    if ctx.output().stdout_is_terminal() {
        ctx.out(b"\n")?;
    }
    Ok(())
}

pub fn ls(ctx: &mut Context, env: Option<&str>, all: bool) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let items = if all {
        vault.list_all()?
    } else {
        vault.list()?
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
    let versions = vault.history(name)?;
    let label = vault.label().to_owned();
    target.done(vault)?;
    if versions.is_empty() {
        bail!("{label}: no secret named {name}");
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
    let result = vault.delete_secret(name, None);
    target.done(vault)?;
    match result {
        Ok(v) => {
            ctx.say(&format!(
                "deleted {name} in {label} (tombstone version {v})"
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

/// Every readable, live secret; `only` restricts and each must exist.
fn readable(vault: &Vault, only: &[String]) -> anyhow::Result<SecretSet> {
    let only: Vec<&str> = only.iter().map(String::as_str).collect();
    Ok(vault.readable((!only.is_empty()).then_some(only.as_slice()))?)
}

fn is_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

pub fn run(
    ctx: &mut Context,
    env: Option<&str>,
    only: &[String],
    command: &[OsString],
) -> anyhow::Result<()> {
    let Some((program, args)) = command.split_first() else {
        bail!("no command to run");
    };
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let secrets = readable(&vault, only)?;
    let label = vault.label().to_owned();
    target.done(vault)?;

    let mut cmd = std::process::Command::new(program);
    cmd.args(args);
    for s in secrets.iter() {
        let (name, value) = (s.name(), s.expose());
        if !is_env_name(name) || value.contains(&0) {
            ctx.say(&format!(
                "warning: {label}: {name} cannot be an environment variable; skipped"
            ));
            continue;
        }
        // Unix environment values are bytes; elsewhere they must be text.
        #[cfg(unix)]
        let value = {
            use std::os::unix::ffi::OsStrExt;
            std::ffi::OsStr::from_bytes(value)
        };
        #[cfg(not(unix))]
        let Ok(value) = std::str::from_utf8(value) else {
            ctx.say(&format!(
                "warning: {label}: {name} is not UTF-8 text, so it cannot be an environment variable here; skipped"
            ));
            continue;
        };
        cmd.env(name, value);
    }
    // On Unix, exec replaces this process: the child's exit status is gv's,
    // and gv's memory (keys, values) is gone with it. Elsewhere gv waits for
    // the child and exits with its status (`crate::cli::util::replace_process`).
    let err = crate::cli::util::replace_process(cmd);
    bail!("could not run {}: {err}", Path::new(program).display())
}

fn utf8<'a>(label: &str, name: &str, value: &'a [u8]) -> anyhow::Result<&'a str> {
    std::str::from_utf8(value)
        .map_err(|_| anyhow::anyhow!("{label}: {name} is not UTF-8 text, so it cannot be exported"))
}

fn render(
    label: &str,
    format: Format,
    secrets: &[(String, Zeroizing<Vec<u8>>)],
) -> anyhow::Result<Zeroizing<String>> {
    let mut out = Zeroizing::new(String::new());
    match format {
        Format::Dotenv => {
            for (name, value) in secrets {
                if !is_env_name(name) {
                    bail!("{label}: {name} is not a valid dotenv name");
                }
                let mut escaped = Zeroizing::new(String::new());
                for c in utf8(label, name, value)?.chars() {
                    match c {
                        '\\' => escaped.push_str("\\\\"),
                        '"' => escaped.push_str("\\\""),
                        '\n' => escaped.push_str("\\n"),
                        '$' => escaped.push_str("\\$"),
                        c => escaped.push(c),
                    }
                }
                out.push_str(&format!("{name}=\"{}\"\n", escaped.as_str()));
            }
        }
        Format::Json => {
            let mut map = serde_json::Map::new();
            for (name, value) in secrets {
                map.insert(name.clone(), utf8(label, name, value)?.into());
            }
            out.push_str(&serde_json::to_string_pretty(&map)?);
            out.push('\n');
            // Clear the map's copies of the values.
            for (_, v) in map.iter_mut() {
                if let serde_json::Value::String(s) = v {
                    zeroize::Zeroize::zeroize(s);
                }
            }
        }
        Format::Yaml => {
            // JSON string literals are valid YAML double-quoted scalars.
            for (name, value) in secrets {
                let v = Zeroizing::new(serde_json::to_string(utf8(label, name, value)?)?);
                out.push_str(&format!(
                    "{}: {}\n",
                    serde_json::to_string(name)?,
                    v.as_str()
                ));
            }
        }
    }
    Ok(out)
}

pub fn export(
    ctx: &mut Context,
    env: Option<&str>,
    format: Format,
    out: Option<&Path>,
    force: bool,
    only: &[String],
) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let vault = target.open()?;
    let set = readable(&vault, only)?;
    let label = vault.label().to_owned();
    target.done(vault)?;
    let secrets: Vec<(String, Zeroizing<Vec<u8>>)> = set
        .iter()
        .map(|s| (s.name().to_owned(), Zeroizing::new(s.expose().to_vec())))
        .collect();
    let text = render(&label, format, &secrets)?;
    match out {
        Some(path) => {
            create_private(path, text.as_bytes(), force)?;
            ctx.say(&format!(
                "wrote {} secrets from {label} to {} (mode 0600)",
                secrets.len(),
                path.display()
            ));
        }
        None => ctx.out(text.as_bytes())?,
    }
    Ok(())
}

pub fn actor_text(actor: &Actor) -> String {
    match actor {
        Actor::Owner => "owner".to_owned(),
        Actor::Token(id) => format!("token {}", &id.to_hex()[..8]),
    }
}

/// Who the server says wrote a version: an actor kind a newer server may
/// name and this gv not know is shown by its name, and never acted on.
pub fn writer_text(written_by: &Tolerant<Actor>) -> String {
    match written_by.known() {
        Some(actor) => actor_text(actor),
        None => format!("{} (unknown)", written_by.unknown().unwrap_or("?")),
    }
}

pub fn audit(ctx: &mut Context, env: Option<&str>) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let opened = target.open()?;
    let label = opened.label().to_owned();
    // The owner verifies from the head recorded last time, and records the
    // new one only on success. Token mode keeps no local state.
    let report = match (target.owner(), &opened) {
        (Some(owner), Opened::Owner(env)) => {
            let report = owner.audit(env, 0)?;
            owner.remember(env);
            report
        }
        _ => opened.verify_audit(None)?,
    };
    drop(opened);
    for r in &report.entries {
        let refused = if r.refused { "  REFUSED" } else { "" };
        ctx.out_line(&format!(
            "{:>6}  {}  {:<14} {:<14} {}{refused}",
            r.seq,
            fmt_time(r.ts),
            actor_text(&r.actor),
            r.action,
            r.name.as_deref().unwrap_or(""),
        ))?;
    }
    target.finish()?;
    ctx.say_ok(&format!(
        "{label}: audit chain verified ({} new rows{})",
        report.new_rows,
        report
            .head
            .map_or(String::new(), |h| format!(", head at seq {}", h.seq))
    ));
    if let Some(u) = report.unverifiable {
        ctx.say(&format!(
            "{label}: the rows from seq {} on are in audit row format {}, newer than this gv \
             reads. They are unverified, not tampered, and the stored head stops before them. \
             Upgrade gv to verify them.",
            u.from_seq.map_or_else(|| "?".to_owned(), |s| s.to_string()),
            u.format
        ));
    }
    Ok(())
}

pub fn status(ctx: &mut Context, env: Option<&str>) -> anyhow::Result<()> {
    let mut target = Target::select(ctx, env)?;
    let opened = target.open()?;
    let label = opened.label().to_owned();
    let status = match &opened {
        Opened::Owner(env) => env.status_at_open().clone(),
        Opened::Token(v) => v.status()?,
    };
    target.done(opened)?;
    let mut lines = vec![
        format!("environment  {label}"),
        format!("vault id     {}", status.vault_id),
        format!("generation   {}", status.generation),
        format!("configs      {} live", status.config_count),
        format!("created      {}", fmt_time(status.created_at)),
        format!("last active  {}", fmt_time(status.last_active_at)),
        match status.expires_at {
            Some(at) => format!("expires      {} if unused", fmt_time(at)),
            None => "expires      never".to_owned(),
        },
        format!(
            "storage      {} of {} bytes",
            status.bytes_used, status.limits.max_vault_bytes
        ),
    ];
    if let Some(tokens) = &status.tokens {
        lines.push(format!("tokens       {}", tokens.len()));
    }
    for line in lines {
        ctx.out_line(&line)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secrets(pairs: &[(&str, &str)]) -> Vec<(String, Zeroizing<Vec<u8>>)> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), Zeroizing::new(v.as_bytes().to_vec())))
            .collect()
    }

    #[test]
    fn formats_escape_values() {
        let s = secrets(&[("A", "x\"y$z\\\nw"), ("B", "plain")]);
        assert_eq!(
            render("p", Format::Dotenv, &s).unwrap().as_str(),
            "A=\"x\\\"y\\$z\\\\\\nw\"\nB=\"plain\"\n"
        );
        let json: serde_json::Value =
            serde_json::from_str(&render("p", Format::Json, &s).unwrap()).unwrap();
        assert_eq!(json["A"], "x\"y$z\\\nw");
        assert_eq!(
            render("p", Format::Yaml, &s).unwrap().as_str(),
            "\"A\": \"x\\\"y$z\\\\\\nw\"\n\"B\": \"plain\"\n"
        );
        let bad = secrets(&[("not-env", "v")]);
        assert!(render("p", Format::Dotenv, &bad).is_err());
    }

    #[test]
    fn env_names() {
        assert!(is_env_name("DATABASE_URL"));
        assert!(is_env_name("_x1"));
        assert!(!is_env_name("1X"));
        assert!(!is_env_name("A-B"));
        assert!(!is_env_name(""));
    }
}
