//! Which environment a command acts on: `--env`, then `<prefix>ENV`, then
//! the nearest directory file. A repository file may name an environment and
//! nothing else, so it can never point the CLI at another server.

use std::path::{Path, PathBuf};

use crate::proto::path::EnvPath;
use anyhow::{Context as _, bail};

use crate::cli::branding::Branding;

pub fn selected_env(branding: &Branding, flag: Option<&str>) -> anyhow::Result<EnvPath> {
    if let Some(env) = flag {
        return parse(env, "--env");
    }
    let var = branding.var("ENV");
    if let Ok(env) = std::env::var(&var)
        && !env.is_empty()
    {
        return parse(&env, &var);
    }
    let cwd = std::env::current_dir()?;
    match find_dir_file(&cwd, branding.dir_file) {
        Some(file) => read_dir_file(&file, branding),
        None => bail!(
            "no environment selected: pass --env <path>, set {var}, or add a {} with env = \"project/env\"",
            branding.dir_file
        ),
    }
}

fn parse(s: &str, source: &str) -> anyhow::Result<EnvPath> {
    s.parse::<EnvPath>()
        .map_err(|e| anyhow::anyhow!("{source}: {s:?} is not an environment path: {e}"))
}

fn find_dir_file(start: &Path, name: &str) -> Option<PathBuf> {
    start
        .ancestors()
        .map(|d| d.join(name))
        .find(|f| f.is_file())
}

pub fn read_dir_file(file: &Path, branding: &Branding) -> anyhow::Result<EnvPath> {
    let bin = branding.bin_name;
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let table: toml::Table =
        toml::from_str(&text).with_context(|| format!("{} is not valid TOML", file.display()))?;
    if let Some(key) = table.keys().find(|k| k.as_str() != "env") {
        bail!(
            "{} may contain only `env`; it contains `{key}`, which {bin} refuses (a repository cannot redirect {bin} or change its settings)",
            file.display()
        );
    }
    match table.get("env") {
        Some(toml::Value::String(env)) => parse(env, &file.display().to_string()),
        Some(_) => bail!("{}: env must be a string like \"acme/dev\"", file.display()),
        None => bail!("{} does not set env", file.display()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_file_allows_only_env() {
        let b = Branding::GV;
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join(b.dir_file);
        std::fs::write(&f, "env = \"acme/dev\"\n").unwrap();
        assert_eq!(read_dir_file(&f, &b).unwrap().to_string(), "acme/dev");

        std::fs::write(
            &f,
            "env = \"acme/dev\"\nserver = \"https://evil.example\"\n",
        )
        .unwrap();
        let err = read_dir_file(&f, &b).unwrap_err().to_string();
        assert!(err.contains("`server`"), "{err}");

        std::fs::write(&f, "env = \"Acme\"\n").unwrap();
        assert!(read_dir_file(&f, &b).is_err());

        let nested = dir.path().join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(find_dir_file(&nested, b.dir_file), Some(f));
    }
}
