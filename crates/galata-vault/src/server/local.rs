//! `gv-server local`: the server on this machine, with no configuration
//! file. The database and a file journal share one data directory, the
//! server listens on loopback only, and it can print a launchd or systemd
//! definition to run it as a user daemon.
//!
//! The data directory is the one the SDK's embedded transport opens
//! (`crate::server_core::data_dir`), and it has one opener at a time: a second
//! local server, or an embedded application, is refused with
//! `data_dir_in_use` while this one runs.
//!
//! Durability is single-machine: the journal is on the same disk as the
//! database, so losing the disk loses the vaults. Back the directory up.
//!
//! Local mode asks nothing of its callers beyond the protocol: no proof of
//! work, no rate limits, and no vault ever expires for inactivity. Every
//! client is this machine, and its operator is its only user. The flags that
//! once turned proof of work and expiry on are refused, naming themselves.

use std::ffi::OsString;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::server_core::data_dir::{DATABASE, JOURNAL_ROOT};

use crate::server::config::{JournalConfig, ServerConfig};

pub const DEFAULT_PORT: u16 = 8750;
pub const LAUNCHD_LABEL: &str = "dev.galata-vault.server";

/// One line for the startup log. Local mode has no window to report: no
/// vault is ever deleted for inactivity.
pub const EXPIRY_NOTICE: &str = "local mode: vaults never expire for inactivity";

/// The flags that turned on controls this server no longer has. Recognised
/// so that asking for one is refused by name, rather than reported as a typo.
const REMOVED_FLAGS: &[&str] = &["--pow-difficulty", "--idle-expiry-days"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceKind {
    Launchd,
    Systemd,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct LocalOptions {
    pub data_dir: Option<PathBuf>,
    pub listen: Option<SocketAddr>,
    pub port: Option<u16>,
    pub print_service: Option<ServiceKind>,
}

pub const USAGE: &str = "usage: gv-server local [--data-dir DIR] [--port N | --listen 127.0.0.1:N] \
                         [--print-service launchd|systemd]";

/// Parse the arguments after `local`.
pub fn parse_args(args: &[String]) -> Result<LocalOptions, String> {
    let mut opts = LocalOptions::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let mut value = || {
            it.next()
                .cloned()
                .ok_or_else(|| format!("{flag} needs a value\n{USAGE}"))
        };
        match flag.as_str() {
            "--data-dir" => opts.data_dir = Some(PathBuf::from(value()?)),
            "--port" => {
                let v = value()?;
                opts.port = Some(
                    v.parse()
                        .map_err(|_| format!("--port {v:?} is not a port number"))?,
                );
            }
            "--listen" => {
                let v = value()?;
                opts.listen = Some(v.parse().map_err(|_| {
                    format!("--listen {v:?} is not an address like 127.0.0.1:8750")
                })?);
            }
            "--print-service" => {
                opts.print_service = Some(match value()?.as_str() {
                    "launchd" => ServiceKind::Launchd,
                    "systemd" => ServiceKind::Systemd,
                    other => {
                        return Err(format!(
                            "--print-service takes launchd or systemd, not {other:?}"
                        ));
                    }
                });
            }
            removed if REMOVED_FLAGS.contains(&removed) => {
                let v = value()?;
                let asked: u64 = v
                    .parse()
                    .map_err(|_| format!("{removed} takes a number, not {v:?}"))?;
                // 0 always meant "none", which is what this server does.
                if asked > 0 {
                    return Err(format!(
                        "{removed} is no longer supported: this server asks for no proof of work \
                         and never expires a vault for inactivity"
                    ));
                }
            }
            other => return Err(format!("unknown argument {other:?}\n{USAGE}")),
        }
    }
    if opts.port.is_some() && opts.listen.is_some() {
        return Err("give --port or --listen, not both".into());
    }
    Ok(opts)
}

/// The address to listen on: loopback only.
pub fn listen_addr(opts: &LocalOptions) -> Result<SocketAddr, String> {
    let addr = match (opts.listen, opts.port) {
        (Some(addr), _) => addr,
        (None, port) => SocketAddr::from((Ipv4Addr::LOCALHOST, port.unwrap_or(DEFAULT_PORT))),
    };
    if !addr.ip().is_loopback() {
        return Err(format!(
            "local mode listens on loopback only, not {addr}. To serve other machines, run \
             `gv-server --config <file>` behind a TLS-terminating proxy (deploy/README.md)"
        ));
    }
    Ok(addr)
}

/// `--data-dir`, then `$GV_DATA_DIR`, then `$XDG_DATA_HOME/galata-vault`,
/// then `~/.local/share/galata-vault`.
pub fn resolve_data_dir(
    flag: Option<&Path>,
    env: impl Fn(&str) -> Option<OsString>,
) -> Result<PathBuf, String> {
    let var = |k: &str| env(k).filter(|v| !v.is_empty()).map(PathBuf::from);
    let dir = if let Some(d) = flag {
        d.to_path_buf()
    } else if let Some(d) = var("GV_DATA_DIR") {
        d
    } else if let Some(d) = var("XDG_DATA_HOME") {
        d.join("galata-vault")
    } else if let Some(h) = var("HOME") {
        h.join(".local").join("share").join("galata-vault")
    } else {
        return Err("cannot find a data directory: pass --data-dir or set GV_DATA_DIR".into());
    };
    if dir.is_absolute() {
        Ok(dir)
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(dir))
            .map_err(|e| format!("cannot resolve the data directory: {e}"))
    }
}

/// The configuration local mode runs with: everything else at its default.
/// Nothing here is shared with strangers, so there is no abuse for proof of
/// work or expiry to control, and idle-by-design vaults must survive. No rate
/// limits either: every client is this machine.
pub fn config(data_dir: &Path, listen: SocketAddr) -> ServerConfig {
    let mut config = ServerConfig::for_database(data_dir.join(DATABASE));
    config.listen = listen;
    config.journal = JournalConfig::File {
        dir: data_dir.join(JOURNAL_ROOT),
    };
    config
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// systemd `ExecStart=` quoting: double quotes, with `\`, `"` and the `%`
/// specifier character escaped.
fn systemd_quote(s: &str) -> String {
    format!(
        "\"{}\"",
        s.replace('\\', "\\\\")
            .replace('"', "\\\"")
            .replace('%', "%%")
    )
}

/// A user-level service definition that runs `bin local` with this data
/// directory and address.
pub fn service_definition(
    kind: ServiceKind,
    bin: &Path,
    data_dir: &Path,
    listen: SocketAddr,
) -> String {
    let (bin, dir) = (bin.display().to_string(), data_dir.display().to_string());
    match kind {
        ServiceKind::Launchd => {
            let log = data_dir.join("server.log").display().to_string();
            let args: String = [
                bin.as_str(),
                "local",
                "--data-dir",
                dir.as_str(),
                "--listen",
            ]
            .iter()
            .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
            .chain(std::iter::once(format!("    <string>{listen}</string>\n")))
            .collect();
            format!(
                r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!--
  galata-vault local server, as a user agent. Install and start:
    gv-server local --print-service launchd > ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist
    launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist
  Stop and remove:
    launchctl bootout gui/$(id -u)/{LAUNCHD_LABEL}
-->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
                log = xml_escape(&log)
            )
        }
        ServiceKind::Systemd => format!(
            "# galata-vault local server, as a systemd user service. Install and start:\n\
             #   gv-server local --print-service systemd > ~/.config/systemd/user/galata-vault.service\n\
             #   systemctl --user daemon-reload && systemctl --user enable --now galata-vault\n\
             [Unit]\n\
             Description=galata-vault local server\n\
             \n\
             [Service]\n\
             ExecStart={} local --data-dir {} --listen {listen}\n\
             Restart=on-failure\n\
             \n\
             [Install]\n\
             WantedBy=default.target\n",
            systemd_quote(&bin),
            systemd_quote(&dir)
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|a| (*a).to_owned()).collect()
    }

    #[test]
    fn arguments_and_addresses() {
        let o = parse_args(&args(&["--data-dir", "/d", "--port", "9000"])).unwrap();
        assert_eq!(o.data_dir, Some(PathBuf::from("/d")));
        assert_eq!(listen_addr(&o).unwrap(), "127.0.0.1:9000".parse().unwrap());
        assert_eq!(
            listen_addr(&LocalOptions::default()).unwrap(),
            "127.0.0.1:8750".parse().unwrap()
        );
        let v6 = parse_args(&args(&["--listen", "[::1]:8750"])).unwrap();
        assert!(listen_addr(&v6).is_ok());

        let wide = parse_args(&args(&["--listen", "0.0.0.0:8750"])).unwrap();
        let err = listen_addr(&wide).unwrap_err();
        assert!(
            err.contains("loopback only") && err.contains("--config"),
            "{err}"
        );

        assert!(parse_args(&args(&["--port", "1", "--listen", "127.0.0.1:2"])).is_err());
        assert!(parse_args(&args(&["--port"])).is_err());
        assert!(parse_args(&args(&["--bogus"])).is_err());
        assert!(parse_args(&args(&["--print-service", "upstart"])).is_err());
        assert_eq!(
            parse_args(&args(&["--print-service", "systemd"]))
                .unwrap()
                .print_service,
            Some(ServiceKind::Systemd)
        );
    }

    /// Proof of work and inactivity expiry are gone: asking for either is
    /// refused by name, never ignored, and no message names a Cargo feature.
    #[test]
    fn removed_flags_are_refused_by_name() {
        for flag in REMOVED_FLAGS {
            let err = parse_args(&args(&[flag, "30"])).unwrap_err();
            assert!(
                err.contains(flag) && err.contains("no longer supported"),
                "{err}"
            );
            assert!(!err.contains("feature"), "{err}");
            // 0 always meant "none", which is what this server does anyway.
            assert_eq!(
                parse_args(&args(&[flag, "0"])).unwrap(),
                LocalOptions::default()
            );
            assert!(parse_args(&args(&[flag, "ninety"])).is_err());
        }
    }

    #[test]
    fn data_directory_precedence() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |k: &str| {
                pairs
                    .iter()
                    .find(|(name, _)| *name == k)
                    .map(|(_, v)| OsString::from(v))
            }
        };
        let all: &'static [(&str, &str)] = &[
            ("GV_DATA_DIR", "/a"),
            ("XDG_DATA_HOME", "/x"),
            ("HOME", "/h"),
        ];
        assert_eq!(
            resolve_data_dir(Some(Path::new("/b")), env(all)).unwrap(),
            PathBuf::from("/b")
        );
        assert_eq!(
            resolve_data_dir(None, env(all)).unwrap(),
            PathBuf::from("/a")
        );
        assert_eq!(
            resolve_data_dir(None, env(&[("XDG_DATA_HOME", "/x"), ("HOME", "/h")])).unwrap(),
            PathBuf::from("/x/galata-vault")
        );
        assert_eq!(
            resolve_data_dir(None, env(&[("HOME", "/h")])).unwrap(),
            PathBuf::from("/h/.local/share/galata-vault")
        );
        assert!(resolve_data_dir(None, env(&[])).is_err());
    }

    #[test]
    fn local_config_keeps_everything_in_the_data_directory() {
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();
        let c = config(Path::new("/d"), addr);
        assert_eq!(c.database, PathBuf::from("/d/vault.db"));
        assert!(
            matches!(c.journal, JournalConfig::File { ref dir } if dir == Path::new("/d/journal-root"))
        );
        assert!(!c.litestream);
        c.validate().unwrap();
    }

    #[test]
    fn local_mode_never_expires() {
        assert!(EXPIRY_NOTICE.contains("never expire"));
    }

    #[test]
    fn service_definitions() {
        let bin = Path::new("/opt/gv & co/gv-server");
        let dir = Path::new("/home/u/.local/share/galata-vault");
        let addr: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let plist = service_definition(ServiceKind::Launchd, bin, dir, addr);
        assert!(
            plist.contains("<string>/opt/gv &amp; co/gv-server</string>"),
            "{plist}"
        );
        assert!(plist.contains("<string>local</string>"));
        assert!(plist.contains("<string>127.0.0.1:9000</string>"));
        assert!(plist.contains(&format!("<string>{}</string>", dir.display())));
        assert!(plist.contains(LAUNCHD_LABEL));
        assert!(!plist.contains("idle-expiry-days"));

        let unit = service_definition(
            ServiceKind::Systemd,
            Path::new("/opt/gv/gv-server"),
            Path::new("/data/100%"),
            addr,
        );
        assert!(
            unit.contains(r#"ExecStart="/opt/gv/gv-server" local --data-dir "/data/100%%" --listen 127.0.0.1:9000"#),
            "{unit}"
        );
        assert!(unit.contains("WantedBy=default.target"));
        assert!(!unit.contains("idle-expiry-days"));
    }
}
