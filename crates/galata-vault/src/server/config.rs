//! Server configuration: one TOML file, unknown keys refused.
//!
//! The server serves its callers with the protocol and nothing more: no proof
//! of work, no rate limits, no idle expiry. The settings that once turned
//! those on are read only so that a configuration asking for one is refused
//! at startup, naming it, rather than served without the control it asks for
//! (ADR-0010: what cannot be verified is denied).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use crate::proto::api::Limits;
use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub database: PathBuf,
    /// Running under `litestream replicate -exec`.
    #[serde(default)]
    pub litestream: bool,
    /// Set only when a TLS-terminating proxy sits in front. Without it the
    /// server refuses any non-loopback address, because it serves no TLS itself.
    #[serde(default)]
    pub behind_tls_proxy: bool,
    #[serde(default)]
    pub limits: Limits,
    /// The request body limit. Unset, it is derived from the quotas: the
    /// largest rotation batch a full vault can produce (see [`Self::body_limit`]).
    #[serde(default)]
    pub max_body_bytes: Option<usize>,
    /// Name this server and its version in `GET /v1/capabilities`. Off by
    /// default: a client needs nothing from it, and it helps anyone
    /// fingerprinting the deployment.
    #[serde(default)]
    pub advertise_version: bool,
    pub journal: JournalConfig,
    /// Which defaults the unset public-service settings took. Read only so
    /// that it is refused by name.
    #[serde(default)]
    profile: Option<String>,
    /// Read only so that it is refused by name.
    #[serde(default)]
    production: bool,
    /// Read only so that it is refused by name.
    #[serde(default)]
    pow_difficulty: Option<u8>,
    /// Read only so that it is refused by name.
    #[serde(default)]
    idle_expiry_days: Option<u32>,
    /// Read only so that it is refused by name.
    #[serde(default)]
    rate_limits: Option<serde::de::IgnoredAny>,
}

/// Where critical operations are journaled before they are acknowledged.
#[derive(Debug, Clone)]
pub enum JournalConfig {
    /// A directory beside the database: it undoes a restored older copy of
    /// the database, and does not survive the loss of the disk.
    File { dir: PathBuf },
    /// Any other kind, kept by name only, so that a configuration asking for
    /// one is answered by name. No server here writes to a bucket.
    Other(String),
}

/// The `file` kind's own fields, so that a typo inside `[journal]` is
/// refused rather than ignored.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileJournalFields {
    dir: PathBuf,
}

/// Read by hand, because only the `file` kind has fields to check: any other
/// kind is remembered by name and refused by [`ServerConfig::validate`],
/// rather than reported as an unknown variant.
impl<'de> Deserialize<'de> for JournalConfig {
    fn deserialize<D>(deserializer: D) -> Result<JournalConfig, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error as _;

        let mut table = toml::Table::deserialize(deserializer)?;
        let kind = match table.remove("kind") {
            Some(toml::Value::String(kind)) => kind,
            Some(_) => return Err(D::Error::custom("[journal] kind is a string")),
            None => return Err(D::Error::missing_field("kind")),
        };
        if kind != "file" {
            return Ok(JournalConfig::Other(kind));
        }
        let file =
            FileJournalFields::deserialize(toml::Value::Table(table)).map_err(D::Error::custom)?;
        Ok(JournalConfig::File { dir: file.dir })
    }
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8750))
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("{path}: {message}")]
    Parse { path: PathBuf, message: String },
    #[error(
        "refusing to listen on {0} without TLS: this server does not terminate TLS itself. \
         Listen on a loopback address, or set behind_tls_proxy = true when a TLS-terminating proxy is in front"
    )]
    PlaintextOffLoopback(SocketAddr),
    #[error(
        "max_body_bytes = {configured} is below {required}, the largest rotation batch these quotas \
         allow, so a full vault could not be rotated. Raise it, or remove it to use the derived limit"
    )]
    BodyLimit { configured: usize, required: usize },
    #[error(
        "{0} is no longer supported: this server asks nothing of its callers beyond the protocol, \
         and journals to a directory beside its database. Remove it from the configuration"
    )]
    Removed(String),
    #[error(
        "unknown journal kind {0:?}: the only kind is \"file\", a directory beside the database"
    )]
    UnknownJournalKind(String),
}

impl ServerConfig {
    pub fn load(path: &Path) -> Result<ServerConfig, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        let config: ServerConfig = toml::from_str(&text).map_err(|e| ConfigError::Parse {
            path: path.to_owned(),
            message: e.to_string(),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// A configuration for tests and embedding: loopback, and a file journal
    /// beside the database.
    pub fn for_database(database: impl Into<PathBuf>) -> ServerConfig {
        let database = database.into();
        let journal_dir = database
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join("journal");
        ServerConfig {
            listen: default_listen(),
            database,
            litestream: false,
            behind_tls_proxy: false,
            limits: Limits::default(),
            max_body_bytes: None,
            advertise_version: false,
            journal: JournalConfig::File { dir: journal_dir },
            profile: None,
            production: false,
            pow_difficulty: None,
            idle_expiry_days: None,
            rate_limits: None,
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.listen.ip().is_loopback() && !self.behind_tls_proxy {
            return Err(ConfigError::PlaintextOffLoopback(self.listen));
        }
        if let Some(configured) = self.max_body_bytes {
            let required = self.limits.max_rotation_body();
            if configured < required {
                return Err(ConfigError::BodyLimit {
                    configured,
                    required,
                });
            }
        }
        self.refuse_removed()
    }

    /// Every setting that went with the public-service machinery, refused by
    /// name rather than ignored. Zero is "none" for the two numeric ones, so
    /// a configuration that only ever switched them off is still served.
    fn refuse_removed(&self) -> Result<(), ConfigError> {
        let refused = if self.profile.as_deref() == Some("hosted") {
            Some("profile = \"hosted\"".to_owned())
        } else if self.profile.is_some() {
            Some("profile".to_owned())
        } else if self.production {
            Some("production".to_owned())
        } else if self.pow_difficulty.is_some_and(|bits| bits > 0) {
            Some("pow_difficulty".to_owned())
        } else if self.idle_expiry_days.is_some_and(|days| days > 0) {
            Some("idle_expiry_days".to_owned())
        } else if self.rate_limits.is_some() {
            Some("[rate_limits]".to_owned())
        } else if let JournalConfig::Other(kind) = &self.journal {
            if kind != "s3" {
                return Err(ConfigError::UnknownJournalKind(kind.clone()));
            }
            Some("an S3 journal ([journal] kind = \"s3\")".to_owned())
        } else {
            None
        };
        refused.map_or(Ok(()), |setting| Err(ConfigError::Removed(setting)))
    }

    /// What the capabilities call this server, when the operator asks for
    /// it: `gv-server/<version>`.
    pub fn advertised_server(&self) -> Option<String> {
        self.advertise_version
            .then(|| format!("gv-server/{}", env!("CARGO_PKG_VERSION")))
    }

    /// The request body limit in force: the configured one, or else the
    /// largest rotation batch these quotas allow.
    pub fn body_limit(&self) -> usize {
        self.max_body_bytes
            .unwrap_or_else(|| self.limits.max_rotation_body())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE_JOURNAL: &str = "[journal]\nkind = \"file\"\ndir = \"j\"\n";

    fn parse(extra: &str) -> ServerConfig {
        toml::from_str(&format!("database = \"x.db\"\n{extra}\n{FILE_JOURNAL}")).unwrap()
    }

    #[test]
    fn plaintext_off_loopback_is_refused_unless_behind_a_proxy() {
        let mut c = ServerConfig::for_database("x.db");
        assert!(c.validate().is_ok());
        c.listen = "0.0.0.0:8750".parse().unwrap();
        assert!(matches!(
            c.validate(),
            Err(ConfigError::PlaintextOffLoopback(_))
        ));
        c.behind_tls_proxy = true;
        assert!(c.validate().is_ok());
        c.listen = "[::1]:8750".parse().unwrap();
        c.behind_tls_proxy = false;
        assert!(c.validate().is_ok(), "IPv6 loopback is loopback");
    }

    #[test]
    fn unknown_keys_are_refused() {
        let text = format!("database = \"x.db\"\nlisen = \"typo\"\n{FILE_JOURNAL}");
        assert!(toml::from_str::<ServerConfig>(&text).is_err());
        let journal_typo =
            "database = \"x.db\"\n[journal]\nkind = \"file\"\ndir = \"j\"\nbucket = \"b\"\n";
        assert!(toml::from_str::<ServerConfig>(journal_typo).is_err());
        // An unknown kind is a typo, not a setting that was removed.
        let unknown = "database = \"x.db\"\n[journal]\nkind = \"flie\"\ndir = \"j\"\n";
        let err = toml::from_str::<ServerConfig>(unknown)
            .unwrap()
            .validate()
            .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownJournalKind(_)), "{err}");
        let ok = format!(
            "database = \"x.db\"\n[limits]\nmax_names = 10\nmax_value_bytes = 1\nmax_versions = 1\nmax_vault_bytes = 1\nmax_tokens = 1\n{FILE_JOURNAL}"
        );
        assert_eq!(
            toml::from_str::<ServerConfig>(&ok)
                .unwrap()
                .limits
                .max_names,
            10
        );
    }

    #[test]
    fn the_default_configuration_asks_for_nothing() {
        let c = parse("");
        c.validate().unwrap();
        // Zero is "none", so it is not a setting that was removed.
        let zeros = parse("pow_difficulty = 0\nidle_expiry_days = 0");
        zeros.validate().unwrap();
        assert_eq!(c.advertised_server(), None, "the version is opt-in");
        let named = parse("advertise_version = true");
        assert!(named.advertised_server().unwrap().starts_with("gv-server/"));
    }

    #[test]
    fn the_body_limit_is_derived_from_the_quotas() {
        let mut c = ServerConfig::for_database("x.db");
        let required = c.limits.max_rotation_body();
        assert_eq!(c.body_limit(), required);
        assert!(
            required > 4 * 1024 * 1024,
            "a full 4 MiB vault grows in base64, so the old fixed 4 MiB limit was too small"
        );

        c.max_body_bytes = Some(required - 1);
        let err = c.validate().unwrap_err();
        assert!(matches!(err, ConfigError::BodyLimit { .. }));
        let text = err.to_string();
        assert!(
            text.contains(&(required - 1).to_string()) && text.contains(&required.to_string()),
            "{text}"
        );

        c.max_body_bytes = Some(required);
        c.validate().unwrap();
        assert_eq!(c.body_limit(), required);
        c.limits.max_vault_bytes *= 2;
        assert!(
            matches!(c.validate(), Err(ConfigError::BodyLimit { .. })),
            "raising a quota without the body limit is refused"
        );
    }

    /// Every removed setting, refused by name, never ignored, and no message
    /// names a Cargo feature: there is no second build to ask for.
    #[test]
    fn a_removed_setting_is_refused_by_name() {
        let s3 = "database = \"x.db\"\n[journal]\nkind = \"s3\"\nendpoint = \"https://s3.example\"\nregion = \"fsn1\"\nbucket = \"gv-journal\"\n";
        let cases = [
            (parse("profile = \"hosted\""), "profile = \"hosted\""),
            (parse("production = true"), "production"),
            (parse("pow_difficulty = 24"), "pow_difficulty"),
            (parse("idle_expiry_days = 90"), "idle_expiry_days"),
            (
                parse("[rate_limits]\ncreations_per_ip_per_hour = 5"),
                "[rate_limits]",
            ),
            (toml::from_str(s3).unwrap(), "S3 journal"),
        ];
        for (config, setting) in cases {
            let err = config.validate().unwrap_err();
            let text = err.to_string();
            assert!(matches!(err, ConfigError::Removed(_)), "{text}");
            assert!(
                text.contains(setting) && text.contains("no longer supported"),
                "{setting}: {text}"
            );
            assert!(!text.contains("feature"), "{setting}: {text}");
        }
    }
}
