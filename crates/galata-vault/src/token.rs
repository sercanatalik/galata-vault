//! The token client: one vault, opened with an access token.

use std::path::Path;

use crate::client::{Api, Pre, Warning};
use crate::keys::TokenKeys;
use crate::proto::FormatError;
use crate::proto::api::{Scope, VaultStatus, VersionMeta};
use crate::proto::audit::ChainHead;
use crate::proto::children::is_reserved_name;
use crate::proto::ids::TokenId;
use zeroize::Zeroizing;

use crate::audit::{self, AuditReport};
use crate::check::{scan_literals, validate};
use crate::error::{Error, code};
use crate::state::StateStore;
use crate::value::{ConfigDocument, Entry, Expect, Expiry, NewConfig, SecretSet, SecretValue};
use crate::vault::{Handle, Item, Pins};

/// One environment's vault. Opened with a token it is a token client; an
/// [`crate::owner::Environment`] derefs to one for its record operations.
/// `Send + Sync`: one handle serves every thread.
pub struct Vault {
    pub(crate) inner: Handle,
    scope: Scope,
}

impl std::fmt::Debug for Vault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Vault")
            .field("scope", &self.scope())
            .field("vault_id", &self.vault_id())
            .finish()
    }
}

fn refuse_reserved(name: &str) -> Result<(), Error> {
    if is_reserved_name(name) || name.is_empty() {
        return Err(Error::local(
            code::INVALID_NAME,
            "a name must not be empty, and names beginning with \"gv:\" are reserved for galata-vault's own records",
        ));
    }
    Ok(())
}

#[cfg(feature = "http")]
fn set(var: &str) -> Option<std::ffi::OsString> {
    std::env::var_os(var).filter(|v| !v.is_empty())
}

/// Check a token string before any request.
pub(crate) fn parse_token(token: &str) -> Result<TokenKeys, Error> {
    TokenKeys::parse(token).map_err(|e| Error::Auth {
        code: code::INVALID_TOKEN.to_owned(),
        message: match e {
            FormatError::UnknownVersion { found } => {
                format!("the token carries version {found}, which this build does not know")
            }
            _ => "the token is not a valid gvt1_ token (its checksum does not match)".to_owned(),
        },
    })
}

/// How a token file's permissions are established before it is read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TokenFileCheck {
    /// This crate checks them: on Unix the mode must be 0600 or 0400. Where
    /// it cannot check them (Windows), the file is refused.
    Permissions,
    /// The caller has verified the file's access control itself (a Windows
    /// ACL, say). On Unix the mode is still checked.
    CallerVerified,
}

#[cfg_attr(not(feature = "http"), allow(dead_code))]
fn read_token_file(path: &Path, check: TokenFileCheck) -> Result<Zeroizing<String>, Error> {
    let unreadable = |e: std::io::Error| {
        Error::local(
            code::INVALID_TOKEN_FILE,
            format!(
                "cannot read the token file {}: {}",
                path.display(),
                e.kind()
            ),
        )
    };
    let meta = std::fs::metadata(path).map_err(unreadable)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = check;
        let mode = meta.permissions().mode() & 0o777;
        if mode != 0o600 && mode != 0o400 {
            return Err(Error::local(
                code::INVALID_TOKEN_FILE,
                format!(
                    "the token file {} has mode {mode:04o}; it must be 0600 or 0400",
                    path.display()
                ),
            ));
        }
    }
    #[cfg(not(unix))]
    {
        let _ = meta;
        if check != TokenFileCheck::CallerVerified {
            return Err(Error::local(
                code::INVALID_TOKEN_FILE,
                format!(
                    "the token file {} is refused: its permissions cannot be verified on this \
                     platform. Check its ACL yourself and open it with \
                     TokenFileCheck::CallerVerified, or pass the token another way",
                    path.display()
                ),
            ));
        }
    }
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(unreadable)?);
    let mut words = text.split_whitespace();
    let (Some(token), None) = (words.next(), words.next()) else {
        return Err(Error::local(
            code::INVALID_TOKEN_FILE,
            format!(
                "the token file {} must hold exactly one gvt1_ token and nothing else",
                path.display()
            ),
        ));
    };
    Ok(Zeroizing::new(token.to_owned()))
}

fn entries(items: Vec<Item>, with_deleted: bool) -> Vec<Entry> {
    items
        .into_iter()
        .filter(|i| (with_deleted || !i.tombstone) && !is_reserved_name(&i.name))
        .map(|i| Entry {
            name: i.name,
            version: i.version,
            updated_at: i.updated_at,
            size: i.size,
            deleted: i.tombstone,
        })
        .collect()
}

impl Vault {
    pub(crate) fn from_handle(inner: Handle) -> Vault {
        // An owner-opened handle holds every key an admin token holds.
        let scope = inner.scope().unwrap_or(Scope::Admin);
        Vault { inner, scope }
    }

    /// Open the vault `token` belongs to, over HTTP. The token's checksum is
    /// checked before any request, and the server must be `https://`, or
    /// `http://` on loopback. The vault is then verified from the vault id
    /// the token carries.
    #[cfg(feature = "http")]
    pub fn new(token: &str, server: &str) -> Result<Vault, Error> {
        let keys = parse_token(token)?;
        let api = crate::client::ClientBuilder::new(server)
            .build()
            .map_err(Error::build)?;
        Vault::open(keys, &api)
    }

    /// Open the vault `token` belongs to over `api`: any transport, with the
    /// observer the API carries (a proxy, a test transport, a
    /// [`crate::client::ClientBuilder`] with a private CA, …).
    pub fn with_api(token: &str, api: &Api) -> Result<Vault, Error> {
        Vault::open(parse_token(token)?, api)
    }

    fn open(keys: TokenKeys, api: &Api) -> Result<Vault, Error> {
        let inner = Handle::open_token(api, keys, "the token's vault")?;
        Ok(Vault::from_handle(inner))
    }

    /// Open the vault of the token in `path`. On Unix the file's mode must
    /// be 0600 or 0400, checked before its contents are read; on other
    /// platforms the file is refused (see [`Vault::from_token_file_with`]).
    /// It must hold one token and nothing else.
    #[cfg(feature = "http")]
    pub fn from_token_file(path: impl AsRef<Path>, server: &str) -> Result<Vault, Error> {
        Vault::from_token_file_with(path, server, TokenFileCheck::Permissions)
    }

    /// As [`Vault::from_token_file`], stating how the file's permissions
    /// were established. [`TokenFileCheck::CallerVerified`] is the only way
    /// to read a token file where this crate cannot check its permissions.
    #[cfg(feature = "http")]
    pub fn from_token_file_with(
        path: impl AsRef<Path>,
        server: &str,
        check: TokenFileCheck,
    ) -> Result<Vault, Error> {
        let token = read_token_file(path.as_ref(), check)?;
        Vault::new(&token, server)
    }

    /// Open the vault named by the environment: `GV_SERVER`, and exactly one
    /// of `GV_TOKEN` or `GV_TOKEN_FILE`. Both set is refused, not ranked.
    #[cfg(feature = "http")]
    pub fn from_env() -> Result<Vault, Error> {
        let (token, file) = (set("GV_TOKEN"), set("GV_TOKEN_FILE"));
        if token.is_some() && file.is_some() {
            return Err(Error::local(
                code::INVALID_ENVIRONMENT,
                "GV_TOKEN and GV_TOKEN_FILE are both set; set exactly one",
            ));
        }
        let server = set("GV_SERVER").ok_or_else(|| {
            Error::local(
                code::MISSING_SERVER,
                "GV_SERVER is not set; a token needs the server it belongs to",
            )
        })?;
        let server = server.to_string_lossy().into_owned();
        match (token, file) {
            (Some(token), None) => {
                let token = Zeroizing::new(token.to_string_lossy().into_owned());
                Vault::new(&token, &server)
            }
            (None, Some(file)) => Vault::from_token_file(file, &server),
            _ => Err(Error::Auth {
                code: code::INVALID_TOKEN.to_owned(),
                message: "neither GV_TOKEN nor GV_TOKEN_FILE is set".to_owned(),
            }),
        }
    }

    /// The token's scope, stored when the vault was opened. An owner-opened
    /// handle reports [`Scope::Admin`]: the owner holds every key an admin
    /// token holds.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// The vault id (hex), pinned from the token string or the owner key.
    pub fn vault_id(&self) -> String {
        self.inner.vault_id.to_hex()
    }

    /// How errors and notices name this vault: the environment path, or
    /// "the token's vault".
    pub fn label(&self) -> &str {
        &self.inner.label
    }

    /// The token's expiry, and the latest vault expiry the server announced.
    pub fn expiry(&self) -> Expiry {
        Expiry {
            token_expires_at: self.inner.token_expires_at(),
            vault_expires_at: self.inner.last_expires_at(),
        }
    }

    /// Fetch the vault's current generation again (after a rotation):
    /// the token's bundle and the descriptor, verified from the pinned vault
    /// id. A handle that met [`Error::StaleGeneration`] works again after
    /// this, without being rebuilt.
    pub fn refresh(&self) -> Result<(), Error> {
        self.inner.refresh()
    }

    /// The vault's status, fetched now, its descriptor verified.
    pub fn status(&self) -> Result<VaultStatus, Error> {
        self.inner.refresh_status()
    }

    /// This vault's tokens, for an `admin` token: the same view the owner
    /// gets from [`crate::owner::Environment::tokens`], with a read token's
    /// allow-list names decrypted where this credential can read them.
    ///
    /// The server sends the list to the owner and to `admin` and to nobody
    /// else (`docs/spec/http-api.md#2`), so every other scope is refused
    /// here by name rather than shown an empty list, which would say the
    /// vault has no tokens.
    pub fn tokens(&self) -> Result<Vec<crate::owner::TokenInfo>, Error> {
        if self.scope != Scope::Admin {
            return Err(Error::forbidden(format!(
                "{}: listing tokens needs an admin token; this one is {}",
                self.label(),
                self.scope
            )));
        }
        let status = self.inner.refresh_status()?;
        // Absent is not empty: an admin credential should have been sent the
        // list, so a missing one is the server withholding it, not a vault
        // without tokens.
        let summaries = status.tokens.ok_or_else(|| {
            Error::other(format!(
                "{}: the server did not send this vault's token list",
                self.label()
            ))
        })?;
        let names: std::collections::HashMap<_, _> = self
            .inner
            .list()?
            .into_iter()
            .map(|i| (i.hmac, i.name))
            .collect();
        Ok(summaries
            .into_iter()
            .map(|t| crate::owner::TokenInfo {
                id: t.token_id,
                scope: t.scope,
                created_at: t.created_at,
                expires_at: t.expires_at,
                only: t.allow_list.map(|l| {
                    l.iter()
                        .map(|h| names.get(h).cloned().unwrap_or_else(|| "?".into()))
                        .collect()
                }),
            })
            .collect())
    }

    /// Revoke token `id`, for an `admin` token. The server drops it at once;
    /// this cannot rotate, so the revocation is always forward-only and the
    /// keys the token's bundle held keep working on whatever its holder
    /// already copied. Rotation needs the owner key
    /// ([`crate::owner::Environment::revoke`] with `rotate`).
    ///
    /// The scope is read from the vault's token list first, so the returned
    /// [`crate::owner::Revocation`] can name what the revoked token held,
    /// and a [`Warning::ForwardOnlyRevocation`] is raised for every scope
    /// but `meta`, exactly as the owner path raises it.
    pub fn revoke(&self, id: &TokenId) -> Result<crate::owner::Revocation, Error> {
        if self.scope != Scope::Admin {
            return Err(Error::forbidden(format!(
                "{}: revoking a token needs an admin token; this one is {}",
                self.label(),
                self.scope
            )));
        }
        let status = self.inner.refresh_status()?;
        let scope = status
            .tokens
            .as_ref()
            .and_then(|ts| ts.iter().find(|t| t.token_id == *id))
            .map(|t| t.scope.clone())
            .ok_or_else(|| Error::not_found(format!("{}: has no token {id}", self.label())))?;
        self.inner.revoke(id)?;
        let revocation = crate::owner::Revocation {
            scope,
            rotated_to: None,
        };
        if revocation.forward_only() {
            self.inner
                .api()
                .events()
                .warning(&Warning::ForwardOnlyRevocation {
                    path: self.label().to_owned(),
                    token: id.to_hex(),
                    scope: revocation.scope.to_string(),
                    held: revocation.held_keys(),
                });
        }
        Ok(revocation)
    }

    // ------------------------------------------------------------ integrity

    /// Fetch and verify this vault's audit chain. Pass the head a previous
    /// call returned (kept by you, across handles or runs) to check that the
    /// server's history only grew since; `None` verifies from the first row
    /// served. Every scope may do this. A chain that does not continue from
    /// `known` is an error with code `audit_mismatch`.
    pub fn verify_audit(&self, known: Option<ChainHead>) -> Result<AuditReport, Error> {
        audit::verify(&self.inner, known, 0)
    }

    /// Verify the audit chain from the head recorded in `store` for this
    /// vault, and record the new head. The recorded head moves only when the
    /// whole fetched range verifies.
    pub fn audit(&self, store: &dyn StateStore) -> Result<AuditReport, Error> {
        let mut state = store.load().map_err(Error::store)?;
        let report = audit::verify_recorded(&self.inner, &mut state, 0)?;
        store.save(&state).map_err(Error::store)?;
        Ok(report)
    }

    /// What this handle has seen: the descriptor it verified and the latest
    /// version of every record it read. Persist it and pass it to
    /// [`Vault::set_pins`] on a later handle to detect rollback.
    pub fn pins(&self) -> Pins {
        self.inner.pins()
    }

    /// Adopt pins kept from earlier. An older or different generation than
    /// the pinned one fails with `generation_rollback`; later reads of a
    /// record older than its pinned version fail with `version_rollback`.
    pub fn set_pins(&self, pins: Pins) -> Result<(), Error> {
        self.inner.set_pins(pins)
    }

    // ------------------------------------------------------------ secrets

    fn read(&self, name: &str, version: Option<u64>) -> Result<SecretValue, Error> {
        let v = self.inner.view();
        if !self.inner.may_read(&v, &v.bundle.name_key().hmac(name)) {
            return Err(Error::forbidden(format!(
                "{}: this token may not read {name}",
                self.inner.label
            )));
        }
        let (version, opened) = self.inner.get(name, version)?;
        Ok(SecretValue {
            name: name.to_owned(),
            version,
            value: opened.value,
        })
    }

    /// The latest version of secret `name`.
    pub fn secret(&self, name: &str) -> Result<SecretValue, Error> {
        self.read(name, None)
    }

    /// Version `version` of secret `name`.
    pub fn secret_version(&self, name: &str, version: u64) -> Result<SecretValue, Error> {
        self.read(name, Some(version))
    }

    /// Every named secret, or an error naming the first that could not be
    /// returned. Never a partial set.
    pub fn secrets(&self, names: &[&str]) -> Result<SecretSet, Error> {
        let mut values = Vec::with_capacity(names.len());
        for name in names {
            values.push(self.read(name, None)?);
        }
        Ok(SecretSet { values })
    }

    /// Every live secret this credential may read, or, with `only`, the
    /// readable ones among those names, each of which must exist. All or
    /// nothing: the first failure is the result. This is what `gv run` and
    /// the Python package's `load_env` inject.
    pub fn readable(&self, only: Option<&[&str]>) -> Result<SecretSet, Error> {
        let v = self.inner.view();
        self.inner.vault_secret(&v)?;
        let all = self.inner.list()?;
        let only = only.unwrap_or(&[]);
        for want in only {
            if !all.iter().any(|i| i.name == *want && !i.tombstone) {
                return Err(Error::not_found(format!(
                    "{}: no secret named {want}",
                    self.inner.label
                )));
            }
        }
        let mut values = Vec::new();
        for item in all {
            if item.tombstone
                || is_reserved_name(&item.name)
                || (!only.is_empty() && !only.contains(&item.name.as_str()))
                || !self.inner.may_read(&v, &item.hmac)
            {
                continue;
            }
            let (version, opened) = self.inner.get(&item.name, Some(item.version))?;
            values.push(SecretValue {
                name: item.name,
                version,
                value: opened.value,
            });
        }
        Ok(SecretSet { values })
    }

    /// Every live secret, sorted by name. Each listed record's signature is
    /// verified.
    pub fn list(&self) -> Result<Vec<Entry>, Error> {
        Ok(entries(self.inner.list()?, false))
    }

    /// Every secret, deleted ones included ([`Entry::deleted`]), sorted by
    /// name.
    pub fn list_all(&self) -> Result<Vec<Entry>, Error> {
        Ok(entries(self.inner.list()?, true))
    }

    /// A secret's versions, oldest first, each verified; empty if it never
    /// existed.
    pub fn history(&self, name: &str) -> Result<Vec<VersionMeta>, Error> {
        self.inner.versions(name)
    }

    /// Create `name`, or update it from its current version; returns the new
    /// version. A write that loses a race fails with a conflict.
    pub fn set_secret(&self, name: &str, value: &[u8]) -> Result<u64, Error> {
        refuse_reserved(name)?;
        let pre = self.inner.current(name)?;
        self.inner.put(name, value, pre)
    }

    /// Write `name` only if it stands as `expect` says; returns the new
    /// version. [`Expect::Absent`] also revives a deleted secret.
    pub fn set_secret_expecting(
        &self,
        name: &str,
        value: &[u8],
        expect: Expect,
    ) -> Result<u64, Error> {
        refuse_reserved(name)?;
        let pre = match expect {
            Expect::Version(v) => Pre::Update(v),
            // `If-None-Match: *`: the server refuses it if the secret is live.
            Expect::Absent => match self.inner.current(name)? {
                Pre::Update(v) => Pre::Revive(v),
                other => other,
            },
        };
        self.inner.put(name, value, pre)
    }

    /// Delete secret `name` (a signed tombstone; history is kept). With
    /// `expected`, only if its latest version is still that one. Returns the
    /// tombstone's version.
    pub fn delete_secret(&self, name: &str, expected: Option<u64>) -> Result<u64, Error> {
        refuse_reserved(name)?;
        let label = &self.inner.label;
        let version = match expected {
            Some(v) => v,
            None => match self.inner.current(name)? {
                Pre::Create => {
                    return Err(Error::not_found(format!("{label}: no secret named {name}")));
                }
                Pre::Revive(v) => {
                    return Err(Error::not_found(format!(
                        "{label}: {name} is already deleted (version {v})"
                    )));
                }
                Pre::Update(v) => v,
            },
        };
        self.inner.delete(name, version)
    }

    // ------------------------------------------------------------ configs

    fn read_config(&self, name: &str, version: Option<u64>) -> Result<ConfigDocument, Error> {
        let (version, opened) = self.inner.get_config(name, version)?;
        Ok(ConfigDocument {
            name: name.to_owned(),
            version,
            format: opened.format,
            body: opened.body,
        })
    }

    /// The latest version of config `name`.
    pub fn config(&self, name: &str) -> Result<ConfigDocument, Error> {
        self.read_config(name, None)
    }

    /// Version `version` of config `name`.
    pub fn config_version(&self, name: &str, version: u64) -> Result<ConfigDocument, Error> {
        self.read_config(name, Some(version))
    }

    /// Every live config, sorted by name.
    pub fn list_configs(&self) -> Result<Vec<Entry>, Error> {
        Ok(entries(self.inner.list_configs()?, false))
    }

    /// Every config, deleted ones included, sorted by name.
    pub fn list_configs_all(&self) -> Result<Vec<Entry>, Error> {
        Ok(entries(self.inner.list_configs()?, true))
    }

    /// A config's versions, oldest first, each verified; empty if it never
    /// existed.
    pub fn config_history(&self, name: &str) -> Result<Vec<VersionMeta>, Error> {
        self.inner.config_versions(name)
    }

    /// Write config `name`. Before any request the body is checked against
    /// its declared format, and refused if it holds a credential literal
    /// (unless the config allows literals). Without an expectation it
    /// updates from the current version; with one it succeeds only against
    /// the version the caller read.
    pub fn set_config(&self, name: &str, config: NewConfig) -> Result<u64, Error> {
        refuse_reserved(name)?;
        validate(config.format, &config.body)?;
        if !config.allow_literals {
            scan_literals(&config.body)?;
        }
        let pre = match config.expect {
            Some(Expect::Version(v)) => Pre::Update(v),
            // `If-None-Match: *`: the server refuses it if the config is live.
            Some(Expect::Absent) => match self.inner.config_current(name)? {
                Pre::Update(v) => Pre::Revive(v),
                other => other,
            },
            None => self.inner.config_current(name)?,
        };
        self.inner
            .put_config(name, config.format, &config.body, pre)
    }

    /// Delete config `name` (a signed tombstone; history is kept). With
    /// `expected`, only if its latest version is still that one. Returns the
    /// tombstone's version.
    pub fn delete_config(&self, name: &str, expected: Option<u64>) -> Result<u64, Error> {
        refuse_reserved(name)?;
        let label = &self.inner.label;
        let version = match expected {
            Some(v) => v,
            None => match self.inner.config_current(name)? {
                Pre::Create => {
                    return Err(Error::not_found(format!("{label}: no config named {name}")));
                }
                Pre::Revive(v) => {
                    return Err(Error::not_found(format!(
                        "{label}: config {name} is already deleted (version {v})"
                    )));
                }
                Pre::Update(v) => v,
            },
        };
        self.inner.delete_config(name, version)
    }
}

/// What reporting a leaked token did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LeakReport {
    /// The token's id.
    pub token_id: String,
    /// Whether the server revoked it now (false: it had nothing to revoke).
    pub revoked: bool,
}

/// Report a leaked token so its server revokes it, by proving possession.
/// The token string is never sent: only a signature made with it is.
pub fn report_leaked_token(api: &Api, token: &str) -> Result<LeakReport, Error> {
    let keys = parse_token(token)?;
    let id = keys.id();
    let response = Handle::report_token(api, &keys)?;
    Ok(LeakReport {
        token_id: id.to_string(),
        revoked: response.revoked.contains(&id),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_vault_is_send_and_sync() {
        fn shared<T: Send + Sync>() {}
        shared::<Vault>();
    }

    #[cfg(feature = "http")]
    #[test]
    fn construction_checks_before_any_request() {
        use crate::proto::ids::VaultId;
        let e = Vault::new("gvt1_nonsense", "https://vault.example").unwrap_err();
        assert_eq!(e.code(), code::INVALID_TOKEN);
        let token = TokenKeys::generate(VaultId([1; 16])).token_string();
        let e = Vault::new(&token, "http://vault.example").unwrap_err();
        assert_eq!(e.code(), code::INVALID_SERVER);
        assert!(e.message().contains("https://"), "{e}");
        assert!(!e.message().contains(token.as_str()));
    }

    #[test]
    fn a_token_of_another_version_is_refused() {
        let other = crate::proto::codec::encode_checked("gvt2_", &[7u8; 48]);
        let e = parse_token(&other).unwrap_err();
        assert_eq!(
            (e.code(), e.kind()),
            (code::INVALID_TOKEN, crate::ErrorKind::Auth)
        );
        assert!(e.message().contains("version 2"), "{e}");
        assert!(!e.message().contains(&other[5..]), "{e}");
    }

    /// Where file permissions cannot be checked, a token file is refused
    /// unless the caller vouches for it, and its contents are not read.
    #[cfg(not(unix))]
    #[test]
    fn a_token_file_fails_closed_where_permissions_cannot_be_checked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        let token = TokenKeys::generate(crate::proto::ids::VaultId([2; 16])).token_string();
        std::fs::write(&path, token.as_str()).unwrap();
        let e = read_token_file(&path, TokenFileCheck::Permissions).unwrap_err();
        assert_eq!(e.code(), code::INVALID_TOKEN_FILE);
        assert!(e.message().contains("cannot be verified"), "{e}");
        assert!(!e.message().contains(token.as_str()));
        let read = read_token_file(&path, TokenFileCheck::CallerVerified).unwrap();
        assert_eq!(read.as_str(), token.as_str());
    }

    #[cfg(unix)]
    #[test]
    fn a_token_file_mode_is_checked_whatever_the_caller_says() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("token");
        std::fs::write(&path, "gvt1_x").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        for check in [TokenFileCheck::Permissions, TokenFileCheck::CallerVerified] {
            let e = read_token_file(&path, check).unwrap_err();
            assert!(e.message().contains("0644"), "{e}");
        }
    }
}
