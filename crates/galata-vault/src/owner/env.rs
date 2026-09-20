//! An environment opened by its owner: the record operations of a
//! [`Vault`] (it derefs to one), plus tokens and rotation.

use std::ops::Deref;

use galata_vault_client::Warning;
use galata_vault_proto::api::{Scope, TokenSummary, VaultStatus};
use galata_vault_proto::ids::TokenId;
use galata_vault_proto::path::EnvPath;
use galata_vault_proto::tolerant::Tolerant;
use zeroize::Zeroizing;

use crate::error::Error;
use crate::token::Vault;
use crate::vault::Handle;

/// An environment's vault, opened with its owner key by
/// [`crate::owner::Owner::environment`]. Everything a [`Vault`] does is
/// available through `Deref`; the owner can also mint, list and revoke
/// tokens, and rotate.
pub struct Environment {
    vault: Vault,
    path: EnvPath,
    status: VaultStatus,
}

impl std::fmt::Debug for Environment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Environment")
            .field("path", &self.path)
            .field("vault_id", &self.vault.vault_id())
            .finish()
    }
}

impl Deref for Environment {
    type Target = Vault;

    fn deref(&self) -> &Vault {
        &self.vault
    }
}

/// A token as the owner sees it in the vault's status.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TokenInfo {
    /// Its id.
    pub id: TokenId,
    /// Its scope: one this client knows, or the name of one a newer client
    /// minted (shown, never acted on).
    pub scope: Tolerant<Scope>,
    /// When it was minted.
    pub created_at: i64,
    /// When it expires.
    pub expires_at: i64,
    /// A read token's allow-list, names decrypted (`?` for one not found).
    pub only: Option<Vec<String>>,
}

/// A token just minted. The token string is shown once, through
/// [`MintedToken::expose`], and is zeroized on drop; `Debug` shows only the
/// id and scope.
pub struct MintedToken {
    id: TokenId,
    scope: Scope,
    expires_at: i64,
    token: Zeroizing<String>,
}

impl std::fmt::Debug for MintedToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedToken")
            .field("id", &self.id)
            .field("scope", &self.scope)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

impl MintedToken {
    /// The token's id.
    pub fn id(&self) -> TokenId {
        self.id
    }

    /// Its scope.
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// When it expires (Unix seconds).
    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// The token string (`gvt1_…`). Hand it over and let this value drop.
    pub fn expose(&self) -> &str {
        &self.token
    }
}

/// What a revocation did.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Revocation {
    /// The revoked token's scope, as the vault's status named it.
    pub scope: Tolerant<Scope>,
    /// The generation the vault rotated to, if the revocation rotated.
    pub rotated_to: Option<u32>,
}

impl Revocation {
    /// Whether the revoked token held key material that outlives a
    /// revocation without rotation: every scope but `meta` does, and a scope
    /// this client does not know is assumed to.
    pub fn forward_only(&self) -> bool {
        self.rotated_to.is_none() && self.scope != Scope::Meta
    }

    /// The keys the token's bundle held, as a phrase ("the secret key, the
    /// secret writer key").
    pub fn held_keys(&self) -> String {
        match self.scope.get() {
            Some(scope) => held_keys(scope),
            None => "keys this client cannot name (its scope is newer than this client)".to_owned(),
        }
    }
}

/// The keys a scope's bundle holds, for the revocation warning.
fn held_keys(scope: Scope) -> String {
    let mut keys = Vec::new();
    if scope.bundle_holds_vault_key() {
        keys.push("the secret key");
    }
    if scope.bundle_holds_config_key() {
        keys.push("the config key");
    }
    if scope.bundle_holds_secret_writer() {
        keys.push("the secret writer key");
    }
    if scope.bundle_holds_config_writer() {
        keys.push("the config writer key");
    }
    keys.join(", ")
}

impl Environment {
    pub(crate) fn new(handle: Handle, path: EnvPath) -> Result<Environment, Error> {
        let status = handle.status().ok_or_else(|| {
            Error::other(format!("{path}: the vault was not opened by its owner"))
        })?;
        Ok(Environment {
            vault: Vault::from_handle(handle),
            path,
            status,
        })
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.vault.inner
    }

    /// The environment's path.
    pub fn path(&self) -> &EnvPath {
        &self.path
    }

    /// The vault's status as it was opened: generation, expiry, usage,
    /// limits and the token list.
    pub fn status_at_open(&self) -> &VaultStatus {
        &self.status
    }

    /// The token list from the status this environment was opened with.
    ///
    /// `None` is not an empty vault: it is a server that did not send the
    /// list, which for an owner-opened environment should not happen. It is
    /// refused rather than flattened away, because the one caller that most
    /// needs it is the guard in [`Environment::mint`], which exists to stop
    /// a mint while a token of an unknown scope is present — and an absent
    /// list is exactly when that guard would otherwise wave everything
    /// through. `galata_vault_seal::SealError::TokensNotVisible` refuses the
    /// same way for a rotation.
    fn visible_tokens(&self) -> Result<&[TokenSummary], Error> {
        self.status.tokens.as_deref().ok_or_else(|| {
            Error::other(format!(
                "{}: the server did not send this vault's token list; \
                 ask for status as the owner",
                self.path
            ))
        })
    }

    /// The vault's tokens, as of its status at open, with a read token's
    /// allow-list names decrypted.
    pub fn tokens(&self) -> Result<Vec<TokenInfo>, Error> {
        let tokens = self.visible_tokens()?.to_vec();
        let names: std::collections::HashMap<_, _> = self
            .handle()
            .list()?
            .into_iter()
            .map(|i| (i.hmac, i.name))
            .collect();
        Ok(tokens
            .into_iter()
            .map(|t| TokenInfo {
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

    /// Mint a token of `scope`: fresh keys, an owner-signed bundle holding
    /// exactly what the scope allows. `ttl_secs` 0 takes the server's
    /// default. `only` names the secrets a read token may read (empty: all).
    ///
    /// Refused with `unsupported_by_client` while the vault holds a token
    /// whose scope this client does not know: a newer client has used the
    /// vault in a way this one cannot account for (`docs/spec/http-api.md#7`).
    pub fn mint(&self, scope: Scope, ttl_secs: u64, only: &[String]) -> Result<MintedToken, Error> {
        if let Some(t) = self.visible_tokens()?.iter().find(|t| !t.scope.is_known()) {
            return Err(Error::unsupported(format!(
                "{}: token {} has scope {:?}, which this client does not know; upgrade before minting",
                self.path,
                t.token_id,
                t.scope.unknown().unwrap_or("?")
            )));
        }
        let h = self.handle();
        let allow = (!only.is_empty()).then(|| only.iter().map(|n| h.hmac(n)).collect());
        let (token, registered) = h.mint(scope, ttl_secs, allow)?;
        Ok(MintedToken {
            id: registered.token_id,
            scope,
            expires_at: registered.expires_at,
            token: token.token_string(),
        })
    }

    /// Revoke token `id`. With `rotate`, the vault moves to fresh keys in the
    /// same step, so the token's keys open and sign nothing afterwards.
    /// Without it the revocation is forward-only for every scope but `meta`,
    /// which is reported as [`Warning::ForwardOnlyRevocation`] (and by
    /// [`Revocation::forward_only`]).
    pub fn revoke(&self, id: &TokenId, rotate: bool) -> Result<Revocation, Error> {
        let scope = self
            .status
            .tokens
            .as_ref()
            .and_then(|ts| ts.iter().find(|t| t.token_id == *id))
            .map(|t| t.scope.clone())
            .ok_or_else(|| Error::not_found(format!("{} has no token {id}", self.path)))?;
        let h = self.handle();
        if rotate {
            let generation = h.rotate(&[*id])?;
            return Ok(Revocation {
                scope,
                rotated_to: Some(generation),
            });
        }
        h.revoke(id)?;
        let revocation = Revocation {
            scope,
            rotated_to: None,
        };
        if revocation.forward_only() {
            h.api().events().warning(&Warning::ForwardOnlyRevocation {
                path: self.path.to_string(),
                token: id.to_hex(),
                scope: revocation.scope.to_string(),
                held: revocation.held_keys(),
            });
        }
        Ok(revocation)
    }

    /// Move the vault to a new generation: fresh keys, every record
    /// re-encrypted and re-signed, every token's bundle resealed. Returns the
    /// new generation. Open the environment again (or
    /// [`Vault::refresh`]) to use it.
    pub fn rotate(&self) -> Result<u32, Error> {
        self.handle().rotate(&[])
    }
}
