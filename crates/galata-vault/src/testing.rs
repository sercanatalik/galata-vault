//! For adversarial test harnesses only (feature `test-util`, never enabled
//! by a shipped crate): the per-vault protocol without local state, so a
//! test can set up a vault, forge what a malicious server would serve, and
//! aim an attack at the owner's side of the protocol directly.
//!
//! Applications use [`crate::Vault`] and [`crate::owner`]; nothing here is
//! needed to use the service.

use crate::client::{Api, Pre};
use crate::keys::{NameKey, NodeKey, TokenKeys};
use crate::proto::api::{RegisterTokenResponse, RevokeResponse, Scope};
use crate::proto::children::ChildrenRecord;
use crate::proto::descriptor::Descriptor;
use crate::proto::ids::{NameHmac, TokenId, VaultId};
use crate::seal::{ConfigFormat, Opened, OpenedConfig};

use crate::error::Error;
use crate::token::Vault;
use crate::vault::Handle;

/// One vault's protocol handle, opened by an owner key or a token.
pub struct RawVault(Handle);

impl std::fmt::Debug for RawVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawVault")
            .field("label", &self.0.label)
            .finish_non_exhaustive()
    }
}

impl RawVault {
    /// Create the vault for `key`; `false` if it already exists.
    pub fn create(api: &Api, key: &NodeKey, label: &str) -> Result<bool, Error> {
        Handle::create(api, key, label)
    }

    /// Open a vault as its owner.
    pub fn open_owner(api: &Api, key: &NodeKey, label: &str) -> Result<RawVault, Error> {
        Handle::open_owner(api, key, label).map(RawVault)
    }

    /// Open a token's vault.
    pub fn open_token(api: &Api, token: TokenKeys, label: &str) -> Result<RawVault, Error> {
        Handle::open_token(api, token, label).map(RawVault)
    }

    /// The token client over this handle.
    pub fn into_vault(self) -> Vault {
        Vault::from_handle(self.0)
    }

    /// The vault id.
    pub fn vault_id(&self) -> VaultId {
        self.0.vault_id
    }

    /// The verified descriptor of the current generation.
    pub fn descriptor(&self) -> Descriptor {
        self.0.view().descriptor.clone()
    }

    /// The name key this credential holds.
    pub fn name_key(&self) -> NameKey {
        self.0.name_key()
    }

    /// The secret writer key, if this credential holds it.
    pub fn secret_writer(&self) -> Option<crate::keys::WriterKey> {
        self.0.view().bundle.secret_writer().cloned()
    }

    /// The config writer key, if this credential holds it.
    pub fn config_writer(&self) -> Option<crate::keys::WriterKey> {
        self.0.view().bundle.config_writer().cloned()
    }

    /// Mint a token (owner only).
    pub fn mint(
        &self,
        scope: Scope,
        ttl_secs: u64,
        allow_list: Option<Vec<NameHmac>>,
    ) -> Result<(TokenKeys, RegisterTokenResponse), Error> {
        self.0.mint(scope, ttl_secs, allow_list)
    }

    /// The precondition for writing secret `name` now.
    pub fn current(&self, name: &str) -> Result<Pre, Error> {
        self.0.current(name)
    }

    /// Write secret `name` under `pre`.
    pub fn put(&self, name: &str, value: &[u8], pre: Pre) -> Result<u64, Error> {
        self.0.put(name, value, pre)
    }

    /// Delete secret `name` at live `version`.
    pub fn delete(&self, name: &str, version: u64) -> Result<u64, Error> {
        self.0.delete(name, version)
    }

    /// Read secret `name`.
    pub fn get(&self, name: &str, version: Option<u64>) -> Result<(u64, Opened), Error> {
        self.0.get(name, version)
    }

    /// The precondition for writing config `name` now.
    pub fn config_current(&self, name: &str) -> Result<Pre, Error> {
        self.0.config_current(name)
    }

    /// Write config `name` under `pre`.
    pub fn put_config(
        &self,
        name: &str,
        format: ConfigFormat,
        body: &[u8],
        pre: Pre,
    ) -> Result<u64, Error> {
        self.0.put_config(name, format, body, pre)
    }

    /// Read config `name`.
    pub fn get_config(
        &self,
        name: &str,
        version: Option<u64>,
    ) -> Result<(u64, OpenedConfig), Error> {
        self.0.get_config(name, version)
    }

    /// The owner-only children record and the precondition to replace it.
    pub fn children(&self) -> Result<(ChildrenRecord, Pre), Error> {
        self.0.children()
    }

    /// Rotate, revoking `revoke` in the same step (owner only).
    pub fn rotate(&self, revoke: &[TokenId]) -> Result<u32, Error> {
        self.0.rotate(revoke)
    }

    /// Revoke without rotating.
    pub fn revoke(&self, id: &TokenId) -> Result<RevokeResponse, Error> {
        self.0.revoke(id)
    }

    /// Fetch the current generation again.
    pub fn refresh(&self) -> Result<(), Error> {
        self.0.refresh()
    }
}
