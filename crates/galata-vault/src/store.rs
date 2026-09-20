//! Key storage, supplied by the caller.
//!
//! The owner API reads and writes node keys only through a [`KeyStore`].
//! This crate ships no implementation that touches the operating system:
//! `gv` implements it over the OS keychain and a 0600 credentials file, and a
//! product brings its own secure storage. Only held keys are stored (a
//! project key, or a node key imported from a kit, and a rekey's keys while
//! it runs); keys derived below a held one are recomputed on every use.

use std::sync::Arc;

use galata_vault_proto::ids::{TokenId, VaultId};
use galata_vault_proto::path::EnvPath;
use zeroize::Zeroizing;

/// A key store or state store failed. The message names what, never the
/// key.
#[derive(Debug, Clone)]
pub struct StoreError {
    message: String,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl StoreError {
    /// A failure described by `message`.
    pub fn new(message: impl Into<String>) -> StoreError {
        StoreError {
            message: message.into(),
            source: None,
        }
    }

    /// A failure described by `message`, caused by `source`.
    pub fn with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> StoreError {
        StoreError {
            message: message.into(),
            source: Some(Arc::new(source)),
        }
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for StoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Which key an entry holds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyName {
    /// A held node key: a project root, or a node imported from a kit.
    Node(EnvPath),
    /// A token string, for a caller that keeps tokens beside its keys.
    Token {
        /// The token's vault.
        vault: VaultId,
        /// The token's id.
        id: TokenId,
    },
    /// A rekey's old root key, kept until the rekey completes.
    RekeyOld(EnvPath),
    /// A rekey's new root key, kept until the rekey completes.
    RekeyNew(EnvPath),
}

impl KeyName {
    /// A stable string for the entry, as `gv` names its keychain entries:
    /// `node:acme/dev`, `rekey-old:acme`, `rekey-new:acme`,
    /// `token:<vault hex>:<id hex>`.
    pub fn entry(&self) -> String {
        match self {
            KeyName::Node(p) => format!("node:{p}"),
            KeyName::Token { vault, id } => format!("token:{}:{}", vault.to_hex(), id.to_hex()),
            KeyName::RekeyOld(p) => format!("rekey-old:{p}"),
            KeyName::RekeyNew(p) => format!("rekey-new:{p}"),
        }
    }
}

impl std::fmt::Display for KeyName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.entry())
    }
}

/// Where node keys live. Values cross this trait in zeroizing buffers.
pub trait KeyStore: Send + Sync {
    /// The value stored for `key`, or `None`.
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError>;
    /// Store `value` for `key`, replacing any.
    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError>;
    /// Forget `key`. Forgetting an absent key succeeds.
    fn delete(&self, key: &KeyName) -> Result<(), StoreError>;
}

impl<K: KeyStore + ?Sized> KeyStore for Arc<K> {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        (**self).get(key)
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        (**self).set(key, value)
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        (**self).delete(key)
    }
}

/// Keys in memory, for tests (feature `test-util`). Cleared on drop.
#[cfg(feature = "test-util")]
#[derive(Default)]
pub struct MemoryKeyStore {
    entries: std::sync::Mutex<std::collections::BTreeMap<String, Zeroizing<String>>>,
}

#[cfg(feature = "test-util")]
impl std::fmt::Debug for MemoryKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemoryKeyStore")
            .field("entries", &self.names())
            .finish()
    }
}

#[cfg(feature = "test-util")]
impl MemoryKeyStore {
    /// An empty store.
    pub fn new() -> MemoryKeyStore {
        MemoryKeyStore::default()
    }

    /// The entry names held, sorted. Never the values.
    pub fn names(&self) -> Vec<String> {
        self.lock().keys().cloned().collect()
    }

    fn lock(
        &self,
    ) -> std::sync::MutexGuard<'_, std::collections::BTreeMap<String, Zeroizing<String>>> {
        self.entries.lock().unwrap_or_else(|p| p.into_inner())
    }
}

#[cfg(feature = "test-util")]
impl KeyStore for MemoryKeyStore {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        Ok(self.lock().get(&key.entry()).cloned())
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        self.lock()
            .insert(key.entry(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        self.lock().remove(&key.entry());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn entry_names_are_the_ones_gv_has_always_used() {
        let p: EnvPath = "acme/dev".parse().unwrap();
        assert_eq!(KeyName::Node(p.clone()).entry(), "node:acme/dev");
        assert_eq!(KeyName::RekeyOld(p.clone()).entry(), "rekey-old:acme/dev");
        assert_eq!(KeyName::RekeyNew(p).entry(), "rekey-new:acme/dev");
    }
}
