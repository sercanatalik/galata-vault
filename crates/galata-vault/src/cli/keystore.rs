//! The CLI's key stores: the OS keychain, or a 0600 credentials file when
//! there is no keychain (or `<prefix>CREDENTIAL_STORE=file`). Both implement
//! the SDK's [`KeyStore`]; the SDK itself ships neither, and an embedding
//! binary may supply its own through [`crate::cli::ContextBuilder::key_store`].
//!
//! Only held keys are stored: a project key, or a node key imported from a
//! kit (and a rekey's keys while it runs). Environment keys below a held key
//! are recomputed on every use.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use crate::{KeyName, KeyStore, StoreError};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::cli::branding::Branding;
use crate::cli::config::Home;
use crate::cli::context::{Output, say};
use crate::cli::fsutil::{require_private, write_private};

/// Keys in the OS keychain, under one service name.
#[derive(Debug, Clone)]
pub struct Keychain {
    service: &'static str,
}

impl Keychain {
    /// The keychain entries of `service` (`galata-vault` for `gv`).
    pub fn new(service: &'static str) -> Keychain {
        Keychain { service }
    }
}

impl KeyStore for Keychain {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        let entry = keyring::Entry::new(self.service, &key.entry())
            .map_err(|e| StoreError::with_source(format!("reading the OS keychain: {e}"), e))?;
        match entry.get_password() {
            Ok(v) => Ok(Some(Zeroizing::new(v))),
            Err(keyring::Error::NoEntry) => Ok(None),
            Err(e) => Err(StoreError::with_source(
                format!("reading the OS keychain: {e}"),
                e,
            )),
        }
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        keyring::Entry::new(self.service, &key.entry())
            .and_then(|e| e.set_password(value))
            .map_err(|e| StoreError::with_source(format!("writing to the OS keychain: {e}"), e))
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        let entry = keyring::Entry::new(self.service, &key.entry()).map_err(|e| {
            StoreError::with_source(format!("deleting from the OS keychain: {e}"), e)
        })?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(e) => Err(StoreError::with_source(
                format!("deleting from the OS keychain: {e}"),
                e,
            )),
        }
    }
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredFile {
    #[serde(default)]
    credentials: BTreeMap<String, String>,
}

impl Drop for CredFile {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        for v in self.credentials.values_mut() {
            v.zeroize();
        }
    }
}

/// Keys in a credentials file, written with mode 0600 and refused unless its
/// mode is 0600 or 0400.
#[derive(Debug, Clone)]
pub struct CredentialsFile {
    path: PathBuf,
}

fn store_error(e: anyhow::Error) -> StoreError {
    StoreError::new(format!("{e:#}"))
}

impl CredentialsFile {
    /// The credentials file at `path`.
    pub fn new(path: impl Into<PathBuf>) -> CredentialsFile {
        CredentialsFile { path: path.into() }
    }

    fn load(&self) -> Result<CredFile, StoreError> {
        if !self.path.exists() {
            return Ok(CredFile::default());
        }
        require_private(&self.path).map_err(store_error)?;
        let text = Zeroizing::new(std::fs::read_to_string(&self.path).map_err(|e| {
            StoreError::with_source(format!("reading {}: {e}", self.path.display()), e)
        })?);
        // The parse error never quotes the file: it holds keys.
        toml::from_str(&text).map_err(|_| {
            StoreError::new(format!(
                "{} is not a valid credentials file",
                self.path.display()
            ))
        })
    }

    fn save(&self, file: &CredFile) -> Result<(), StoreError> {
        let text = Zeroizing::new(
            toml::to_string(file)
                .map_err(|_| StoreError::new("the credentials could not be encoded"))?,
        );
        write_private(&self.path, text.as_bytes()).map_err(store_error)
    }
}

impl KeyStore for CredentialsFile {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        Ok(self
            .load()?
            .credentials
            .get(&key.entry())
            .map(|v| Zeroizing::new(v.clone())))
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        let mut file = self.load()?;
        file.credentials.insert(key.entry(), value.to_owned());
        self.save(&file)
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        let mut file = self.load()?;
        if file.credentials.remove(&key.entry()).is_some() {
            self.save(&file)?;
        }
        Ok(())
    }
}

/// Pick the store: `<prefix>CREDENTIAL_STORE=keychain|file`, else the
/// keychain when the platform has one, else the file (saying so).
fn open(home: &Home, b: &Branding, output: &dyn Output) -> Result<Box<dyn KeyStore>, StoreError> {
    let var = b.var("CREDENTIAL_STORE");
    let file = || -> Box<dyn KeyStore> { Box::new(CredentialsFile::new(home.credentials_path())) };
    match std::env::var(&var).as_deref() {
        Ok("file") => Ok(file()),
        Ok("keychain") => match keyring::Entry::store_status() {
            Ok(()) => Ok(Box::new(Keychain::new(b.keychain_service))),
            Err(e) => Err(StoreError::new(format!(
                "{var}=keychain, but no keychain is available: {e}"
            ))),
        },
        Ok(other) => Err(StoreError::new(format!(
            "{var} must be \"keychain\" or \"file\", not {other:?}"
        ))),
        Err(_) => {
            if keyring::Entry::store_status().is_ok() {
                Ok(Box::new(Keychain::new(b.keychain_service)))
            } else {
                say(
                    output,
                    b.message_prefix,
                    &format!(
                        "no OS keychain available; keeping keys in {} (mode 0600)",
                        home.credentials_path().display()
                    ),
                );
                Ok(file())
            }
        }
    }
}

/// The CLI's default store, chosen the first time a key is needed (so a
/// command that needs no key never touches the keychain).
pub(crate) struct LazyKeyStore {
    home: Home,
    branding: Branding,
    output: Arc<dyn Output>,
    inner: OnceLock<Result<Box<dyn KeyStore>, StoreError>>,
}

impl LazyKeyStore {
    pub(crate) fn new(home: Home, branding: Branding, output: Arc<dyn Output>) -> LazyKeyStore {
        LazyKeyStore {
            home,
            branding,
            output,
            inner: OnceLock::new(),
        }
    }

    fn store(&self) -> Result<&dyn KeyStore, StoreError> {
        match self
            .inner
            .get_or_init(|| open(&self.home, &self.branding, &*self.output))
        {
            Ok(s) => Ok(s.as_ref()),
            Err(e) => Err(e.clone()),
        }
    }
}

impl KeyStore for LazyKeyStore {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        self.store()?.get(key)
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        self.store()?.set(key, value)
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        self.store()?.delete(key)
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn file_store_roundtrip_and_mode_check() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let store = CredentialsFile::new(&path);
        let acme = KeyName::Node("acme".parse().unwrap());
        assert!(store.get(&acme).unwrap().is_none());
        store.set(&acme, "gvk1_x").unwrap();
        assert_eq!(store.get(&acme).unwrap().unwrap().as_str(), "gvk1_x");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("node:acme")
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o400)).unwrap();
        assert!(store.get(&acme).is_ok(), "0400 is accepted");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.get(&acme).unwrap_err().to_string();
        assert!(
            err.contains("credentials.toml") && err.contains("0600"),
            "{err}"
        );
        assert!(!err.contains("gvk1_"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        store.delete(&acme).unwrap();
        assert!(store.get(&acme).unwrap().is_none());
    }
}
