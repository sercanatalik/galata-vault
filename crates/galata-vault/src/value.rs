//! What the token client hands back. Plaintext sits in buffers zeroized on
//! drop, and none of these types can print it: no `Display`, no `Serialize`,
//! and a `Debug` that shows names, versions, formats and sizes only.
//! Plaintext is reached through `expose()`, which returns exactly the bytes
//! that were written.

use crate::seal::ConfigFormat;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::{Error, code};

/// A decrypted secret.
pub struct SecretValue {
    pub(crate) name: String,
    pub(crate) version: u64,
    pub(crate) value: Zeroizing<Vec<u8>>,
}

impl SecretValue {
    /// The secret's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version read.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The value's length in bytes.
    pub fn len(&self) -> usize {
        self.value.len()
    }

    /// Whether the value is empty.
    pub fn is_empty(&self) -> bool {
        self.value.is_empty()
    }

    /// The plaintext, exactly as written.
    pub fn expose(&self) -> &[u8] {
        &self.value
    }
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretValue")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("size", &self.value.len())
            .finish()
    }
}

/// Several secrets, fetched all-or-nothing.
#[derive(Debug)]
pub struct SecretSet {
    pub(crate) values: Vec<SecretValue>,
}

impl SecretSet {
    /// The secret named `name`, if the set holds it.
    pub fn get(&self, name: &str) -> Option<&SecretValue> {
        self.values.iter().find(|v| v.name == name)
    }

    /// Every secret in the set, sorted by name.
    pub fn iter(&self) -> impl Iterator<Item = &SecretValue> {
        self.values.iter()
    }

    /// How many secrets the set holds.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

impl IntoIterator for SecretSet {
    type Item = SecretValue;
    type IntoIter = std::vec::IntoIter<SecretValue>;

    fn into_iter(self) -> Self::IntoIter {
        self.values.into_iter()
    }
}

/// A decrypted config document.
pub struct ConfigDocument {
    pub(crate) name: String,
    pub(crate) version: u64,
    pub(crate) format: ConfigFormat,
    pub(crate) body: Zeroizing<Vec<u8>>,
}

impl ConfigDocument {
    /// The config's name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The version read.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The declared format.
    pub fn format(&self) -> ConfigFormat {
        self.format
    }

    /// The body's length in bytes.
    pub fn len(&self) -> usize {
        self.body.len()
    }

    /// Whether the body is empty.
    pub fn is_empty(&self) -> bool {
        self.body.is_empty()
    }

    /// The body, exactly as written: no newline, whitespace or encoding
    /// normalisation.
    pub fn expose(&self) -> &[u8] {
        &self.body
    }

    /// The body as text. Configs are checked for UTF-8 before they are
    /// written, so this fails only for a document written some other way.
    pub fn text(&self) -> Result<&str, Error> {
        std::str::from_utf8(&self.body)
            .map_err(|_| Error::local(code::NOT_TEXT, format!("config {} is not UTF-8", self.name)))
    }

    /// Parse a `toml` or `json` body into a caller type. `yaml` and `text`
    /// are refused: parse those yourself from [`ConfigDocument::expose`].
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, Error> {
        match self.format {
            ConfigFormat::Toml => toml::from_str::<T>(self.text()?).map_err(|e| {
                let line = e.span().map_or(1, |s| {
                    self.body[..s.start.min(self.body.len())]
                        .iter()
                        .filter(|b| **b == b'\n')
                        .count()
                        + 1
                });
                Error::local(
                    code::INVALID_CONFIG,
                    format!(
                        "config {}, line {line}: the toml does not fit the type",
                        self.name
                    ),
                )
            }),
            ConfigFormat::Json => serde_json::from_slice::<T>(&self.body).map_err(|e| {
                Error::local(
                    code::INVALID_CONFIG,
                    format!(
                        "config {}, line {}: the json does not fit the type",
                        self.name,
                        e.line()
                    ),
                )
            }),
            other => Err(Error::local(
                code::UNSUPPORTED_FORMAT,
                format!(
                    "config {} is {other}; only toml and json deserialize, so parse it from expose()",
                    self.name
                ),
            )),
        }
    }
}

impl std::fmt::Debug for ConfigDocument {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigDocument")
            .field("name", &self.name)
            .field("version", &self.version)
            .field("format", &self.format)
            .field("size", &self.body.len())
            .finish()
    }
}

/// What a write expects the record to be, checked by the server: a stale
/// write fails with a conflict naming both versions, and is never retried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expect {
    /// Its latest version is this live one (`If-Match`).
    Version(u64),
    /// It does not exist, or was deleted (`If-None-Match: *`).
    Absent,
}

/// A config document to write.
pub struct NewConfig {
    pub(crate) format: ConfigFormat,
    pub(crate) body: Zeroizing<Vec<u8>>,
    pub(crate) allow_literals: bool,
    pub(crate) expect: Option<Expect>,
}

impl NewConfig {
    /// A document of `format`.
    pub fn new(format: ConfigFormat, body: impl Into<Vec<u8>>) -> NewConfig {
        NewConfig {
            format,
            body: Zeroizing::new(body.into()),
            allow_literals: false,
            expect: None,
        }
    }

    /// A `toml` document.
    pub fn toml(body: impl Into<Vec<u8>>) -> NewConfig {
        NewConfig::new(ConfigFormat::Toml, body)
    }

    /// A `json` document.
    pub fn json(body: impl Into<Vec<u8>>) -> NewConfig {
        NewConfig::new(ConfigFormat::Json, body)
    }

    /// A `yaml` document (checked for UTF-8 only).
    pub fn yaml(body: impl Into<Vec<u8>>) -> NewConfig {
        NewConfig::new(ConfigFormat::Yaml, body)
    }

    /// A `text` document (checked for UTF-8 only).
    pub fn text(body: impl Into<Vec<u8>>) -> NewConfig {
        NewConfig::new(ConfigFormat::Text, body)
    }

    /// Write this one document even if it holds a credential literal.
    pub fn allow_literals(mut self) -> NewConfig {
        self.allow_literals = true;
        self
    }

    /// Succeed only if the config is still at `version`, the one the caller
    /// read. A stale edit fails with a conflict naming both versions, and is
    /// never retried.
    pub fn expect_version(mut self, version: u64) -> NewConfig {
        self.expect = Some(Expect::Version(version));
        self
    }

    /// Succeed only if the config does not exist yet (or was deleted).
    pub fn expect_absent(mut self) -> NewConfig {
        self.expect = Some(Expect::Absent);
        self
    }
}

impl std::fmt::Debug for NewConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NewConfig")
            .field("format", &self.format)
            .field("size", &self.body.len())
            .field("allow_literals", &self.allow_literals)
            .field("expect", &self.expect)
            .finish()
    }
}

/// A record's latest version, as listed. Never its value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Entry {
    /// The record's name.
    pub name: String,
    /// Its latest version.
    pub version: u64,
    /// When the latest version was written (Unix seconds, as its writer
    /// signed it).
    pub updated_at: i64,
    /// The latest version's ciphertext size in bytes.
    pub size: u32,
    /// Whether the latest version is a tombstone. Only the `_all` listings
    /// return deleted records.
    pub deleted: bool,
}

/// When things expire, as data: printing a warning is the caller's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Expiry {
    /// When the token expires; `None` for an owner-opened handle.
    pub token_expires_at: Option<i64>,
    /// The latest the server announced; `None` before any response.
    pub vault_expires_at: Option<i64>,
}
