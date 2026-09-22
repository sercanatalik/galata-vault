//! Secret values and config documents: an envelope (v3), sealed with age.
//!
//! ```text
//! secret envelope = 3 ‖ kind(1) = 1 ‖ vault_id(16) ‖ generation(4) ‖ version(8)
//!                   ‖ written_at(8) ‖ name_len(2) ‖ name ‖ value
//! config envelope = 3 ‖ kind(1) = 2 ‖ format(1) ‖ vault_id(16) ‖ generation(4)
//!                   ‖ version(8) ‖ written_at(8) ‖ name_len(2) ‖ name ‖ body
//! value_ct        = age v1, one X25519 recipient: the descriptor's vault_pub
//!                   for a secret, config_pub for a config
//! ```
//!
//! The plaintext binds the same context the record signature binds (design
//! D5). A reader that decrypts checks the kind, vault, generation, version,
//! write time and name against what the signature and the server reported,
//! so a ciphertext cannot be moved between vaults, generations, versions,
//! names or kinds.
//!
//! The envelope is binary rather than JSON so the plaintext exists in one
//! zeroized buffer, not in a serializer's intermediate copies.

use crate::keys::{ConfigSecret, VaultSecret};
use crate::proto::api::AGE_HEADER;
use crate::proto::ids::{Key32, VaultId};
use crate::proto::record::{ENVELOPE_VERSION, RecordKind};
use zeroize::Zeroizing;

use crate::seal::SealError;
use crate::seal::keys::{config_identity, identity, recipient};

const VERSION: u8 = ENVELOPE_VERSION;
/// version, kind, vault id, generation, version, written_at, name_len.
const HEADER_LEN: usize = 1 + 1 + 16 + 4 + 8 + 8 + 2;
pub const MAX_NAME_LEN: usize = 256;

/// Why an envelope's plaintext does not decode (`docs/spec/records.md#3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnvelopeFault {
    /// A version byte this build does not know.
    UnknownVersion(u8),
    /// A record kind this build does not know.
    UnknownKind(u8),
    /// A config format this build does not know.
    UnknownFormat(u8),
    /// Shorter than its fixed fields and name.
    Truncated,
    /// A name longer than [`MAX_NAME_LEN`].
    NameTooLong(usize),
    /// A name that is not UTF-8.
    NameNotUtf8,
}

impl std::fmt::Display for EnvelopeFault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeFault::UnknownVersion(v) => {
                write!(f, "version {v} is not one this client knows")
            }
            EnvelopeFault::UnknownKind(k) => {
                write!(f, "record kind {k} is not one this client knows")
            }
            EnvelopeFault::UnknownFormat(c) => {
                write!(f, "config format {c} is not one this client knows")
            }
            EnvelopeFault::Truncated => f.write_str("it is truncated"),
            EnvelopeFault::NameTooLong(n) => write!(f, "its name is {n} bytes long"),
            EnvelopeFault::NameNotUtf8 => f.write_str("its name is not UTF-8"),
        }
    }
}

impl From<EnvelopeFault> for SealError {
    fn from(f: EnvelopeFault) -> SealError {
        SealError::Envelope(f)
    }
}

/// What an envelope binds besides its kind and name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EnvelopeContext {
    pub vault_id: VaultId,
    pub generation: u32,
    pub version: u64,
    pub written_at: i64,
}

/// A decrypted value. `Debug` never prints the value.
pub struct Opened {
    pub name: String,
    pub value: Zeroizing<Vec<u8>>,
    pub written_at: i64,
}

impl std::fmt::Debug for Opened {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Opened")
            .field("name", &self.name)
            .field("value", &format_args!("<{} bytes>", self.value.len()))
            .field("written_at", &self.written_at)
            .finish()
    }
}

/// A config's declared format. It is fixed per write and travels inside the
/// ciphertext, so the server never learns it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigFormat {
    Toml,
    Json,
    Yaml,
    Text,
}

impl ConfigFormat {
    pub const ALL: [ConfigFormat; 4] = [
        ConfigFormat::Toml,
        ConfigFormat::Json,
        ConfigFormat::Yaml,
        ConfigFormat::Text,
    ];

    fn code(self) -> u8 {
        match self {
            ConfigFormat::Toml => 1,
            ConfigFormat::Json => 2,
            ConfigFormat::Yaml => 3,
            ConfigFormat::Text => 4,
        }
    }

    fn from_code(code: u8) -> Option<ConfigFormat> {
        ConfigFormat::ALL.into_iter().find(|f| f.code() == code)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ConfigFormat::Toml => "toml",
            ConfigFormat::Json => "json",
            ConfigFormat::Yaml => "yaml",
            ConfigFormat::Text => "text",
        }
    }

    /// The inverse of [`ConfigFormat::as_str`].
    pub fn parse(s: &str) -> Option<ConfigFormat> {
        ConfigFormat::ALL.into_iter().find(|f| f.as_str() == s)
    }
}

impl std::fmt::Display for ConfigFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A decrypted config document. `Debug` never prints the body.
pub struct OpenedConfig {
    pub name: String,
    pub format: ConfigFormat,
    pub body: Zeroizing<Vec<u8>>,
    pub written_at: i64,
}

impl std::fmt::Debug for OpenedConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenedConfig")
            .field("name", &self.name)
            .field("format", &self.format)
            .field("body", &format_args!("<{} bytes>", self.body.len()))
            .field("written_at", &self.written_at)
            .finish()
    }
}

/// A decoded envelope, before its bindings are checked.
pub(crate) struct Decoded {
    pub kind: RecordKind,
    pub format: Option<ConfigFormat>,
    pub ctx: EnvelopeContext,
    pub name: String,
    pub body: Zeroizing<Vec<u8>>,
}

pub(crate) fn encode_envelope(
    kind: RecordKind,
    format: Option<ConfigFormat>,
    ctx: &EnvelopeContext,
    name: &str,
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SealError> {
    if name.len() > MAX_NAME_LEN {
        return Err(SealError::NameTooLong);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(HEADER_LEN + 1 + name.len() + body.len()));
    out.push(VERSION);
    out.push(kind.code());
    if let Some(f) = format {
        out.push(f.code());
    }
    out.extend_from_slice(&ctx.vault_id.0);
    out.extend_from_slice(&ctx.generation.to_be_bytes());
    out.extend_from_slice(&ctx.version.to_be_bytes());
    out.extend_from_slice(&ctx.written_at.to_be_bytes());
    out.extend_from_slice(&(name.len() as u16).to_be_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// The `N` bytes at `at`, or `Truncated`. (The caller checks the length
/// first; this only names the field without a panicking conversion.)
fn field<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], SealError> {
    bytes
        .get(at..)
        .and_then(|rest| rest.first_chunk::<N>())
        .copied()
        .ok_or_else(|| EnvelopeFault::Truncated.into())
}

/// Decode an envelope's plaintext. The version byte is checked first, so a
/// version this build does not know is refused as such, whatever follows.
pub(crate) fn decode_envelope(bytes: &[u8]) -> Result<Decoded, SealError> {
    let version = *bytes.first().ok_or(EnvelopeFault::Truncated)?;
    if version != VERSION {
        return Err(EnvelopeFault::UnknownVersion(version).into());
    }
    let kind_code = *bytes.get(1).ok_or(EnvelopeFault::Truncated)?;
    let kind = RecordKind::from_code(kind_code).ok_or(EnvelopeFault::UnknownKind(kind_code))?;
    let (format, rest) = match kind {
        RecordKind::Secret => (None, &bytes[2..]),
        RecordKind::Config => {
            let code = *bytes.get(2).ok_or(EnvelopeFault::Truncated)?;
            (
                Some(ConfigFormat::from_code(code).ok_or(EnvelopeFault::UnknownFormat(code))?),
                &bytes[3..],
            )
        }
    };
    let fixed = HEADER_LEN - 2;
    if rest.len() < fixed {
        return Err(EnvelopeFault::Truncated.into());
    }
    let ctx = EnvelopeContext {
        vault_id: VaultId(field(rest, 0)?),
        generation: u32::from_be_bytes(field(rest, 16)?),
        version: u64::from_be_bytes(field(rest, 20)?),
        written_at: i64::from_be_bytes(field(rest, 28)?),
    };
    let name_len = usize::from(u16::from_be_bytes(field(rest, 36)?));
    if name_len > MAX_NAME_LEN {
        return Err(EnvelopeFault::NameTooLong(name_len).into());
    }
    if rest.len() < fixed + name_len {
        return Err(EnvelopeFault::Truncated.into());
    }
    let name = std::str::from_utf8(&rest[fixed..fixed + name_len])
        .map_err(|_| EnvelopeFault::NameNotUtf8)?
        .to_owned();
    Ok(Decoded {
        kind,
        format,
        ctx,
        name,
        body: Zeroizing::new(rest[fixed + name_len..].to_vec()),
    })
}

/// Check every binding of a decoded envelope.
fn check(
    decoded: &Decoded,
    kind: RecordKind,
    ctx: &EnvelopeContext,
    name: &str,
) -> Result<(), SealError> {
    if decoded.kind != kind {
        return Err(SealError::KindMismatch {
            expected: kind.as_str(),
            found: decoded.kind.as_str(),
        });
    }
    if decoded.ctx.vault_id != ctx.vault_id {
        return Err(SealError::Binding("vault id"));
    }
    if decoded.ctx.generation != ctx.generation {
        return Err(SealError::Binding("generation"));
    }
    if decoded.ctx.version != ctx.version {
        return Err(SealError::Binding("version"));
    }
    if decoded.ctx.written_at != ctx.written_at {
        return Err(SealError::Binding("write time"));
    }
    if decoded.name != name {
        return Err(SealError::NameMismatch);
    }
    Ok(())
}

fn decrypt(identity: &age::x25519::Identity, value_ct: &[u8]) -> Result<Decoded, SealError> {
    if !value_ct.starts_with(AGE_HEADER) {
        return Err(SealError::NotAge);
    }
    let plain = Zeroizing::new(age::decrypt(identity, value_ct).map_err(|_| SealError::Decrypt)?);
    decode_envelope(&plain)
}

/// Encrypt a secret value to a descriptor's `vault_pub`.
pub fn seal_value(
    vault_pub: &Key32,
    ctx: &EnvelopeContext,
    name: &str,
    value: &[u8],
) -> Result<Vec<u8>, SealError> {
    let envelope = encode_envelope(RecordKind::Secret, None, ctx, name, value)?;
    age::encrypt(&recipient(vault_pub)?, &envelope).map_err(|e| SealError::Encrypt(e.to_string()))
}

/// Decrypt a secret value and check every binding against `ctx` and `name`.
pub fn open_value(
    secret: &VaultSecret,
    ctx: &EnvelopeContext,
    name: &str,
    value_ct: &[u8],
) -> Result<Opened, SealError> {
    let decoded = decrypt(&identity(secret)?, value_ct)?;
    check(&decoded, RecordKind::Secret, ctx, name)?;
    Ok(Opened {
        name: decoded.name,
        value: decoded.body,
        written_at: decoded.ctx.written_at,
    })
}

/// Encrypt a config document to a descriptor's `config_pub`. The body is
/// stored exactly as given.
pub fn seal_config(
    config_pub: &Key32,
    ctx: &EnvelopeContext,
    name: &str,
    format: ConfigFormat,
    body: &[u8],
) -> Result<Vec<u8>, SealError> {
    let envelope = encode_envelope(RecordKind::Config, Some(format), ctx, name, body)?;
    age::encrypt(&recipient(config_pub)?, &envelope).map_err(|e| SealError::Encrypt(e.to_string()))
}

/// Decrypt a config document and check every binding against `ctx` and `name`.
pub fn open_config(
    secret: &ConfigSecret,
    ctx: &EnvelopeContext,
    name: &str,
    value_ct: &[u8],
) -> Result<OpenedConfig, SealError> {
    let decoded = decrypt(&config_identity(secret)?, value_ct)?;
    check(&decoded, RecordKind::Config, ctx, name)?;
    Ok(OpenedConfig {
        name: decoded.name,
        format: decoded
            .format
            .ok_or(EnvelopeFault::UnknownKind(RecordKind::Config.code()))?,
        body: decoded.body,
        written_at: decoded.ctx.written_at,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::{new_config_keypair, new_vault_keypair};

    fn ctx() -> EnvelopeContext {
        EnvelopeContext {
            vault_id: VaultId([1; 16]),
            generation: 2,
            version: 3,
            written_at: 42,
        }
    }

    #[test]
    fn configs_roundtrip_byte_for_byte_in_every_format() {
        let (secret, public) = new_config_keypair().unwrap();
        let body = b"[a]\r\nb = 1  \r\n# no final newline".to_vec();
        for format in ConfigFormat::ALL {
            let ct = seal_config(&public, &ctx(), "app", format, &body).unwrap();
            assert!(ct.starts_with(AGE_HEADER));
            let opened = open_config(&secret, &ctx(), "app", &ct).unwrap();
            assert_eq!(opened.format, format);
            assert_eq!(*opened.body, body, "exactly the bytes written");
            assert_eq!(opened.written_at, 42);
            assert_eq!(ConfigFormat::parse(format.as_str()), Some(format));
        }
    }

    #[test]
    fn every_binding_is_checked() {
        let (secret, public) = new_vault_keypair().unwrap();
        let ct = seal_value(&public, &ctx(), "K", b"v").unwrap();
        assert_eq!(*open_value(&secret, &ctx(), "K", &ct).unwrap().value, b"v");
        let wrong = [
            EnvelopeContext {
                vault_id: VaultId([9; 16]),
                ..ctx()
            },
            EnvelopeContext {
                generation: 3,
                ..ctx()
            },
            EnvelopeContext {
                version: 4,
                ..ctx()
            },
            EnvelopeContext {
                written_at: 43,
                ..ctx()
            },
        ];
        for w in wrong {
            assert!(matches!(
                open_value(&secret, &w, "K", &ct),
                Err(SealError::Binding(_))
            ));
        }
        assert!(matches!(
            open_value(&secret, &ctx(), "L", &ct),
            Err(SealError::NameMismatch)
        ));
    }

    #[test]
    fn the_kinds_cannot_be_swapped() {
        let (vault, vault_pub) = new_vault_keypair().unwrap();
        let (config, config_pub) = new_config_keypair().unwrap();
        let config_ct =
            seal_config(&config_pub, &ctx(), "app", ConfigFormat::Toml, b"a=1").unwrap();
        assert!(matches!(
            open_value(&vault, &ctx(), "app", &config_ct),
            Err(SealError::Decrypt)
        ));
        // The kind byte catches an envelope sealed to the wrong key.
        let misplaced = seal_value(&config_pub, &ctx(), "app", b"v").unwrap();
        assert!(matches!(
            open_config(&config, &ctx(), "app", &misplaced),
            Err(SealError::KindMismatch { .. })
        ));
        let misplaced = seal_config(&vault_pub, &ctx(), "app", ConfigFormat::Text, b"v").unwrap();
        assert!(matches!(
            open_value(&vault, &ctx(), "app", &misplaced),
            Err(SealError::KindMismatch { .. })
        ));
    }

    #[test]
    fn values_roundtrip_including_binary() {
        let (secret, public) = new_vault_keypair().unwrap();
        let binary: Vec<u8> = (0..=255).collect();
        for value in [b"postgres://u:p@h/db".to_vec(), binary, Vec::new()] {
            let ct = seal_value(&public, &ctx(), "DATABASE_URL", &value).unwrap();
            let opened = open_value(&secret, &ctx(), "DATABASE_URL", &ct).unwrap();
            assert_eq!(*opened.value, value);
        }
    }

    #[test]
    fn wrong_key_tampered_and_plaintext_are_refused() {
        let (secret, public) = new_vault_keypair().unwrap();
        let ct = seal_value(&public, &ctx(), "STRIPE_KEY", b"sk_live_x").unwrap();
        let (other, _) = new_vault_keypair().unwrap();
        assert!(matches!(
            open_value(&other, &ctx(), "STRIPE_KEY", &ct),
            Err(SealError::Decrypt)
        ));
        let mut tampered = ct.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(matches!(
            open_value(&secret, &ctx(), "STRIPE_KEY", &tampered),
            Err(SealError::Decrypt)
        ));
        assert!(matches!(
            open_value(&secret, &ctx(), "STRIPE_KEY", b"sk_live_x"),
            Err(SealError::NotAge)
        ));
    }

    #[test]
    fn envelope_limits_and_debug() {
        assert!(matches!(
            encode_envelope(
                RecordKind::Secret,
                None,
                &ctx(),
                &"n".repeat(MAX_NAME_LEN + 1),
                b""
            ),
            Err(SealError::NameTooLong)
        ));
        for (bad, fault) in [
            (&[][..], EnvelopeFault::Truncated),
            (&[2, 1][..], EnvelopeFault::UnknownVersion(2)),
            (&[4][..], EnvelopeFault::UnknownVersion(4)),
            (&[1, 9, 0][..], EnvelopeFault::UnknownKind(9)),
            (&[1, 2, 9][..], EnvelopeFault::UnknownFormat(9)),
            (&[1, 1, 0, 0][..], EnvelopeFault::Truncated),
        ] {
            assert!(
                matches!(decode_envelope(bad), Err(SealError::Envelope(f)) if f == fault),
                "{bad:?}"
            );
        }
        let d = decode_envelope(
            &encode_envelope(RecordKind::Secret, None, &ctx(), "K", b"secret-value").unwrap(),
        )
        .unwrap();
        let opened = Opened {
            name: d.name,
            value: d.body,
            written_at: d.ctx.written_at,
        };
        let debug = format!("{opened:?}");
        assert!(debug.contains("<12 bytes>"));
        assert!(!debug.contains("secret-value"));
    }
}
