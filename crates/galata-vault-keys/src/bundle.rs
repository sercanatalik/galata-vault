//! Sealed bundles: key material sealed to one holder's X25519
//! key with a libsodium-compatible sealed box, and signed by the owner.
//!
//! ```text
//! plaintext = version(1) = 2 ‖ kind(1) ‖ vault_id(16) ‖ token_id(16) ‖ generation(4) ‖ body
//!   kind 1 names         name_key                                                        meta
//!   kind 2 append        name_key ‖ secret_writer ‖ config_writer                        append
//!   kind 3 config        name_key ‖ config_sk                                            config
//!   kind 4 config-write  name_key ‖ config_sk ‖ config_writer                            config-write
//!   kind 5 read          name_key ‖ vault_sk ‖ config_sk                                 read
//!   kind 6 full          name_key ‖ vault_sk ‖ config_sk ‖ secret_writer ‖ config_writer owner, admin
//!   kind 7 child         node_key                                    a sealed children entry
//! signature = Ed25519(owner_sign, frame("gv/v1/bundle",
//!                 vault_id ‖ token_id ‖ scope ‖ generation ‖ SHA-256(sealed)))
//! ```
//!
//! Each kind has one exact length, and every generation has all five
//! keys. The bundle *types* are distinct: [`ConfigBundle`] and
//! [`ConfigWriteBundle`] have no field for the vault key or the secret writer,
//! so a config token cannot be handed one. [`seal_for_scope`] is the only
//! minting path, and it picks the kind from the scope. The holder checks the
//! owner's signature, then that the plaintext names its vault, token and
//! generation. v1 kinds are refused.

use crypto_box::aead::OsRng;
use galata_vault_proto::api::{
    BUNDLE_VERSION, OWNER_SCOPE_CODE, OWNER_TOKEN_ID, Scope, SignedBundle,
};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{B64, Hash32, Key32, TokenId, VaultId};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::name_key::NameKey;
use crate::node::NodeKey;
use crate::owner::OwnerKeys;
use crate::random::random_bytes;
use crate::writer::WriterKey;

const VERSION: u8 = BUNDLE_VERSION;
const KIND_NAMES: u8 = 1;
const KIND_APPEND: u8 = 2;
const KIND_CONFIG: u8 = 3;
const KIND_CONFIG_WRITE: u8 = 4;
const KIND_READ: u8 = 5;
const KIND_FULL: u8 = 6;
const KIND_CHILD: u8 = 7;
/// version, kind, vault id, token id, generation.
const HEADER_LEN: usize = 1 + 1 + 16 + 16 + 4;

/// The raw X25519 secret that opens a generation's secrets. Only `galata-vault-seal`
/// turns it into something that can decrypt.
#[derive(Clone)]
pub struct VaultSecret(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("VaultSecret(<redacted>)")
    }
}

impl VaultSecret {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> VaultSecret {
        VaultSecret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The X25519 public key (the same value age computes).
    pub fn public(&self) -> Key32 {
        x25519_public(&self.0)
    }
}

/// The raw X25519 secret that opens a generation's configs. A distinct type
/// from [`VaultSecret`], so a config bundle cannot be given a vault secret.
#[derive(Clone)]
pub struct ConfigSecret(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for ConfigSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ConfigSecret(<redacted>)")
    }
}

impl ConfigSecret {
    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> ConfigSecret {
        ConfigSecret(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The X25519 public key (the same value age computes).
    pub fn public(&self) -> Key32 {
        x25519_public(&self.0)
    }
}

fn x25519_public(secret: &[u8; 32]) -> Key32 {
    Key32(
        *crypto_box::SecretKey::from_bytes(*secret)
            .public_key()
            .as_bytes(),
    )
}

/// What `meta` tokens hold.
#[derive(Debug, Clone)]
pub struct NamesBundle {
    pub generation: u32,
    pub name_key: NameKey,
}

/// What `append` tokens hold: both writer keys, and no key that decrypts.
#[derive(Debug, Clone)]
pub struct AppendBundle {
    pub generation: u32,
    pub name_key: NameKey,
    pub secret_writer: WriterKey,
    pub config_writer: WriterKey,
}

/// What `config` tokens hold: no field for the vault key or a writer.
#[derive(Debug, Clone)]
pub struct ConfigBundle {
    pub generation: u32,
    pub name_key: NameKey,
    pub config_secret: ConfigSecret,
}

/// What `config-write` tokens hold: no field for the vault key or the
/// secret writer, so a config-write token cannot read or write a secret.
#[derive(Debug, Clone)]
pub struct ConfigWriteBundle {
    pub generation: u32,
    pub name_key: NameKey,
    pub config_secret: ConfigSecret,
    pub config_writer: WriterKey,
}

/// What `read` tokens hold: both decryption keys, and no writer.
#[derive(Debug, Clone)]
pub struct ReadBundle {
    pub generation: u32,
    pub name_key: NameKey,
    pub vault_secret: VaultSecret,
    pub config_secret: ConfigSecret,
}

/// Every key of a generation: what the owner and `admin` tokens hold.
#[derive(Debug, Clone)]
pub struct FullBundle {
    pub generation: u32,
    pub name_key: NameKey,
    pub vault_secret: VaultSecret,
    pub config_secret: ConfigSecret,
    pub secret_writer: WriterKey,
    pub config_writer: WriterKey,
}

impl FullBundle {
    /// A new generation: every key fresh.
    pub fn generate(generation: u32) -> FullBundle {
        FullBundle {
            generation,
            name_key: NameKey::generate(),
            vault_secret: random_vault_secret(),
            config_secret: random_config_secret(),
            secret_writer: WriterKey::generate(),
            config_writer: WriterKey::generate(),
        }
    }

    /// This generation's descriptor, for the owner to sign.
    pub fn descriptor(&self, vault_id: VaultId, prev_hash: Hash32, created_at: i64) -> Descriptor {
        Descriptor {
            vault_id,
            generation: self.generation,
            vault_pub: self.vault_secret.public(),
            config_pub: self.config_secret.public(),
            secret_writer_pub: self.secret_writer.public(),
            config_writer_pub: self.config_writer.public(),
            prev_hash,
            created_at,
        }
    }

    /// Whether every key here is the one `descriptor` names.
    pub fn matches(&self, descriptor: &Descriptor) -> bool {
        self.generation == descriptor.generation
            && self.vault_secret.public() == descriptor.vault_pub
            && self.config_secret.public() == descriptor.config_pub
            && self.secret_writer.public() == descriptor.secret_writer_pub
            && self.config_writer.public() == descriptor.config_writer_pub
    }

    /// What a token of `scope` receives, and nothing more. A scope this
    /// build gives no bundle kind is refused.
    pub fn for_scope(&self, scope: Scope) -> Result<Bundle, KeyError> {
        let (generation, name_key) = (self.generation, self.name_key.clone());
        Ok(match scope {
            Scope::Meta => Bundle::Names(NamesBundle {
                generation,
                name_key,
            }),
            Scope::Append => Bundle::Append(AppendBundle {
                generation,
                name_key,
                secret_writer: self.secret_writer.clone(),
                config_writer: self.config_writer.clone(),
            }),
            Scope::Config => Bundle::Config(ConfigBundle {
                generation,
                name_key,
                config_secret: self.config_secret.clone(),
            }),
            Scope::ConfigWrite => Bundle::ConfigWrite(ConfigWriteBundle {
                generation,
                name_key,
                config_secret: self.config_secret.clone(),
                config_writer: self.config_writer.clone(),
            }),
            Scope::Read => Bundle::Read(ReadBundle {
                generation,
                name_key,
                vault_secret: self.vault_secret.clone(),
                config_secret: self.config_secret.clone(),
            }),
            Scope::Admin => Bundle::Full(self.clone()),
            other => return Err(KeyError::UnsupportedScope(other.to_string())),
        })
    }
}

#[derive(Debug, Clone)]
pub enum Bundle {
    Names(NamesBundle),
    Append(AppendBundle),
    Config(ConfigBundle),
    ConfigWrite(ConfigWriteBundle),
    Read(ReadBundle),
    Full(FullBundle),
}

impl Bundle {
    pub fn generation(&self) -> u32 {
        match self {
            Bundle::Names(b) => b.generation,
            Bundle::Append(b) => b.generation,
            Bundle::Config(b) => b.generation,
            Bundle::ConfigWrite(b) => b.generation,
            Bundle::Read(b) => b.generation,
            Bundle::Full(b) => b.generation,
        }
    }

    pub fn name_key(&self) -> &NameKey {
        match self {
            Bundle::Names(b) => &b.name_key,
            Bundle::Append(b) => &b.name_key,
            Bundle::Config(b) => &b.name_key,
            Bundle::ConfigWrite(b) => &b.name_key,
            Bundle::Read(b) => &b.name_key,
            Bundle::Full(b) => &b.name_key,
        }
    }

    pub fn vault_secret(&self) -> Option<&VaultSecret> {
        match self {
            Bundle::Read(b) => Some(&b.vault_secret),
            Bundle::Full(b) => Some(&b.vault_secret),
            _ => None,
        }
    }

    pub fn config_secret(&self) -> Option<&ConfigSecret> {
        match self {
            Bundle::Config(b) => Some(&b.config_secret),
            Bundle::ConfigWrite(b) => Some(&b.config_secret),
            Bundle::Read(b) => Some(&b.config_secret),
            Bundle::Full(b) => Some(&b.config_secret),
            _ => None,
        }
    }

    pub fn secret_writer(&self) -> Option<&WriterKey> {
        match self {
            Bundle::Append(b) => Some(&b.secret_writer),
            Bundle::Full(b) => Some(&b.secret_writer),
            _ => None,
        }
    }

    pub fn config_writer(&self) -> Option<&WriterKey> {
        match self {
            Bundle::Append(b) => Some(&b.config_writer),
            Bundle::ConfigWrite(b) => Some(&b.config_writer),
            Bundle::Full(b) => Some(&b.config_writer),
            _ => None,
        }
    }

    pub fn holds_vault_secret(&self) -> bool {
        self.vault_secret().is_some()
    }

    /// Whether every key this bundle holds is the one `descriptor` names.
    pub fn matches(&self, descriptor: &Descriptor) -> bool {
        self.generation() == descriptor.generation
            && self
                .vault_secret()
                .is_none_or(|k| k.public() == descriptor.vault_pub)
            && self
                .config_secret()
                .is_none_or(|k| k.public() == descriptor.config_pub)
            && self
                .secret_writer()
                .is_none_or(|k| k.public() == descriptor.secret_writer_pub)
            && self
                .config_writer()
                .is_none_or(|k| k.public() == descriptor.config_writer_pub)
    }

    fn kind(&self) -> u8 {
        match self {
            Bundle::Names(_) => KIND_NAMES,
            Bundle::Append(_) => KIND_APPEND,
            Bundle::Config(_) => KIND_CONFIG,
            Bundle::ConfigWrite(_) => KIND_CONFIG_WRITE,
            Bundle::Read(_) => KIND_READ,
            Bundle::Full(_) => KIND_FULL,
        }
    }

    pub(crate) fn kind_name(&self) -> &'static str {
        kind_name(self.kind())
    }

    pub fn into_full(self) -> Result<FullBundle, KeyError> {
        match self {
            Bundle::Full(b) => Ok(b),
            other => Err(KeyError::Kind {
                expected: "full",
                found: other.kind_name(),
            }),
        }
    }

    /// For `gv-mcp`: refuse anything that carries more than the name key.
    pub fn into_names_only(self) -> Result<NamesBundle, KeyError> {
        match self {
            Bundle::Names(b) => Ok(b),
            other => Err(KeyError::Kind {
                expected: "names",
                found: other.kind_name(),
            }),
        }
    }
}

fn kind_name(kind: u8) -> &'static str {
    match kind {
        KIND_NAMES => "names",
        KIND_APPEND => "append",
        KIND_CONFIG => "config",
        KIND_CONFIG_WRITE => "config-write",
        KIND_READ => "read",
        KIND_FULL => "full",
        KIND_CHILD => "child",
        _ => "unknown",
    }
}

fn scope_kind(scope: Scope) -> Option<u8> {
    Some(match scope {
        Scope::Meta => KIND_NAMES,
        Scope::Append => KIND_APPEND,
        Scope::Config => KIND_CONFIG,
        Scope::ConfigWrite => KIND_CONFIG_WRITE,
        Scope::Read => KIND_READ,
        Scope::Admin => KIND_FULL,
        _ => return None,
    })
}

pub(crate) fn seal_bytes(to: &Key32, plaintext: &[u8]) -> Result<Vec<u8>, KeyError> {
    crypto_box::PublicKey::from_bytes(to.0)
        .seal(&mut OsRng, plaintext)
        .map_err(|_| KeyError::Encrypt("a sealed box"))
}

fn plaintext(
    kind: u8,
    vault_id: &VaultId,
    token_id: &TokenId,
    generation: u32,
    keys: &[&[u8; 32]],
) -> Zeroizing<Vec<u8>> {
    let mut p = Zeroizing::new(Vec::with_capacity(HEADER_LEN + 32 * keys.len()));
    p.extend_from_slice(&[VERSION, kind]);
    p.extend_from_slice(&vault_id.0);
    p.extend_from_slice(&token_id.0);
    p.extend_from_slice(&generation.to_be_bytes());
    for key in keys {
        p.extend_from_slice(key.as_slice());
    }
    p
}

fn encode(bundle: &Bundle, vault_id: &VaultId, token_id: &TokenId) -> Zeroizing<Vec<u8>> {
    let generation = bundle.generation();
    let name_key = bundle.name_key().as_bytes();
    match bundle {
        Bundle::Names(_) => plaintext(KIND_NAMES, vault_id, token_id, generation, &[name_key]),
        Bundle::Append(b) => plaintext(
            KIND_APPEND,
            vault_id,
            token_id,
            generation,
            &[
                name_key,
                &b.secret_writer.to_bytes(),
                &b.config_writer.to_bytes(),
            ],
        ),
        Bundle::Config(b) => plaintext(
            KIND_CONFIG,
            vault_id,
            token_id,
            generation,
            &[name_key, b.config_secret.as_bytes()],
        ),
        Bundle::ConfigWrite(b) => plaintext(
            KIND_CONFIG_WRITE,
            vault_id,
            token_id,
            generation,
            &[
                name_key,
                b.config_secret.as_bytes(),
                &b.config_writer.to_bytes(),
            ],
        ),
        Bundle::Read(b) => plaintext(
            KIND_READ,
            vault_id,
            token_id,
            generation,
            &[
                name_key,
                b.vault_secret.as_bytes(),
                b.config_secret.as_bytes(),
            ],
        ),
        Bundle::Full(b) => plaintext(
            KIND_FULL,
            vault_id,
            token_id,
            generation,
            &[
                name_key,
                b.vault_secret.as_bytes(),
                b.config_secret.as_bytes(),
                &b.secret_writer.to_bytes(),
                &b.config_writer.to_bytes(),
            ],
        ),
    }
}

/// The one way to mint a token's bundle: the scope decides the kind, and the
/// owner signs the binding. A scope this build gives no bundle kind is
/// refused, and nothing is sealed.
pub fn seal_for_scope(
    owner: &OwnerKeys,
    holder_box_pub: &Key32,
    token_id: &TokenId,
    scope: Scope,
    full: &FullBundle,
) -> Result<SignedBundle, KeyError> {
    let bundle = full.for_scope(scope)?;
    let sealed = seal_bytes(
        holder_box_pub,
        &encode(&bundle, &owner.vault_id(), token_id),
    )?;
    let sig = owner.sign_bundle(token_id, scope.code(), full.generation, &sealed);
    Ok(SignedBundle::new(B64(sealed), sig))
}

/// The owner's own bundle: every key, sealed to the owner box key.
pub fn seal_owner_bundle(owner: &OwnerKeys, full: &FullBundle) -> Result<SignedBundle, KeyError> {
    let bundle = Bundle::Full(full.clone());
    let sealed = seal_bytes(
        &owner.box_pub(),
        &encode(&bundle, &owner.vault_id(), &OWNER_TOKEN_ID),
    )?;
    let sig = owner.sign_bundle(&OWNER_TOKEN_ID, OWNER_SCOPE_CODE, full.generation, &sealed);
    Ok(SignedBundle::new(B64(sealed), sig))
}

/// Seal a re-rooted child's random key to its parent's owner box key. It
/// travels inside the owner-signed children record.
pub fn seal_child_key(
    parent_box_pub: &Key32,
    parent_vault: &VaultId,
    key: &NodeKey,
) -> Result<Vec<u8>, KeyError> {
    seal_bytes(
        parent_box_pub,
        &plaintext(
            KIND_CHILD,
            parent_vault,
            &OWNER_TOKEN_ID,
            0,
            &[key.as_bytes()],
        ),
    )
}

/// What a bundle's plaintext must name.
pub(crate) struct Binding {
    pub vault_id: VaultId,
    pub token_id: TokenId,
    pub generation: u32,
}

/// Open the seal, then check the version byte (first, so an unknown version
/// is refused as one whatever its length) and that a whole header is there.
pub(crate) fn unseal(
    sk: &crypto_box::SecretKey,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let plain = Zeroizing::new(sk.unseal(sealed).map_err(|_| KeyError::Unseal)?);
    match plain.first() {
        None => return Err(KeyError::Truncated),
        Some(&VERSION) => {}
        Some(&v) => return Err(KeyError::UnknownVersion(v)),
    }
    if plain.len() < HEADER_LEN {
        return Err(KeyError::Truncated);
    }
    Ok(plain)
}

fn key32(bytes: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(bytes);
    k
}

fn check_binding(p: &[u8], binding: &Binding) -> Result<(), KeyError> {
    if p[2..18] != binding.vault_id.0 {
        return Err(KeyError::Binding("vault id"));
    }
    if p[18..34] != binding.token_id.0 {
        return Err(KeyError::Binding("token id"));
    }
    if p[34..38] != binding.generation.to_be_bytes() {
        return Err(KeyError::Binding("generation"));
    }
    Ok(())
}

pub(crate) fn open_bundle(
    sk: &crypto_box::SecretKey,
    sealed: &[u8],
    binding: &Binding,
) -> Result<Bundle, KeyError> {
    let p = unseal(sk, sealed)?;
    if p[1] == KIND_CHILD {
        return Err(KeyError::Kind {
            expected: "a token or owner bundle",
            found: "child",
        });
    }
    check_binding(&p, binding)?;
    let generation = binding.generation;
    let k = |i: usize| key32(&p[HEADER_LEN + 32 * i..HEADER_LEN + 32 * (i + 1)]);
    let name_key = || NameKey::from_bytes(k(0));
    let writer = |i: usize| WriterKey::from_bytes(&k(i));
    let body = p.len() - HEADER_LEN;
    let bundle = match (p[1], body) {
        (KIND_NAMES, 32) => Bundle::Names(NamesBundle {
            generation,
            name_key: name_key(),
        }),
        (KIND_APPEND, 96) => Bundle::Append(AppendBundle {
            generation,
            name_key: name_key(),
            secret_writer: writer(1),
            config_writer: writer(2),
        }),
        (KIND_CONFIG, 64) => Bundle::Config(ConfigBundle {
            generation,
            name_key: name_key(),
            config_secret: ConfigSecret::from_bytes(k(1)),
        }),
        (KIND_CONFIG_WRITE, 96) => Bundle::ConfigWrite(ConfigWriteBundle {
            generation,
            name_key: name_key(),
            config_secret: ConfigSecret::from_bytes(k(1)),
            config_writer: writer(2),
        }),
        (KIND_READ, 96) => Bundle::Read(ReadBundle {
            generation,
            name_key: name_key(),
            vault_secret: VaultSecret::from_bytes(k(1)),
            config_secret: ConfigSecret::from_bytes(k(2)),
        }),
        (KIND_FULL, 160) => Bundle::Full(FullBundle {
            generation,
            name_key: name_key(),
            vault_secret: VaultSecret::from_bytes(k(1)),
            config_secret: ConfigSecret::from_bytes(k(2)),
            secret_writer: writer(3),
            config_writer: writer(4),
        }),
        (KIND_NAMES..=KIND_FULL, len) => {
            return Err(KeyError::BadLength {
                kind: kind_name(p[1]),
                len,
            });
        }
        (kind, _) => return Err(KeyError::UnknownKind(kind)),
    };
    Ok(bundle)
}

/// The kind a scope's bundle must be.
pub(crate) fn expect_scope(bundle: &Bundle, scope: Scope) -> Result<(), KeyError> {
    let expected =
        scope_kind(scope).ok_or_else(|| KeyError::UnsupportedScope(scope.to_string()))?;
    if bundle.kind() != expected {
        return Err(KeyError::Kind {
            expected: kind_name(expected),
            found: bundle.kind_name(),
        });
    }
    Ok(())
}

pub(crate) fn open_child_key(
    sk: &crypto_box::SecretKey,
    sealed: &[u8],
    parent_vault: &VaultId,
) -> Result<NodeKey, KeyError> {
    let p = unseal(sk, sealed)?;
    if p[1] != KIND_CHILD {
        return Err(KeyError::Kind {
            expected: "child",
            found: kind_name(p[1]),
        });
    }
    check_binding(
        &p,
        &Binding {
            vault_id: *parent_vault,
            token_id: OWNER_TOKEN_ID,
            generation: 0,
        },
    )?;
    if p.len() != HEADER_LEN + 32 {
        return Err(KeyError::BadLength {
            kind: "child",
            len: p.len() - HEADER_LEN,
        });
    }
    Ok(NodeKey::from_bytes(key32(&p[HEADER_LEN..])))
}

/// A fresh random vault secret.
pub fn random_vault_secret() -> VaultSecret {
    VaultSecret::from_bytes(random_bytes::<32>())
}

/// A fresh random config secret.
pub fn random_config_secret() -> ConfigSecret {
    ConfigSecret::from_bytes(random_bytes::<32>())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::token::TokenKeys;

    fn setup() -> (OwnerKeys, FullBundle, Descriptor) {
        let owner = NodeKey::generate().owner();
        let full = FullBundle::generate(3);
        let d = full.descriptor(owner.vault_id(), Hash32([1; 32]), 0);
        (owner, full, d)
    }

    #[test]
    fn the_owner_opens_its_own_bundle() {
        let (owner, full, d) = setup();
        let signed = seal_owner_bundle(&owner, &full).unwrap();
        let back = owner.open_own_bundle(&signed, 3).unwrap();
        assert!(back.matches(&d));
        assert_eq!(back.name_key.hmac("X"), full.name_key.hmac("X"));
        // The wrong generation fails the signature before anything opens.
        assert!(owner.open_own_bundle(&signed, 4).is_err());
    }

    #[test]
    fn scope_decides_exactly_what_a_token_holds() {
        let (owner, full, d) = setup();
        for scope in Scope::ALL {
            let token = TokenKeys::generate(owner.vault_id());
            let signed =
                seal_for_scope(&owner, &token.box_pub(), &token.id(), scope, &full).unwrap();
            let opened = token
                .open_bundle(&signed, &owner.sign_pub(), scope, 3)
                .unwrap();
            assert!(opened.matches(&d), "{scope}");
            assert_eq!(
                opened.holds_vault_secret(),
                scope.bundle_holds_vault_key(),
                "{scope}"
            );
            assert_eq!(
                opened.secret_writer().is_some(),
                scope.bundle_holds_secret_writer(),
                "{scope}"
            );
            assert_eq!(
                opened.config_writer().is_some(),
                scope.bundle_holds_config_writer(),
                "{scope}"
            );
            assert_eq!(opened.name_key().hmac("A"), full.name_key.hmac("A"));
        }
    }

    #[test]
    fn a_bundle_does_not_move_between_tokens_scopes_or_owners() {
        let (owner, full, _) = setup();
        let a = TokenKeys::generate(owner.vault_id());
        let b = TokenKeys::generate(owner.vault_id());
        let signed = seal_for_scope(&owner, &a.box_pub(), &a.id(), Scope::Read, &full).unwrap();
        // Another token cannot open it, and the signature names token a.
        assert!(
            b.open_bundle(&signed, &owner.sign_pub(), Scope::Read, 3)
                .is_err()
        );
        // Claimed as a different scope, the signature fails.
        assert!(
            a.open_bundle(&signed, &owner.sign_pub(), Scope::Admin, 3)
                .is_err()
        );
        // A bundle signed by some other owner fails against the pinned vault.
        let impostor = NodeKey::generate().owner();
        let forged = seal_for_scope(&impostor, &a.box_pub(), &a.id(), Scope::Read, &full).unwrap();
        assert!(
            a.open_bundle(&forged, &impostor.sign_pub(), Scope::Read, 3)
                .is_err()
        );
        assert!(
            a.open_bundle(&forged, &owner.sign_pub(), Scope::Read, 3)
                .is_err()
        );
    }

    #[test]
    fn a_config_write_bundle_holds_no_secret_key_or_writer() {
        let (owner, full, _) = setup();
        let token = TokenKeys::generate(owner.vault_id());
        let signed = seal_for_scope(
            &owner,
            &token.box_pub(),
            &token.id(),
            Scope::ConfigWrite,
            &full,
        )
        .unwrap();
        let opened = token
            .open_bundle(&signed, &owner.sign_pub(), Scope::ConfigWrite, 3)
            .unwrap();
        assert!(opened.vault_secret().is_none());
        assert!(opened.secret_writer().is_none());
        assert!(opened.config_writer().is_some());
        assert!(matches!(opened.into_full(), Err(KeyError::Kind { .. })));
    }

    #[test]
    fn tampering_and_wrong_recipients_fail() {
        let (owner, full, _) = setup();
        let a = TokenKeys::generate(owner.vault_id());
        let mut signed = seal_for_scope(&owner, &a.box_pub(), &a.id(), Scope::Meta, &full).unwrap();
        signed.sealed.0[40] ^= 1;
        assert!(
            a.open_bundle(&signed, &owner.sign_pub(), Scope::Meta, 3)
                .is_err()
        );
    }

    #[test]
    fn child_keys_roundtrip_and_are_bound_to_the_parent() {
        let parent = NodeKey::generate().owner();
        let child = NodeKey::generate();
        let sealed = seal_child_key(&parent.box_pub(), &parent.vault_id(), &child).unwrap();
        assert_eq!(
            parent.open_child_key(&sealed).unwrap().as_bytes(),
            child.as_bytes()
        );
        // Sealed for another vault: the binding fails.
        let elsewhere = seal_child_key(&parent.box_pub(), &VaultId([9; 16]), &child).unwrap();
        assert!(parent.open_child_key(&elsewhere).is_err());
        // A bundle is not a child key.
        let bundle = seal_owner_bundle(&parent, &FullBundle::generate(1)).unwrap();
        assert!(matches!(
            parent.open_child_key(&bundle.sealed.0),
            Err(KeyError::Kind { .. })
        ));
    }
}
