//! The name key: indexes record names and encrypts them for display.
//!
//! ```text
//! index_key = HKDF(name_key, salt, "gv/v1/name-index" ‖ 0)
//! index     = HMAC-SHA256(index_key, kind(1) ‖ name)          the server's index
//! enc_key   = HKDF(name_key, salt, "gv/v1/name-enc" ‖ 0)
//! name_ct   = nonce(24) ‖ XChaCha20-Poly1305(enc_key, nonce, name,
//!               aad = "gv/v1/name" ‖ 0 ‖ vault_id ‖ generation(4) ‖ kind(1))
//! ```
//!
//! The name key is never used directly as an HMAC key: both uses go through
//! HKDF (review finding M1). The AAD binds a name ciphertext to its vault,
//! generation and kind, so it cannot be moved between them.

use crate::proto::frame::{frame, label};
use crate::proto::ids::{NameHmac, VaultId};
use crate::proto::record::RecordKind;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::keys::KeyError;
use crate::keys::kdf::{derive32, info};
use crate::keys::random::random_bytes;

const NONCE_LEN: usize = 24;

/// Where a name ciphertext belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NameContext {
    pub vault_id: VaultId,
    pub generation: u32,
    pub kind: RecordKind,
}

impl NameContext {
    pub(crate) fn aad(&self) -> Vec<u8> {
        frame(
            label::NAME_AAD,
            &[
                &self.vault_id.0,
                &self.generation.to_be_bytes(),
                &[self.kind.code()],
            ],
        )
    }
}

#[derive(Clone)]
pub struct NameKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for NameKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NameKey(<redacted>)")
    }
}

impl NameKey {
    pub fn generate() -> NameKey {
        NameKey(random_bytes::<32>())
    }

    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> NameKey {
        NameKey(bytes)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// A record's index in its kind's domain.
    pub fn index(&self, kind: RecordKind, name: &str) -> NameHmac {
        let key = derive32(self.0.as_slice(), &info(label::NAME_INDEX, &[]));
        // HMAC takes a key of any length (RFC 2104 pads or hashes it), so
        // `new_from_slice` cannot fail for `Hmac`; its `Result` exists for
        // fixed-key MACs sharing the trait. The index is computed on every
        // read and write, and an impossible error on each is no better.
        #[allow(clippy::expect_used)]
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key.as_slice())
            .expect("HMAC accepts a key of any length");
        mac.update(&[kind.code()]);
        mac.update(name.as_bytes());
        let tag = mac.finalize().into_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&tag);
        NameHmac(out)
    }

    /// A secret's index.
    pub fn hmac(&self, name: &str) -> NameHmac {
        self.index(RecordKind::Secret, name)
    }

    /// A config's index: its own domain, so one name can be a secret and a
    /// config without the two indexes colliding.
    pub fn config_hmac(&self, name: &str) -> NameHmac {
        self.index(RecordKind::Config, name)
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        let key = derive32(self.0.as_slice(), &info(label::NAME_ENC, &[]));
        let key: &[u8; 32] = &key;
        XChaCha20Poly1305::new(key.into())
    }

    pub fn encrypt_name(&self, ctx: &NameContext, name: &str) -> Result<Vec<u8>, KeyError> {
        let nonce_bytes = random_bytes::<NONCE_LEN>();
        let nonce = XNonce::from(*nonce_bytes);
        let ct = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: name.as_bytes(),
                    aad: &ctx.aad(),
                },
            )
            .map_err(|_| KeyError::Encrypt("a record name"))?;
        let mut out = Vec::with_capacity(NONCE_LEN + ct.len());
        out.extend_from_slice(nonce_bytes.as_slice());
        out.extend_from_slice(&ct);
        Ok(out)
    }

    pub fn decrypt_name(&self, ctx: &NameContext, sealed: &[u8]) -> Result<String, KeyError> {
        if sealed.len() < NONCE_LEN {
            return Err(KeyError::NameDecrypt);
        }
        let (nonce, ct) = sealed.split_at(NONCE_LEN);
        let nonce = XNonce::try_from(nonce).map_err(|_| KeyError::NameDecrypt)?;
        let plain = self
            .cipher()
            .decrypt(
                &nonce,
                Payload {
                    msg: ct,
                    aad: &ctx.aad(),
                },
            )
            .map_err(|_| KeyError::NameDecrypt)?;
        String::from_utf8(plain).map_err(|_| KeyError::NameDecrypt)
    }

    /// Decrypt a name and check it against the index it was listed under, so
    /// a server that swaps two entries' ciphertexts is caught.
    pub fn open_name(
        &self,
        ctx: &NameContext,
        index: &NameHmac,
        sealed: &[u8],
    ) -> Result<String, KeyError> {
        let name = self.decrypt_name(ctx, sealed)?;
        if &self.index(ctx.kind, &name) != index {
            return Err(KeyError::NameMismatch);
        }
        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(kind: RecordKind) -> NameContext {
        NameContext {
            vault_id: VaultId([7; 16]),
            generation: 3,
            kind,
        }
    }

    #[test]
    fn index_is_deterministic_and_key_bound() {
        let k = NameKey::generate();
        assert_eq!(k.hmac("DATABASE_URL"), k.hmac("DATABASE_URL"));
        assert_ne!(k.hmac("DATABASE_URL"), k.hmac("DATABASE_URl"));
        assert_ne!(
            k.hmac("DATABASE_URL"),
            NameKey::generate().hmac("DATABASE_URL")
        );
    }

    #[test]
    fn secret_and_config_indexes_never_collide() {
        let k = NameKey::generate();
        assert_ne!(k.hmac("app"), k.config_hmac("app"));
        let sealed = k.encrypt_name(&ctx(RecordKind::Config), "app").unwrap();
        assert_eq!(
            k.open_name(&ctx(RecordKind::Config), &k.config_hmac("app"), &sealed)
                .unwrap(),
            "app"
        );
        // A config's ciphertext does not open as a secret's: the AAD differs.
        assert!(matches!(
            k.open_name(&ctx(RecordKind::Secret), &k.hmac("app"), &sealed),
            Err(KeyError::NameDecrypt)
        ));
    }

    #[test]
    fn the_aad_binds_vault_and_generation() {
        let k = NameKey::generate();
        let sealed = k
            .encrypt_name(&ctx(RecordKind::Secret), "STRIPE_KEY")
            .unwrap();
        for other in [
            NameContext {
                vault_id: VaultId([8; 16]),
                ..ctx(RecordKind::Secret)
            },
            NameContext {
                generation: 4,
                ..ctx(RecordKind::Secret)
            },
        ] {
            assert!(matches!(
                k.decrypt_name(&other, &sealed),
                Err(KeyError::NameDecrypt)
            ));
        }
    }

    #[test]
    fn names_roundtrip_and_ciphertexts_are_randomised() {
        let k = NameKey::generate();
        let c = ctx(RecordKind::Secret);
        let a = k.encrypt_name(&c, "STRIPE_KEY").unwrap();
        let b = k.encrypt_name(&c, "STRIPE_KEY").unwrap();
        assert_ne!(a, b);
        assert_eq!(k.decrypt_name(&c, &a).unwrap(), "STRIPE_KEY");
        assert_eq!(
            k.open_name(&c, &k.hmac("STRIPE_KEY"), &b).unwrap(),
            "STRIPE_KEY"
        );
    }

    #[test]
    fn swaps_tampering_and_wrong_keys_are_refused() {
        let k = NameKey::generate();
        let c = ctx(RecordKind::Secret);
        let stripe = k.encrypt_name(&c, "STRIPE_KEY").unwrap();
        assert!(matches!(
            k.open_name(&c, &k.hmac("DATABASE_URL"), &stripe),
            Err(KeyError::NameMismatch)
        ));
        let mut flipped = stripe.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert!(matches!(
            k.decrypt_name(&c, &flipped),
            Err(KeyError::NameDecrypt)
        ));
        assert!(matches!(
            NameKey::generate().decrypt_name(&c, &stripe),
            Err(KeyError::NameDecrypt)
        ));
        assert!(matches!(
            k.decrypt_name(&c, &[1, 2, 3]),
            Err(KeyError::NameDecrypt)
        ));
    }
}
