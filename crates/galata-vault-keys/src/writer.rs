//! Writer keys: one Ed25519 key per generation per record kind.
//!
//! A record is valid only if the generation's writer key for its kind signed
//! it. The keys sit only in the bundles of scopes allowed to write, so `meta`,
//! `read` and `config` cannot produce a valid write, and `config-write`
//! cannot produce a valid secret.

use ed25519_dalek::{Signer, SigningKey};
use galata_vault_proto::ids::{Key32, Sig64};
use galata_vault_proto::record::RecordContext;
use zeroize::Zeroizing;

use crate::random::random_bytes;

#[derive(Clone)]
pub struct WriterKey(SigningKey);

impl std::fmt::Debug for WriterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WriterKey(pub {:?})", self.public())
    }
}

impl WriterKey {
    pub fn generate() -> WriterKey {
        WriterKey(SigningKey::from_bytes(&random_bytes::<32>()))
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> WriterKey {
        WriterKey(SigningKey::from_bytes(bytes))
    }

    pub(crate) fn to_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// What the generation's descriptor names.
    pub fn public(&self) -> Key32 {
        Key32(self.0.verifying_key().to_bytes())
    }

    /// Sign a record's context.
    pub fn sign(&self, ctx: &RecordContext) -> Sig64 {
        Sig64(self.0.sign(&ctx.signing_input()).to_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galata_vault_proto::ids::{NameHmac, VaultId};
    use galata_vault_proto::record::RecordKind;

    #[test]
    fn signatures_verify_only_under_the_matching_key_and_context() {
        let w = WriterKey::generate();
        let ctx = RecordContext::new(
            VaultId([1; 16]),
            1,
            RecordKind::Secret,
            NameHmac([2; 32]),
            1,
            0,
            b"n",
            Some(b"v"),
        );
        let sig = w.sign(&ctx);
        assert!(ctx.verify(&w.public(), &sig).is_ok());
        assert!(ctx.verify(&WriterKey::generate().public(), &sig).is_err());
        let other = RecordContext {
            version: 2,
            ..ctx.clone()
        };
        assert!(other.verify(&w.public(), &sig).is_err());
        assert!(!format!("{w:?}").contains(&hex::encode(*w.to_bytes())));
    }
}
