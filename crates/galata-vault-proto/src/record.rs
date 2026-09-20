//! Signed records: what a generation's writer key signs.
//!
//! ```text
//! frame("gv/v1/record", vault_id(16) ‖ generation(4) ‖ kind(1) ‖ name_index(32)
//!       ‖ version(8) ‖ written_at(8) ‖ tombstone(1) ‖ SHA-256(value_ct) ‖ SHA-256(name_ct))
//! ```
//!
//! The signature is over the ciphertext, not inside it, so the server can
//! check every write against the public descriptor before storing it, and a
//! holder that cannot decrypt (`meta`, `append`, `config`) can still check
//! the names, versions and tombstones it relies on. A tombstone signs an
//! empty `value_ct`.

use serde::{Deserialize, Serialize};

use crate::frame::{frame, label};
use crate::ids::{Hash32, Key32, NameHmac, Sig64, VaultId};
use crate::integrity::{IntegrityError, verify_ed25519};

/// The record envelope's version byte (`docs/spec/records.md#3`). The
/// envelope itself is sealed with age, so only a client that decrypts reads
/// it: `galata-vault-seal` encodes and checks it.
pub const ENVELOPE_VERSION: u8 = 1;

/// A record kind. Secrets and configs have their own keys, writer keys and
/// name-index domains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum RecordKind {
    Secret,
    Config,
}

impl RecordKind {
    /// The byte every binding uses for the kind.
    pub fn code(self) -> u8 {
        match self {
            RecordKind::Secret => 1,
            RecordKind::Config => 2,
        }
    }

    pub fn from_code(code: u8) -> Option<RecordKind> {
        match code {
            1 => Some(RecordKind::Secret),
            2 => Some(RecordKind::Config),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::Secret => "secret",
            RecordKind::Config => "config",
        }
    }
}

/// Everything a record signature binds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordContext {
    pub vault_id: VaultId,
    pub generation: u32,
    pub kind: RecordKind,
    pub name_index: NameHmac,
    pub version: u64,
    pub written_at: i64,
    pub tombstone: bool,
    pub value_ct_hash: Hash32,
    pub name_ct_hash: Hash32,
}

impl RecordContext {
    /// A context from the ciphertexts themselves. `value_ct = None` is a
    /// tombstone, which signs the hash of an empty value.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: VaultId,
        generation: u32,
        kind: RecordKind,
        name_index: NameHmac,
        version: u64,
        written_at: i64,
        name_ct: &[u8],
        value_ct: Option<&[u8]>,
    ) -> RecordContext {
        RecordContext {
            vault_id,
            generation,
            kind,
            name_index,
            version,
            written_at,
            tombstone: value_ct.is_none(),
            value_ct_hash: Hash32::sha256(value_ct.unwrap_or(&[])),
            name_ct_hash: Hash32::sha256(name_ct),
        }
    }

    /// The exact bytes a writer signs.
    pub fn signing_input(&self) -> Vec<u8> {
        frame(
            label::RECORD,
            &[
                &self.vault_id.0,
                &self.generation.to_be_bytes(),
                &[self.kind.code()],
                &self.name_index.0,
                &self.version.to_be_bytes(),
                &self.written_at.to_be_bytes(),
                &[u8::from(self.tombstone)],
                &self.value_ct_hash.0,
                &self.name_ct_hash.0,
            ],
        )
    }

    /// Verify a record signature against the generation's writer key for
    /// this record's kind.
    pub fn verify(&self, writer_pub: &Key32, sig: &Sig64) -> Result<(), IntegrityError> {
        verify_ed25519(writer_pub, &self.signing_input(), sig, "record")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(tombstone: bool) -> RecordContext {
        RecordContext::new(
            VaultId([1; 16]),
            3,
            RecordKind::Secret,
            NameHmac([2; 32]),
            9,
            1_757_500_000,
            b"name-ct",
            (!tombstone).then_some(&b"value-ct"[..]),
        )
    }

    #[test]
    fn the_context_binds_every_field() {
        let base = ctx(false).signing_input();
        assert!(base.starts_with(b"gv/v1/record\0"));
        assert_eq!(
            base.len(),
            "gv/v1/record".len() + 1 + 16 + 4 + 1 + 32 + 8 + 8 + 1 + 32 + 32
        );
        let variants = [
            RecordContext {
                vault_id: VaultId([9; 16]),
                ..ctx(false)
            },
            RecordContext {
                generation: 4,
                ..ctx(false)
            },
            RecordContext {
                kind: RecordKind::Config,
                ..ctx(false)
            },
            RecordContext {
                name_index: NameHmac([3; 32]),
                ..ctx(false)
            },
            RecordContext {
                version: 10,
                ..ctx(false)
            },
            RecordContext {
                written_at: 0,
                ..ctx(false)
            },
            ctx(true),
            RecordContext {
                name_ct_hash: Hash32::sha256(b"other"),
                ..ctx(false)
            },
        ];
        for v in variants {
            assert_ne!(v.signing_input(), base);
        }
        assert_eq!(ctx(true).value_ct_hash, Hash32::sha256(b""));
    }

    #[test]
    fn kinds_have_stable_codes() {
        for k in [RecordKind::Secret, RecordKind::Config] {
            assert_eq!(RecordKind::from_code(k.code()), Some(k));
        }
        assert_eq!(RecordKind::from_code(0), None);
    }
}
