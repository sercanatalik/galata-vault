//! Journal records for critical operations.
//!
//! A record holds only what the database would have held: ciphertext,
//! signatures, sealed bundles, public keys and ids. It is written to an
//! Object-Lock bucket *before* the transaction that produced it commits, and
//! replayed after any restore, so a crash can never quietly resurrect a
//! revoked token or a deleted vault, or undo a rotation.
//!
//! The protocol has no server-side rekey: a re-root is creations, writes,
//! children updates and deletions, and the deletions are journaled.

use galata_vault_proto::api::RotationRequest;
use galata_vault_proto::audit::Actor;
use galata_vault_proto::ids::{TokenId, VaultId};
use serde::{Deserialize, Serialize};

/// Called with the record while the transaction is open. `Err` rolls it back.
pub type CommitHook<'a> = &'a mut dyn FnMut(&JournalRecord) -> Result<(), String>;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalRecord {
    pub seq: u64,
    pub ts: i64,
    pub op: JournalOp,
}

// A rotation carries its whole signed batch. Records are rare (one per
// critical operation) and go straight to JSON, so the size gap is harmless.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum JournalOp {
    RevokeTokens {
        vault_id: VaultId,
        token_ids: Vec<TokenId>,
        actor: Actor,
        reported: bool,
    },
    Rotate {
        vault_id: VaultId,
        actor: Actor,
        request: RotationRequest,
    },
    DeleteVault {
        vault_id: VaultId,
    },
}

impl JournalRecord {
    pub fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("a journal record always serializes")
    }

    pub fn from_json(bytes: &[u8]) -> Result<JournalRecord, serde_json::Error> {
        serde_json::from_slice(bytes)
    }

    /// Zero-padded, so lexical order in the bucket is replay order.
    pub fn object_key(&self) -> String {
        format!("journal/{:020}.json", self.seq)
    }
}
