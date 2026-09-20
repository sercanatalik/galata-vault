//! The only crate that can read a secret value: age v1 encryption to a
//! descriptor's public keys, decryption with a generation's private keys,
//! signed records, and the rotation batch that re-encrypts a whole vault.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! **Client-only.** `galata-vault-cli` links it. `galata-vault-server` and `galata-vault-mcp`
//! must not, and the linkage guards in `scripts/` fail the build if one does.
//!
//! Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
//! are denied outside `#[cfg(test)]`. Integration tests and benches are
//! separate crates, and
//! exempt.

#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

mod envelope;
mod keys;
#[cfg(test)]
mod properties;
mod record;
mod rotation;
#[cfg(feature = "vectors")]
pub mod vectors;

pub use envelope::{
    ConfigFormat, EnvelopeContext, EnvelopeFault, MAX_NAME_LEN, Opened, OpenedConfig, open_config,
    open_value, seal_config, seal_value,
};
pub use keys::{config_public_key, new_config_keypair, new_vault_keypair, vault_public_key};
pub use record::{
    OpenedRecord, Writer, WrittenRecord, open_config_record, open_name, open_secret, verify_listed,
    verify_meta, verify_version,
};
pub use rotation::{Rotation, build_rotation};

use galata_vault_keys::KeyError;
use galata_vault_proto::ids::TokenId;
use galata_vault_proto::integrity::IntegrityError;

#[derive(Debug, thiserror::Error)]
pub enum SealError {
    #[error("the ciphertext is not age v1")]
    NotAge,
    #[error("the value does not decrypt with this key")]
    Decrypt,
    #[error("the value's envelope is malformed: {0}")]
    Envelope(EnvelopeFault),
    #[error("the value belongs to a different record name; the server may have swapped entries")]
    NameMismatch,
    #[error("the value's envelope names a different {0} than the record")]
    Binding(&'static str),
    #[error("record names are at most {MAX_NAME_LEN} bytes")]
    NameTooLong,
    #[error("the public key is not a valid X25519 key")]
    BadPublicKey,
    #[error("age encryption failed: {0}")]
    Encrypt(String),
    #[error(transparent)]
    Key(#[from] KeyError),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("the keys are for generation {bundle}, the record or vault is at generation {vault}")]
    StaleGeneration { bundle: u32, vault: u32 },
    #[error("a rotation needs the vault's token list; request status as the owner")]
    TokensNotVisible,
    #[error("token {0} is not in this vault")]
    UnknownToken(TokenId),
    #[error(
        "the ciphertext holds a {found}, not a {expected}; the server may have swapped entries"
    )]
    KindMismatch {
        expected: &'static str,
        found: &'static str,
    },
    /// Something the server holds uses a value this build does not know (a
    /// token scope, a record kind). Nothing was built or sent.
    #[error("{0}; upgrade this client to do this")]
    UnsupportedByClient(String),
}
