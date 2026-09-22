//! Client-side key material that is not a secret value: the
//! project and environment key tree, owner signing and box keys, token keys,
//! writer keys, owner-signed bundles, and the name key that indexes and
//! encrypts record names.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! **This crate cannot decrypt a secret value.** Values are age ciphertext,
//! and age lives in `galata-vault-seal`. `galata-vault-mcp` links this crate and not that one, so
//! the metadata-only MCP server is unable to read a value, whatever an agent
//! asks of it. `scripts/check-mcp-linkage.sh` asserts the edge is absent.
//!
//! ```text
//! project key (random)                                   K_acme
//!   └─ child: HKDF(K_p, salt, "gv/v1/child"‖0‖seg)        K_acme/prod, K_acme/dev, …
//! any node key K
//!   ├─ HKDF(K, salt, "gv/v1/owner-sign"‖0) → Ed25519      owner_sign_pub → vault_id
//!   └─ HKDF(K, salt, "gv/v1/owner-box"‖0)  → X25519       owner_box_pub
//! each generation (random): vault_sk, config_sk, name_key, secret_writer, config_writer
//!   named by an owner-signed descriptor; handed out in owner-signed bundles
//! ```
//!
//! Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
//! are denied outside `#[cfg(test)]`. Integration tests and benches are
//! separate crates, and
//! exempt.

mod bundle;
mod kdf;
mod name_key;
mod node;
mod owner;
mod random;
mod token;
#[cfg(feature = "vectors")]
pub mod vectors;
mod writer;

pub use bundle::{
    AppendBundle, Bundle, ConfigBundle, ConfigSecret, ConfigWriteBundle, FullBundle, NamesBundle,
    ReadBundle, VaultSecret, random_config_secret, random_vault_secret, seal_child_key,
    seal_for_scope, seal_owner_bundle,
};
pub use kdf::SALT;
pub use name_key::{NameContext, NameKey};
pub use node::NodeKey;
pub use owner::OwnerKeys;
pub use token::TokenKeys;
pub use writer::WriterKey;

use crate::proto::FormatError;
use crate::proto::children::ChildrenError;
use crate::proto::integrity::IntegrityError;

#[derive(Debug, thiserror::Error)]
pub enum KeyError {
    #[error(transparent)]
    Format(#[from] FormatError),
    #[error(transparent)]
    Integrity(#[from] IntegrityError),
    #[error("the sealed bundle does not open with this key")]
    Unseal,
    #[error("the bundle is version {0}, which this client does not know")]
    UnknownVersion(u8),
    #[error("the bundle is of kind {0}, which this client does not know")]
    UnknownKind(u8),
    #[error("a {kind} bundle cannot hold {len} bytes of keys")]
    BadLength { kind: &'static str, len: usize },
    #[error("the bundle is shorter than its header")]
    Truncated,
    #[error("scope {0} has no bundle kind in this client")]
    UnsupportedScope(String),
    #[error("the bundle names a different {0} than expected")]
    Binding(&'static str),
    #[error("expected a {expected} bundle, found a {found} bundle")]
    Kind {
        expected: &'static str,
        found: &'static str,
    },
    #[error("a record name does not decrypt with this name key")]
    NameDecrypt,
    #[error("a record name does not match its index; the server may have swapped entries")]
    NameMismatch,
    #[error("the children record is invalid: {0}")]
    Children(ChildrenError),
    /// The AEAD refused to encrypt: only possible for a message too long
    /// for the cipher, which no caller builds.
    #[error("encrypting {0} failed")]
    Encrypt(&'static str),
}
