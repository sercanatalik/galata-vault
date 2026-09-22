//! The shared vocabulary of the galata-vault protocol: string formats
//! (`gvk1_`, `gvt1_`, paths), the framing convention, API types,
//! descriptors, record contexts, proof-of-work and audit-chain hashing.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! **Every crate links this one, so it must never be able to decrypt.** It
//! holds no private key and depends on no cipher. What it can do (parse,
//! check a checksum, hash an audit row, verify a proof-of-work or an Ed25519
//! signature) the server needs too, and the server is the one binary that
//! must stay unable to read a secret.
//!
//! Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
//! are denied outside `#[cfg(test)]`. Integration tests and benches are
//! separate crates, and
//! exempt.

pub mod api;
pub mod audit;
pub mod children;
pub mod codec;
pub mod descriptor;
pub mod frame;
pub mod ids;
pub mod integrity;
pub mod mcp;
pub mod path;
pub mod pow;
pub mod record;
pub mod sig;
pub mod time;
pub mod tolerant;
pub mod url;
#[cfg(feature = "vectors")]
pub mod vectors;

pub use codec::FormatError;
