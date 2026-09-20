// The crate documentation is the README, so every example in it compiles as
// a doctest and the two cannot drift. It carries the review-status
// statement, `REVIEW_STATUS` below.
#![doc = include_str!("../README.md")]
#![warn(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
#![cfg_attr(docsrs, feature(doc_cfg))]
// Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
// are denied outside `#[cfg(test)]`. Integration tests are separate crates,
// and exempt.
#![cfg_attr(
    not(test),
    deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)
)]

/// The review-status statement, word for word as the README, the Python
/// package's description and the `gv --help` footer carry it. It is replaced by a link to the report only
/// once an external review is published in the repository's `audit/`.
pub const REVIEW_STATUS: &str = "galata-vault has not been independently audited. Its formats may change before 1.0. Use it at your own risk.";

/// The private test-vector runner (feature `vectors`). Unsupported: it
/// exists so the Python wheel runs the protocol vectors with this build's
/// code (`docs/spec/README.md#5`).
#[cfg(feature = "vectors")]
#[doc(hidden)]
#[path = "vectors.rs"]
pub mod __vectors;
pub mod audit;
mod check;
#[cfg(feature = "embedded")]
pub mod embedded;
mod error;
pub mod owner;
pub mod state;
pub mod store;
#[cfg(feature = "test-util")]
pub mod testing;
mod token;
mod value;
mod vault;

/// The client transport crate this SDK is built on: [`Transport`], [`Api`]
/// and the builder, re-exported whole.
pub use galata_vault_client as client;

pub use audit::{AuditEntry, AuditReport, Unverifiable};
pub use check::{scan_literals, validate};
pub use error::{Error, ErrorKind, Expected, IntegrityFailure, code, kind_of, kind_of_status};
pub use galata_vault_client::{
    Api, Events, Method, NoEvents, Progress, Request, Response, Transport, TransportError, Warning,
};
#[cfg(feature = "http")]
pub use galata_vault_client::{BuildError, ClientBuilder, HttpTransport};
pub use galata_vault_proto::api::{Scope, VaultStatus, VersionMeta};
pub use galata_vault_proto::audit::{Actor, ChainHead};
pub use galata_vault_proto::path::EnvPath;
pub use galata_vault_seal::ConfigFormat;
pub use state::{FileStateStore, LocalState, StateStore};
pub use store::{KeyName, KeyStore, StoreError};
pub use token::{LeakReport, TokenFileCheck, Vault, report_leaked_token};
pub use value::{ConfigDocument, Entry, Expect, Expiry, NewConfig, SecretSet, SecretValue};
pub use vault::{DescriptorPin, EXPIRY_WARNING_SECS, Pins};
