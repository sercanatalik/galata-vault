// The crate documentation is the README, so every example in it compiles as
// a doctest and the two cannot drift. It carries the review-status
// statement, `REVIEW_STATUS` below.
// Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
// are denied outside `#[cfg(test)]`. Integration tests are separate crates,
// and exempt.

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
// The SDK itself: the owner API, the token client, and the client-side
// crypto they are built on. `sdk` is what pulls in `keys` and `seal`, so a
// build without it links no value or name crypto at all -- which is what
// makes the server build below provable rather than merely intended
// (scripts/check-linkage.sh).
#[cfg(feature = "sdk")]
pub mod audit;
#[cfg(feature = "sdk")]
mod check;
#[cfg(feature = "sdk")]
pub mod client;
#[cfg(feature = "sdk")]
pub mod keys;
#[cfg(feature = "sdk")]
pub mod seal;

/// The wire protocol: types, framing and the route table. Every build has it.
pub mod proto;

// The storage and serving side. None of it is compiled into an SDK-only
// build, and none of it can reach `keys` or `seal`, which are not compiled
// into a server-only build.
#[cfg(feature = "storage")]
pub mod backend;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server-core")]
pub mod server_core;

// The two binaries' libraries; crates/gv and crates/gv-mcp wrap them.
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "mcp")]
pub mod mcp;

#[cfg(feature = "embedded")]
pub mod embedded;
#[cfg(feature = "sdk")]
mod error;
#[cfg(feature = "sdk")]
pub mod owner;
#[cfg(feature = "sdk")]
pub mod state;
#[cfg(feature = "sdk")]
pub mod store;
#[cfg(feature = "test-util")]
pub mod testing;
#[cfg(feature = "sdk")]
mod token;
#[cfg(feature = "sdk")]
mod value;
#[cfg(feature = "sdk")]
mod vault;

#[cfg(feature = "sdk")]
pub use crate::client::{
    Api, Events, Method, NoEvents, Progress, Request, Response, Transport, TransportError, Warning,
};
#[cfg(feature = "http")]
#[cfg(feature = "sdk")]
pub use crate::client::{BuildError, ClientBuilder, HttpTransport};
#[cfg(feature = "sdk")]
pub use crate::proto::api::{Scope, VaultStatus, VersionMeta};
#[cfg(feature = "sdk")]
pub use crate::proto::audit::{Actor, ChainHead};
#[cfg(feature = "sdk")]
pub use crate::proto::path::EnvPath;
#[cfg(feature = "sdk")]
pub use crate::seal::ConfigFormat;
#[cfg(feature = "sdk")]
pub use audit::{AuditEntry, AuditReport, Unverifiable};
#[cfg(feature = "sdk")]
pub use check::{scan_literals, validate};
#[cfg(feature = "sdk")]
pub use error::{Error, ErrorKind, Expected, IntegrityFailure, code, kind_of, kind_of_status};
#[cfg(feature = "sdk")]
pub use state::{FileStateStore, LocalState, StateStore};
#[cfg(feature = "sdk")]
pub use store::{KeyName, KeyStore, StoreError};
#[cfg(feature = "sdk")]
pub use token::{LeakReport, TokenFileCheck, Vault, report_leaked_token};
#[cfg(feature = "sdk")]
pub use value::{ConfigDocument, Entry, Expect, Expiry, NewConfig, SecretSet, SecretValue};
#[cfg(feature = "sdk")]
pub use vault::{DescriptorPin, EXPIRY_WARNING_SECS, Pins};
