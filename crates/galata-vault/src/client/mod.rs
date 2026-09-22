//! The galata-vault client transport: the layer the SDK
//! (`galata-vault`) and the MCP server (`galata-vault-mcp`) share.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! It holds everything a client does on the wire and nothing that decrypts:
//!
//! - [`Transport`]: one method, [`Transport::send`], carrying the canonical
//!   request the protocol signs (method, path and query, preconditions,
//!   authorization, body) and returning status, the protocol's response
//!   headers and the body. It names no HTTP-library type, so a test, a proxy
//!   or an in-process backend can implement it.
//! - [`Api`]: the typed operations over any transport. It builds each
//!   request, signs it as the owner or a token holder, sends it, and maps
//!   the answer to a typed result or an [`ApiError`] carrying the server's
//!   stable code.
//! - [`ClientBuilder`] and [`HttpTransport`] (feature `http`, on by
//!   default): ureq over rustls, with no redirects, no proxy unless one is
//!   given (never from the environment), a 120-second timeout, and the
//!   bundled roots, given roots or the platform verifier.
//! - [`Events`]: where notices go (expiry, progress, warnings). The default
//!   ([`NoEvents`]) drops them: this crate writes nothing to stdout or stderr.
//! - `RecordingTransport` (feature `test-util`).
//!
//! **What it cannot do** is the point of it being a crate: it links no
//! value-decryption code (`galata-vault-seal`, `age`), which
//! `scripts/check-client-linkage.sh` checks against the resolved dependency
//! graph. That is what lets `galata-vault-mcp` use the one client implementation and
//! still be unable to read a secret.
//!
//! Nothing here is process-global: every notice goes to the [`Events`] of
//! the [`Api`] that made the request.

// Non-test code never panics on its input: `unwrap`, `expect` and `panic!`
// are denied outside `#[cfg(test)]`. Integration tests are separate crates,
// and exempt.

mod api;
mod events;
#[cfg(feature = "http")]
mod http;
#[cfg(feature = "test-util")]
mod recording;
mod transport;

pub use api::{AUDIT_PAGE, Answer, Api, ApiError, Auth, LIST_PAGE, Pre, Reply, records_path};
pub use events::{Events, NoEvents, Progress, Warning};
#[cfg(feature = "http")]
pub use http::{BuildError, ClientBuilder, DEFAULT_TIMEOUT, HttpTransport};
#[cfg(feature = "test-util")]
pub use recording::{Recorded, RecordingTransport};
pub use transport::{Method, Request, Response, Transport, TransportError};

/// Seconds since the Unix epoch, as request signatures carry it.
pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64)
}
