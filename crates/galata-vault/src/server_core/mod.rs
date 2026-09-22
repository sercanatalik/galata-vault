//! The server's rules, as a synchronous library.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! Everything a galata-vault server enforces is here:
//!
//! * request authentication: owner and token signatures over the canonical
//!   request, the skew window, and nonce spending;
//! * the scope matrix, the read allow-list, and auditing of refusals;
//! * quotas, record versions, preconditions and tombstones;
//! * vault creation checks and token registration rules;
//! * revocation, rotation and vault deletion through the [`Journal`], and
//!   journal replay;
//! * status assembly and the capabilities document.
//!
//! Two transports reach it, and neither has rules of its own. `gv-server`
//! turns an HTTP request into a [`CanonicalRequest`] and a [`CoreResponse`]
//! back into headers; the SDK's `embedded` transport calls [`Core::call`]
//! in-process. Both hand over the request exactly as a signature covers
//! it, so both authenticate through one code path. There is no trusted
//! in-process shortcut.
//!
//! **It cannot read what it stores.** Its workspace dependencies are
//! `galata-vault-proto` and `galata-vault-store`, and it links no HTTP stack, no async runtime
//! and no code that could open a bundle or decrypt a value
//! (`scripts/check-server-linkage.sh`). It verifies, though: every request
//! signature, and every descriptor, bundle, record and children signature
//! before it stores it (Ed25519 public keys only).
//!
//! The core is synchronous and `Send + Sync`, and prints nothing: what an
//! operator should see goes to a [`Log`].

mod auth;
mod critical;
pub mod data_dir;
mod error;
pub mod journal;
mod policy;
mod records;
pub mod route;
mod tokens;
mod vaults;

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::backend::{CommitHook, JournalRecord, Store, StoreError};
use crate::proto::api::{Capabilities, ErrorCode};
use serde::Serialize;

pub use auth::{Caller, Principal};
pub use error::CoreError;
pub use journal::{FileJournal, Journal, ReplayError, replay_journal};
pub use policy::{Admission, Admitted, AllowAll, Policy};
pub use route::{AuthScheme, ROUTES, Route, RouteId, Served};

/// Unix seconds. A trait so tests can move time.
pub trait Clock: Send + Sync {
    fn now(&self) -> i64;
}

/// The operating system's clock.
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs() as i64)
    }
}

/// Where the core reports what an operator should see. The core itself
/// writes nothing anywhere: the HTTP server logs these, and the embedded
/// transport drops them.
pub trait Log: Send + Sync {
    /// Something failed behind an answer that does not say why: a storage
    /// error behind `internal`, a journal write behind `unavailable`.
    fn error(&self, message: &str);
    /// Something went wrong without failing the request, such as a refusal
    /// that could not be audited.
    fn warn(&self, message: &str);
}

/// Drops everything: the default [`Log`].
pub struct NoLog;

impl Log for NoLog {
    fn error(&self, _message: &str) {}
    fn warn(&self, _message: &str) {}
}

/// One request, exactly as a signature covers it: the method, the path
/// and query, the body and both preconditions, with the `GV-Sig` value that
/// signs them.
///
/// `Debug` never shows the authorization value.
#[derive(Clone, Copy)]
pub struct CanonicalRequest<'a> {
    /// `GET`, `PUT`, `POST` or `DELETE`, upper case.
    pub method: &'a str,
    /// The path and query, e.g. `/v1/secrets?limit=500`.
    pub path_and_query: &'a str,
    /// The `Authorization` value, if any.
    pub authorization: Option<&'a str>,
    /// The `If-Match` value, if any.
    pub if_match: Option<&'a str>,
    /// The `If-None-Match` value, if any.
    pub if_none_match: Option<&'a str>,
    /// The body; empty when there is none.
    pub body: &'a [u8],
}

impl std::fmt::Debug for CanonicalRequest<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CanonicalRequest")
            .field("method", &self.method)
            .field("path_and_query", &self.path_and_query)
            .field("authorized", &self.authorization.is_some())
            .field("if_match", &self.if_match)
            .field("if_none_match", &self.if_none_match)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The answer to a [`CanonicalRequest`]. Its body is always JSON: the
/// operation's response, or an `ErrorBody`.
#[derive(Clone, PartialEq, Eq)]
pub struct CoreResponse {
    /// The HTTP status the answer maps to.
    pub status: u16,
    /// The error code of an error answer; the body names it too.
    pub error: Option<ErrorCode>,
    /// A record version, sent over HTTP as `ETag: "<version>"`.
    pub etag: Option<u64>,
    /// When the caller's vault expires if nothing touches it (Unix seconds,
    /// `X-GV-Expires-At` over HTTP). Set on every answer after
    /// authentication, and only when the policy has an idle-expiry window.
    pub expires_at: Option<i64>,
    /// Seconds before a refused request may be retried (`Retry-After`).
    pub retry_after: Option<u64>,
    /// The JSON body.
    pub body: Vec<u8>,
}

impl std::fmt::Debug for CoreResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CoreResponse")
            .field("status", &self.status)
            .field("error", &self.error)
            .field("etag", &self.etag)
            .field("expires_at", &self.expires_at)
            .field("retry_after", &self.retry_after)
            .field("body_len", &self.body.len())
            .finish()
    }
}

impl CoreResponse {
    /// A success with `value` as its body.
    pub(crate) fn json<T: Serialize>(status: u16, value: &T) -> Result<CoreResponse, CoreError> {
        let body = serde_json::to_vec(value)
            .map_err(|e| CoreError::internal().logged(format!("encoding a response: {e}")))?;
        Ok(CoreResponse {
            status,
            error: None,
            etag: None,
            expires_at: None,
            retry_after: None,
            body,
        })
    }

    pub(crate) fn with_etag(mut self, version: u64) -> CoreResponse {
        self.etag = Some(version);
        self
    }
}

/// The server's rules over one store and one journal.
pub struct Core {
    store: Arc<dyn Store>,
    journal: Arc<dyn Journal>,
    policy: Policy,
    clock: Arc<dyn Clock>,
    log: Arc<dyn Log>,
    replayed: usize,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Core")
            .field("journal", &self.journal.describe())
            .field("policy", &self.policy)
            .field("replayed", &self.replayed)
            .finish_non_exhaustive()
    }
}

impl Core {
    /// Open the core over `store` and `journal`. Every journal record newer
    /// than the database is replayed first, so there is no core to call until
    /// the database reflects every acknowledged critical operation; if replay
    /// fails, nothing is served. [`Core::replayed`] says how many records were
    /// replayed.
    pub fn open(
        store: Arc<dyn Store>,
        journal: Arc<dyn Journal>,
        policy: Policy,
        clock: Arc<dyn Clock>,
    ) -> Result<Core, ReplayError> {
        let replayed = replay_journal(&*store, &*journal)?;
        Ok(Core {
            store,
            journal,
            policy,
            clock,
            log: Arc::new(NoLog),
            replayed,
        })
    }

    /// The same core, reporting to `log`.
    pub fn with_log(mut self, log: Arc<dyn Log>) -> Core {
        self.log = log;
        self
    }

    /// How many journal records [`Core::open`] replayed. More than zero means
    /// the database was behind the journal (a restore, or an older copy put
    /// back), which is a security-relevant event.
    pub fn replayed(&self) -> usize {
        self.replayed
    }

    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// What `GET /v1/capabilities` answers.
    pub fn capabilities(&self) -> Capabilities {
        self.policy.capabilities()
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    /// Is the journal reachable right now? Critical operations fail while it
    /// is not.
    pub fn journal_ready(&self) -> bool {
        self.journal.check().is_ok()
    }

    /// Serve one request. Every answer, success or refusal, comes back as a
    /// [`CoreResponse`]; nothing here panics on what a caller sends.
    pub fn call(&self, request: CanonicalRequest<'_>) -> CoreResponse {
        route::dispatch(self, &request).unwrap_or_else(|e| self.answer(e))
    }

    pub(crate) fn store(&self) -> &dyn Store {
        &*self.store
    }

    /// An error as the caller sees it. Its detail, if it has one, goes to the
    /// log and never to the caller.
    pub(crate) fn answer(&self, e: CoreError) -> CoreResponse {
        if let Some(detail) = e.detail() {
            self.log.error(detail);
        }
        e.to_response()
    }

    pub(crate) fn warn(&self, message: &str) {
        self.log.warn(message);
    }

    /// Authenticate `request`, admit it, and run `op` as its caller. Every
    /// answer after authentication, success or error, carries the vault's
    /// expiry when the policy has one; a refusal before that carries none.
    pub(crate) fn authed(
        &self,
        request: &CanonicalRequest<'_>,
        op: impl FnOnce(&Caller) -> Result<CoreResponse, CoreError>,
    ) -> Result<CoreResponse, CoreError> {
        let caller = auth::authenticate(self, request)?;
        self.policy.admission.admit_request(&caller, self.now())?;
        let mut response = op(&caller).unwrap_or_else(|e| self.answer(e));
        response.expires_at = caller.expires_at;
        Ok(response)
    }

    /// Run a critical store operation: the journal write happens inside its
    /// transaction, and a journal failure rolls it back (`unavailable`).
    pub(crate) fn critical<T>(
        &self,
        f: impl FnOnce(&dyn Store, CommitHook<'_>) -> Result<T, StoreError>,
    ) -> Result<T, CoreError> {
        let journal = &self.journal;
        let mut hook = |record: &JournalRecord| journal.put(record);
        f(&*self.store, &mut hook).map_err(CoreError::from)
    }
}
