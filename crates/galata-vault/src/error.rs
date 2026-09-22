//! One error type, with stable codes. The Python package reports the same
//! code for the same failure, from the same table ([`kind_of`]).
//!
//! [`Error`] is an enum: match on the variant for structured detail (a
//! conflict's versions, the refused path's suggestion, the integrity
//! failure), or on [`Error::code`] for the stable string, which is exactly
//! what this crate reported before the enum existed.
//!
//! Messages are built from allow-listed parts: the path or label, a name the
//! caller used, versions and failure kinds. Never a token, key material, a
//! value or a config body. An error's `Display` is its whole message;
//! [`std::error::Error::source`] returns the underlying transport or store
//! cause where there is one.

use std::sync::Arc;

use crate::client::{ApiError, Pre};
use crate::keys::KeyError;
use crate::proto::api::ErrorCode;
use crate::proto::audit::ChainError;
use crate::proto::integrity::IntegrityError;
use crate::seal::SealError;

use crate::store::StoreError;

/// The codes this crate raises itself, beside the server's own
/// (`token_expired`, `precondition_failed`, …).
pub mod code {
    /// A token string that does not parse or whose checksum does not match.
    pub const INVALID_TOKEN: &str = "invalid_token";
    /// A token file that is unreadable, too permissive, or holds more than
    /// one token.
    pub const INVALID_TOKEN_FILE: &str = "invalid_token_file";
    /// A server URL that is not `https://`, or `http://` to loopback.
    pub const INVALID_SERVER: &str = "invalid_server";
    /// A proxy URL that does not parse.
    pub const INVALID_PROXY: &str = "invalid_proxy";
    /// `GV_SERVER` is not set.
    pub const MISSING_SERVER: &str = "missing_server";
    /// The environment names both token sources, or neither.
    pub const INVALID_ENVIRONMENT: &str = "invalid_environment";
    /// An empty name, or one in the reserved `gv:` namespace.
    pub const INVALID_NAME: &str = "invalid_name";
    /// A config body that does not parse in its declared format.
    pub const INVALID_CONFIG: &str = "invalid_config";
    /// An audit head that is not one this crate returned.
    pub const INVALID_AUDIT_HEAD: &str = "invalid_audit_head";
    /// A credential literal in a config body.
    pub const CREDENTIAL_LITERAL: &str = "credential_literal";
    /// A config format the operation does not support.
    pub const UNSUPPORTED_FORMAT: &str = "unsupported_format";
    /// A config body that is not UTF-8.
    pub const NOT_TEXT: &str = "not_text";
    /// No such record, version, vault or token.
    pub const NOT_FOUND: &str = "not_found";
    /// This credential may not do it.
    pub const FORBIDDEN: &str = "forbidden";
    /// Another writer won; nothing was overwritten.
    pub const CONFLICT: &str = "conflict";
    /// The vault was rotated underneath the handle: refresh it and retry.
    pub const STALE_GENERATION: &str = "stale_generation";
    /// The server could not be reached.
    pub const UNREACHABLE: &str = "unreachable";
    /// Any other failure.
    pub const ERROR: &str = "error";
    /// A descriptor, bundle, record or children signature does not verify.
    pub const BAD_SIGNATURE: &str = "bad_signature";
    /// A key does not match the pinned vault or its descriptor.
    pub const KEY_MISMATCH: &str = "key_mismatch";
    /// A signed or encrypted binding disagrees with what the server reported.
    pub const BINDING_MISMATCH: &str = "binding_mismatch";
    /// The server showed an older record version than this client saw.
    pub const VERSION_ROLLBACK: &str = "version_rollback";
    /// The server showed an older or different generation than this client saw.
    pub const GENERATION_ROLLBACK: &str = "generation_rollback";
    /// The audit chain does not verify against the known head.
    pub const AUDIT_MISMATCH: &str = "audit_mismatch";
    /// A key store or state store failed.
    pub const STORE: &str = "store";
    /// A path absent from the known tree (the error carries a suggestion).
    pub const UNKNOWN_PATH: &str = "unknown_path";
    /// A string that is not an environment path or project name.
    pub const INVALID_PATH: &str = "invalid_path";
    /// A kit file that does not parse, or is of the wrong kind.
    pub const INVALID_KIT: &str = "invalid_kit";
    /// No project of that name is configured in local state.
    pub const UNKNOWN_PROJECT: &str = "unknown_project";
    /// A project of that name is already configured.
    pub const PROJECT_EXISTS: &str = "project_exists";
    /// The environment already exists.
    pub const ENV_EXISTS: &str = "env_exists";
    /// The path is a project, where an environment was expected.
    pub const IS_PROJECT: &str = "is_project";
    /// The environment has environments below it.
    pub const HAS_CHILDREN: &str = "has_children";
    /// The server already has a vault for this key.
    pub const VAULT_EXISTS: &str = "vault_exists";
    /// No key is held for the path or any node above it.
    pub const NO_KEY: &str = "no_key";
    /// A kit or local project is pinned to another server or vault.
    pub const SERVER_MISMATCH: &str = "server_mismatch";
    /// A rekey is in progress and must be resumed or aborted first.
    pub const REKEY_IN_PROGRESS: &str = "rekey_in_progress";
    /// No rekey is in progress (or not for that path).
    pub const NO_REKEY: &str = "no_rekey";
    /// The rekey's parent already points at the new key: it can only resume.
    pub const REKEY_FORWARD_ONLY: &str = "rekey_forward_only";
    /// The data directory is open in another process or handle: a `gv-server
    /// local`, or another embedded opener (feature `embedded`).
    pub const DATA_DIR_IN_USE: &str = "data_dir_in_use";
    /// A data directory that is not a directory, is reachable by its group or
    /// others, or cannot be read (feature `embedded`).
    pub const INVALID_DATA_DIR: &str = "invalid_data_dir";
    /// The server's capabilities do not list protocol 2: nothing
    /// authenticated was sent to it.
    pub const UNSUPPORTED_PROTOCOL: &str = "unsupported_protocol";
    /// The operation depends on a value this client does not know (a newer
    /// server's token scope, audit action or actor, children entry mode):
    /// it was refused and nothing changed. Upgrade the client.
    pub const UNSUPPORTED_BY_CLIENT: &str = "unsupported_by_client";
}

/// What kind of failure a code is. The Python package raises one exception
/// class per kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The token is malformed, unknown, revoked or expired, or its vault
    /// expired.
    Auth,
    /// The credential's scope or allow-list does not permit it.
    Forbidden,
    /// No such record, version, or the record was deleted.
    NotFound,
    /// Another writer won; nothing was overwritten.
    Conflict,
    /// The server could not be reached.
    Transport,
    /// Refused on this side before any request: a bad argument, file,
    /// environment, document or local state.
    Invalid,
    /// Something the server served does not verify. Treat the server's
    /// answer as untrustworthy.
    Integrity,
    /// Anything else.
    Other,
}

impl ErrorKind {
    /// The kind's name, as the Python package sees it.
    pub fn as_str(self) -> &'static str {
        match self {
            ErrorKind::Auth => "auth",
            ErrorKind::Forbidden => "forbidden",
            ErrorKind::NotFound => "not_found",
            ErrorKind::Conflict => "conflict",
            ErrorKind::Transport => "transport",
            ErrorKind::Invalid => "invalid",
            ErrorKind::Integrity => "integrity",
            ErrorKind::Other => "error",
        }
    }
}

/// The kind a code belongs to: one table for Rust and Python.
///
/// A code the protocol defines is classified from [`ErrorCode`] itself, so
/// renaming a variant there is a compile error here rather than a refusal
/// that quietly becomes [`ErrorKind::Other`]. Codes this crate raises itself
/// are matched by their `code::` constant. A protocol code this crate
/// chooses no kind for keeps [`ErrorKind::Other`], as it always has, and
/// [`Error::kind`] takes such a refusal's kind from the status class.
pub fn kind_of(code: &str) -> ErrorKind {
    if let Some(kind) = ErrorCode::parse(code).and_then(kind_of_protocol) {
        return kind;
    }
    match code {
        code::INVALID_TOKEN => ErrorKind::Auth,
        code::UNREACHABLE => ErrorKind::Transport,
        code::INVALID_TOKEN_FILE
        | code::INVALID_SERVER
        | code::INVALID_PROXY
        | code::MISSING_SERVER
        | code::INVALID_ENVIRONMENT
        | code::INVALID_NAME
        | code::INVALID_CONFIG
        | code::INVALID_AUDIT_HEAD
        | code::CREDENTIAL_LITERAL
        | code::UNSUPPORTED_FORMAT
        | code::NOT_TEXT
        | code::UNKNOWN_PATH
        | code::INVALID_PATH
        | code::INVALID_KIT
        | code::UNKNOWN_PROJECT
        | code::PROJECT_EXISTS
        | code::ENV_EXISTS
        | code::IS_PROJECT
        | code::HAS_CHILDREN
        | code::VAULT_EXISTS
        | code::NO_KEY
        | code::SERVER_MISMATCH
        | code::REKEY_IN_PROGRESS
        | code::NO_REKEY
        | code::REKEY_FORWARD_ONLY
        | code::DATA_DIR_IN_USE
        | code::INVALID_DATA_DIR
        | code::UNSUPPORTED_PROTOCOL
        | code::UNSUPPORTED_BY_CLIENT => ErrorKind::Invalid,
        code::BINDING_MISMATCH | code::AUDIT_MISMATCH => ErrorKind::Integrity,
        _ => ErrorKind::Other,
    }
}

/// The kind of a code the protocol defines, where this crate classifies it.
///
/// `None` means the code keeps [`ErrorKind::Other`], exactly as it did when
/// this table matched wire strings. Naming the variants rather than their
/// strings is the point: a rename in `galata-vault-proto` stops the build
/// here. Adding a variant does not, and needs no change: it is `None` until
/// a kind is chosen for it.
fn kind_of_protocol(code: ErrorCode) -> Option<ErrorKind> {
    Some(match code {
        ErrorCode::Unauthorized | ErrorCode::TokenExpired => ErrorKind::Auth,
        ErrorCode::Forbidden => ErrorKind::Forbidden,
        ErrorCode::NotFound => ErrorKind::NotFound,
        ErrorCode::PreconditionFailed
        | ErrorCode::Conflict
        | ErrorCode::StaleGeneration
        | ErrorCode::VersionMismatch => ErrorKind::Conflict,
        ErrorCode::BadSignature
        | ErrorCode::KeyMismatch
        | ErrorCode::VersionRollback
        | ErrorCode::GenerationRollback => ErrorKind::Integrity,
        _ => return None,
    })
}

/// The kind a refusal's HTTP status implies: how a server code this client
/// does not know is classified (`docs/spec/http-api.md#7`).
pub fn kind_of_status(status: u16) -> ErrorKind {
    match status {
        401 => ErrorKind::Auth,
        403 => ErrorKind::Forbidden,
        404 => ErrorKind::NotFound,
        409 | 412 => ErrorKind::Conflict,
        _ => ErrorKind::Other,
    }
}

/// What a write expected the record to be, in a conflict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Expected {
    /// That it did not exist (or was deleted).
    Absent,
    /// That its latest version was this one.
    Version(u64),
}

impl From<Pre> for Expected {
    fn from(pre: Pre) -> Expected {
        match pre {
            Pre::Create | Pre::Revive(_) => Expected::Absent,
            Pre::Update(v) => Expected::Version(v),
        }
    }
}

impl std::fmt::Display for Expected {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Expected::Absent => f.write_str("no existing record"),
            Expected::Version(v) => write!(f, "version {v}"),
        }
    }
}

/// A protocol verification failure: what the server served does not
/// verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IntegrityFailure {
    /// A descriptor, bundle, record or children signature does not verify.
    BadSignature(&'static str),
    /// A key or identity does not match the pinned vault.
    KeyMismatch(&'static str),
    /// A signed or encrypted binding disagrees with what the server reported.
    BindingMismatch(&'static str),
    /// The server showed an older record version than this client saw.
    VersionRollback {
        /// The version this client saw.
        known: u64,
        /// The version the server showed.
        got: u64,
    },
    /// The server showed an older or different generation than this client saw.
    GenerationRollback {
        /// The generation this client saw.
        known: u32,
        /// The generation the server showed.
        got: u32,
    },
    /// The audit chain does not continue the known head.
    AuditMismatch,
}

impl IntegrityFailure {
    /// The stable code.
    pub fn code(&self) -> &'static str {
        match self {
            IntegrityFailure::BadSignature(_) => code::BAD_SIGNATURE,
            IntegrityFailure::KeyMismatch(_) => code::KEY_MISMATCH,
            IntegrityFailure::BindingMismatch(_) => code::BINDING_MISMATCH,
            IntegrityFailure::VersionRollback { .. } => code::VERSION_ROLLBACK,
            IntegrityFailure::GenerationRollback { .. } => code::GENERATION_ROLLBACK,
            IntegrityFailure::AuditMismatch => code::AUDIT_MISMATCH,
        }
    }
}

impl From<&IntegrityError> for IntegrityFailure {
    fn from(e: &IntegrityError) -> IntegrityFailure {
        match *e {
            IntegrityError::BadSignature(w) => IntegrityFailure::BadSignature(w),
            IntegrityError::KeyMismatch(w) => IntegrityFailure::KeyMismatch(w),
            IntegrityError::BindingMismatch(w) | IntegrityError::Malformed(w) => {
                IntegrityFailure::BindingMismatch(w)
            }
            IntegrityError::VersionRollback { known, got } => {
                IntegrityFailure::VersionRollback { known, got }
            }
            IntegrityError::GenerationRollback { known, got } => {
                IntegrityFailure::GenerationRollback { known, got }
            } // An integrity failure galata-vault-proto names that this build does not:
              // still an integrity failure.
        }
    }
}

/// Every failure this crate returns. `Send`, `Sync` and `Clone`.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Error {
    /// Refused on this side before any request: a bad argument, file,
    /// environment, document or local state. `code` says which.
    Invalid {
        /// The stable code.
        code: &'static str,
        /// The message.
        message: String,
    },
    /// The token is malformed, unknown, revoked or expired, or its vault
    /// expired (`unauthorized`, `token_expired`, `invalid_token`).
    Auth {
        /// The stable code.
        code: String,
        /// The message.
        message: String,
    },
    /// The credential's scope or allow-list does not permit it.
    Forbidden {
        /// The message.
        message: String,
    },
    /// No such record, version or token, or the record was deleted.
    NotFound {
        /// The message.
        message: String,
    },
    /// The server does not know an owner's vault: it expired, was deleted,
    /// or was re-rooted. An expired one can be repaired at the same id.
    VaultNotFound {
        /// The environment path.
        label: String,
        /// The message.
        message: String,
    },
    /// A path that is not in the known tree, refused before any request.
    UnknownPath {
        /// The path asked for.
        path: String,
        /// The closest known path, if one is plausibly a typo.
        suggestion: Option<String>,
        /// Whether the path's project is known at all.
        project_known: bool,
        /// The message.
        message: String,
    },
    /// Another writer won; nothing was overwritten.
    Conflict {
        /// The record name.
        name: String,
        /// What the write expected.
        expected: Expected,
        /// The server's latest version, if the record exists.
        current: Option<u64>,
        /// The message.
        message: String,
    },
    /// The vault was rotated underneath this handle: call
    /// [`crate::Vault::refresh`] and retry.
    StaleGeneration {
        /// The vault's label.
        label: String,
        /// The message.
        message: String,
    },
    /// Something the server served does not verify.
    Integrity {
        /// What failed.
        failure: IntegrityFailure,
        /// The message.
        message: String,
    },
    /// Any other refusal by the server, its code kept verbatim, including a
    /// code this client does not know (`http_<status>` when it named none).
    Server {
        /// The stable code.
        code: String,
        /// The HTTP status.
        status: u16,
        /// The message.
        message: String,
    },
    /// The server could not be reached; `source()` is the I/O or TLS error.
    Transport {
        /// The server.
        server: String,
        /// The message.
        message: String,
        /// The underlying cause.
        source: Arc<dyn std::error::Error + Send + Sync>,
    },
    /// A key store or state store failed; `source()` is its error.
    Store {
        /// The message.
        message: String,
        /// The store's error.
        source: Arc<StoreError>,
    },
    /// Any other failure (code `error`).
    Other {
        /// The message.
        message: String,
    },
}

impl Error {
    /// The stable code, the same string Python's `.code` reports.
    pub fn code(&self) -> &str {
        match self {
            Error::Invalid { code, .. } => code,
            Error::Auth { code, .. } | Error::Server { code, .. } => code,
            Error::Forbidden { .. } => code::FORBIDDEN,
            Error::NotFound { .. } | Error::VaultNotFound { .. } => code::NOT_FOUND,
            Error::UnknownPath { .. } => code::UNKNOWN_PATH,
            Error::Conflict { .. } => code::CONFLICT,
            Error::StaleGeneration { .. } => code::STALE_GENERATION,
            Error::Integrity { failure, .. } => failure.code(),
            Error::Transport { .. } => code::UNREACHABLE,
            Error::Store { .. } => code::STORE,
            Error::Other { .. } => code::ERROR,
        }
    }

    /// The kind of failure, from [`kind_of`]; for a server code this client
    /// does not know, from the HTTP status class ([`kind_of_status`]).
    pub fn kind(&self) -> ErrorKind {
        match self {
            Error::Server { code, status, .. } if ErrorCode::parse(code).is_none() => {
                kind_of_status(*status)
            }
            _ => kind_of(self.code()),
        }
    }

    /// The whole message.
    pub fn message(&self) -> &str {
        match self {
            Error::Invalid { message, .. }
            | Error::Auth { message, .. }
            | Error::Forbidden { message }
            | Error::NotFound { message }
            | Error::VaultNotFound { message, .. }
            | Error::UnknownPath { message, .. }
            | Error::Conflict { message, .. }
            | Error::StaleGeneration { message, .. }
            | Error::Integrity { message, .. }
            | Error::Server { message, .. }
            | Error::Transport { message, .. }
            | Error::Store { message, .. }
            | Error::Other { message } => message,
        }
    }

    fn message_mut(&mut self) -> &mut String {
        match self {
            Error::Invalid { message, .. }
            | Error::Auth { message, .. }
            | Error::Forbidden { message }
            | Error::NotFound { message }
            | Error::VaultNotFound { message, .. }
            | Error::UnknownPath { message, .. }
            | Error::Conflict { message, .. }
            | Error::StaleGeneration { message, .. }
            | Error::Integrity { message, .. }
            | Error::Server { message, .. }
            | Error::Transport { message, .. }
            | Error::Store { message, .. }
            | Error::Other { message } => message,
        }
    }

    /// The same error, its message prefixed with `context: `.
    pub(crate) fn context(mut self, context: impl std::fmt::Display) -> Error {
        let m = self.message_mut();
        *m = format!("{context}: {m}");
        self
    }

    pub(crate) fn local(code: &'static str, message: impl Into<String>) -> Error {
        Error::Invalid {
            code,
            message: message.into(),
        }
    }

    pub(crate) fn forbidden(message: impl Into<String>) -> Error {
        Error::Forbidden {
            message: message.into(),
        }
    }

    pub(crate) fn not_found(message: impl Into<String>) -> Error {
        Error::NotFound {
            message: message.into(),
        }
    }

    pub(crate) fn other(message: impl Into<String>) -> Error {
        Error::Other {
            message: message.into(),
        }
    }

    pub(crate) fn stale(label: &str, message: impl Into<String>) -> Error {
        Error::StaleGeneration {
            label: label.to_owned(),
            message: message.into(),
        }
    }

    /// Refused because the operation depends on a value this client does not
    /// know. Nothing was changed.
    pub(crate) fn unsupported(message: impl Into<String>) -> Error {
        Error::Invalid {
            code: code::UNSUPPORTED_BY_CLIENT,
            message: message.into(),
        }
    }

    /// `label: integrity check failed: <what>`.
    pub(crate) fn integrity(label: &str, e: IntegrityError) -> Error {
        Error::Integrity {
            failure: IntegrityFailure::from(&e),
            message: format!("{label}: integrity check failed: {e}"),
        }
    }

    pub(crate) fn conflict(name: &str, pre: Pre, current: Option<u64>, deleting: bool) -> Error {
        let expected = Expected::from(pre);
        let current_text = current.map_or("none".to_owned(), |v| v.to_string());
        let outcome = if deleting {
            "nothing was deleted"
        } else {
            "nothing was overwritten"
        };
        Error::Conflict {
            name: name.to_owned(),
            expected,
            current,
            message: format!(
                "{name} changed on the server: expected {expected}, the server has version {current_text}; {outcome}"
            ),
        }
    }

    /// A value-crate failure, with context: an integrity code when it is one.
    pub(crate) fn seal(e: SealError, context: impl std::fmt::Display) -> Error {
        let message = format!("{context}: {}", chain(&e));
        match seal_class(&e) {
            Class::Integrity(failure) => Error::Integrity { failure, message },
            Class::Stale => Error::StaleGeneration {
                label: context.to_string(),
                message,
            },
            Class::Unsupported => Error::unsupported(message),
            Class::Other => Error::Other { message },
        }
    }

    /// A key-crate failure, with context: an integrity code when it is one.
    pub(crate) fn key(e: KeyError, context: impl std::fmt::Display) -> Error {
        let message = format!("{context}: {}", chain(&e));
        match key_class(&e) {
            Class::Integrity(failure) => Error::Integrity { failure, message },
            Class::Unsupported => Error::unsupported(message),
            _ => Error::Other { message },
        }
    }

    /// An audit chain that does not verify. A row naming an action or actor
    /// this client does not know is not a verdict on the chain: it is
    /// `unsupported_by_client`, and nothing is recorded.
    pub(crate) fn audit_chain(e: ChainError, context: impl std::fmt::Display) -> Error {
        let message = format!("{context}: {}", chain(&e));
        match e {
            ChainError::UnknownValue { .. } => Error::unsupported(message),
            ChainError::HeadMismatch => Error::Integrity {
                failure: IntegrityFailure::BindingMismatch("audit head"),
                message,
            },
            _ => Error::Integrity {
                failure: IntegrityFailure::AuditMismatch,
                message,
            },
        }
    }

    /// A request that did not succeed. A refusal or a transport failure is
    /// labelled with `label`; an answer that did not decode is not.
    pub(crate) fn api(e: ApiError, label: Option<&str>) -> Error {
        let labelled = |m: String| match label {
            Some(l) => format!("{l}: {m}"),
            None => m,
        };
        match &e {
            ApiError::Transport(t) => Error::Transport {
                server: t.server().to_owned(),
                message: labelled(t.to_string()),
                source: t.cause().unwrap_or_else(|| Arc::new(t.clone())),
            },
            ApiError::UnsupportedProtocol { .. } => Error::Invalid {
                code: code::UNSUPPORTED_PROTOCOL,
                message: labelled(e.to_string()),
            },
            ApiError::Refused { status, .. } => {
                let code = e.stable_code();
                let message = labelled(e.to_string());
                match kind_of(&code) {
                    ErrorKind::Auth => Error::Auth { code, message },
                    ErrorKind::Forbidden => Error::Forbidden { message },
                    ErrorKind::NotFound => Error::NotFound { message },
                    _ => Error::Server {
                        code,
                        status: *status,
                        message,
                    },
                }
            }
            _ => Error::Other {
                message: e.to_string(),
            },
        }
    }

    /// A store failure.
    pub(crate) fn store(e: StoreError) -> Error {
        Error::Store {
            message: e.message().to_owned(),
            source: Arc::new(e),
        }
    }

    #[cfg(feature = "http")]
    pub(crate) fn build(e: crate::client::BuildError) -> Error {
        match e {
            crate::client::BuildError::InvalidServer(m) => Error::local(code::INVALID_SERVER, m),
            other => Error::local(code::INVALID_PROXY, other.to_string()),
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Transport { source, .. } => Some(&**source),
            Error::Store { source, .. } => Some(&**source),
            _ => None,
        }
    }
}

/// An error and its sources, `: `-separated (what `anyhow`'s `{:#}` gave).
pub(crate) fn chain(e: &dyn std::error::Error) -> String {
    let mut out = e.to_string();
    let mut cur = e.source();
    while let Some(s) = cur {
        out.push_str(": ");
        out.push_str(&s.to_string());
        cur = s.source();
    }
    out
}

enum Class {
    Integrity(IntegrityFailure),
    Stale,
    Unsupported,
    Other,
}

fn key_class(e: &KeyError) -> Class {
    match e {
        KeyError::Integrity(i) => Class::Integrity(IntegrityFailure::from(i)),
        KeyError::Binding(w) => Class::Integrity(IntegrityFailure::BindingMismatch(w)),
        KeyError::NameMismatch => {
            Class::Integrity(IntegrityFailure::BindingMismatch("record name"))
        }
        KeyError::Kind { .. } => Class::Integrity(IntegrityFailure::BindingMismatch("bundle kind")),
        KeyError::UnsupportedScope(_) => Class::Unsupported,
        _ => Class::Other,
    }
}

fn seal_class(e: &SealError) -> Class {
    match e {
        SealError::Integrity(i) => Class::Integrity(IntegrityFailure::from(i)),
        SealError::Key(k) => key_class(k),
        SealError::Binding(w) => Class::Integrity(IntegrityFailure::BindingMismatch(w)),
        SealError::NameMismatch => {
            Class::Integrity(IntegrityFailure::BindingMismatch("record name"))
        }
        SealError::KindMismatch { .. } => {
            Class::Integrity(IntegrityFailure::BindingMismatch("record kind"))
        }
        SealError::StaleGeneration { .. } => Class::Stale,
        SealError::UnsupportedByClient(_) => Class::Unsupported,
        _ => Class::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_map_to_kinds() {
        assert_eq!(kind_of("token_expired"), ErrorKind::Auth);
        assert_eq!(kind_of(code::INVALID_TOKEN), ErrorKind::Auth);
        assert_eq!(kind_of("precondition_failed"), ErrorKind::Conflict);
        assert_eq!(kind_of("version_mismatch"), ErrorKind::Conflict);
        assert_eq!(kind_of(code::STALE_GENERATION), ErrorKind::Conflict);
        assert_eq!(kind_of(code::CREDENTIAL_LITERAL), ErrorKind::Invalid);
        assert_eq!(kind_of(code::UNKNOWN_PATH), ErrorKind::Invalid);
        for c in [
            code::BAD_SIGNATURE,
            code::KEY_MISMATCH,
            code::VERSION_ROLLBACK,
            code::GENERATION_ROLLBACK,
            code::AUDIT_MISMATCH,
        ] {
            assert_eq!(kind_of(c), ErrorKind::Integrity, "{c}");
        }
        assert_eq!(Error::forbidden("x").code(), code::FORBIDDEN);
    }

    /// Every protocol code this crate classifies, named through [`ErrorCode`]
    /// rather than a copy of its wire string: a rename in
    /// `galata-vault-proto` fails here instead of quietly becoming
    /// [`ErrorKind::Other`].
    #[test]
    fn protocol_codes_classify_through_their_type() {
        for (c, kind) in [
            (ErrorCode::Unauthorized, ErrorKind::Auth),
            (ErrorCode::TokenExpired, ErrorKind::Auth),
            (ErrorCode::Forbidden, ErrorKind::Forbidden),
            (ErrorCode::NotFound, ErrorKind::NotFound),
            (ErrorCode::PreconditionFailed, ErrorKind::Conflict),
            (ErrorCode::Conflict, ErrorKind::Conflict),
            (ErrorCode::StaleGeneration, ErrorKind::Conflict),
            (ErrorCode::VersionMismatch, ErrorKind::Conflict),
            (ErrorCode::BadSignature, ErrorKind::Integrity),
            (ErrorCode::KeyMismatch, ErrorKind::Integrity),
            (ErrorCode::VersionRollback, ErrorKind::Integrity),
            (ErrorCode::GenerationRollback, ErrorKind::Integrity),
        ] {
            assert_eq!(kind_of(c.as_str()), kind, "{c}");
        }
        // A protocol code this crate does not classify keeps the general
        // kind, as before; `Error::kind` reads the status class instead.
        assert_eq!(kind_of(ErrorCode::RateLimited.as_str()), ErrorKind::Other);
        assert_eq!(kind_of(ErrorCode::Unavailable.as_str()), ErrorKind::Other);
    }

    #[test]
    fn integrity_failures_keep_their_code_through_context() {
        let e = Error::seal(
            SealError::Integrity(IntegrityError::BadSignature("record")),
            "acme/dev: version 2 of DB",
        );
        assert_eq!(
            (e.code(), e.kind()),
            (code::BAD_SIGNATURE, ErrorKind::Integrity)
        );
        assert!(e.message().starts_with("acme/dev: version 2 of DB"), "{e}");
        assert!(matches!(
            e,
            Error::Integrity {
                failure: IntegrityFailure::BadSignature("record"),
                ..
            }
        ));
        let stale = Error::seal(
            SealError::StaleGeneration {
                bundle: 1,
                vault: 2,
            },
            "a",
        );
        assert_eq!(stale.code(), code::STALE_GENERATION);
    }

    #[test]
    fn a_conflict_carries_both_versions() {
        let e = Error::conflict("app", Pre::Update(7), Some(8), false);
        assert!(matches!(
            e,
            Error::Conflict {
                expected: Expected::Version(7),
                current: Some(8),
                ..
            }
        ));
        assert_eq!(e.code(), code::CONFLICT);
        assert_eq!(
            e.message(),
            "app changed on the server: expected version 7, the server has version 8; nothing was overwritten"
        );
        assert_eq!(e.clone().context("acme/dev").kind(), ErrorKind::Conflict);
    }

    /// A code from a newer server keeps its string and the server's message,
    /// and takes its kind from the status class.
    #[test]
    fn an_unknown_server_code_keeps_its_code_message_and_status_kind() {
        let body = br#"{"error":"future_conflict","message":"try again later"}"#;
        let transport = crate::client::RecordingTransport::responding(move |_| {
            Ok(crate::client::Response::new(409, body.to_vec()))
        });
        let e = crate::client::Api::new(transport)
            .status(crate::client::Auth::None)
            .unwrap_err();
        let e = Error::api(e, Some("acme/dev"));
        assert_eq!(e.code(), "future_conflict");
        assert_eq!(e.kind(), ErrorKind::Conflict);
        assert!(e.message().contains("try again later"), "{e}");
        assert_eq!(kind_of_status(401), ErrorKind::Auth);
        assert_eq!(kind_of_status(418), ErrorKind::Other);
        assert_eq!(kind_of(code::UNSUPPORTED_BY_CLIENT), ErrorKind::Invalid);
        assert_eq!(kind_of(code::UNSUPPORTED_PROTOCOL), ErrorKind::Invalid);
    }

    #[test]
    fn an_error_is_shareable() {
        fn shared<T: Send + Sync + Clone + std::error::Error>() {}
        shared::<Error>();
    }

    #[test]
    fn a_transport_failure_keeps_its_cause() {
        let io = std::io::Error::new(std::io::ErrorKind::ConnectionRefused, "refused");
        let t = crate::client::TransportError::with_source("https://vault.example", io);
        let e = Error::api(ApiError::Transport(t), Some("acme/dev"));
        assert_eq!(e.code(), code::UNREACHABLE);
        assert!(e.message().starts_with("acme/dev: could not reach"), "{e}");
        let source = std::error::Error::source(&e).expect("a cause");
        assert!(source.downcast_ref::<std::io::Error>().is_some());
    }
}
