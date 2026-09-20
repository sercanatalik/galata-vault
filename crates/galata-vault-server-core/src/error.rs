//! Every error the core answers with: a stable code, a human message, never
//! the request body, a token, ciphertext or a client address.

use std::borrow::Cow;

use galata_vault_proto::api::{ErrorBody, ErrorCode};
use galata_vault_proto::integrity::IntegrityError;
use galata_vault_store::{Quota, StoreError};

use crate::CoreResponse;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoreError {
    pub code: ErrorCode,
    pub message: Cow<'static, str>,
    /// Seconds, for 429.
    pub retry_after: Option<u64>,
    /// For the operator's log, never for the caller: what went wrong behind
    /// an `internal` or `unavailable` answer.
    detail: Option<String>,
}

impl std::fmt::Display for CoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}: {}", self.code, self.message)
    }
}

impl std::error::Error for CoreError {}

impl CoreError {
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> CoreError {
        CoreError {
            code,
            message: message.into(),
            retry_after: None,
            detail: None,
        }
    }

    /// The one answer for every authentication failure: unknown token,
    /// revoked token, expired vault, bad or replayed signature, a bearer or
    /// v1 credential.
    pub fn unauthorized() -> CoreError {
        CoreError::new(ErrorCode::Unauthorized, "authentication failed")
    }

    pub fn forbidden() -> CoreError {
        CoreError::new(
            ErrorCode::Forbidden,
            "this credential's scope does not allow that",
        )
    }

    pub fn invalid(message: impl Into<Cow<'static, str>>) -> CoreError {
        CoreError::new(ErrorCode::InvalidRequest, message)
    }

    pub fn internal() -> CoreError {
        CoreError::new(ErrorCode::Internal, "internal error")
    }

    /// A path this server does not serve.
    pub fn no_endpoint() -> CoreError {
        CoreError::new(ErrorCode::NotFound, "no such endpoint")
    }

    /// A path this server serves, with a method it does not.
    pub fn method_not_allowed() -> CoreError {
        CoreError::invalid("method not allowed on this endpoint")
    }

    pub fn rate_limited(retry_after: u64) -> CoreError {
        CoreError {
            retry_after: Some(retry_after),
            ..CoreError::new(
                ErrorCode::RateLimited,
                "too many requests; retry after the indicated delay",
            )
        }
    }

    /// The same error, with `detail` for the operator's log.
    pub fn logged(mut self, detail: impl Into<String>) -> CoreError {
        self.detail = Some(detail.into());
        self
    }

    /// What the operator's log should say about this error, if anything.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// The answer a caller receives: the status, the code, and a JSON
    /// `ErrorBody` with the message.
    pub fn to_response(&self) -> CoreResponse {
        let body = ErrorBody::new(self.code, self.message.clone().into_owned());
        CoreResponse {
            status: self.code.status(),
            error: Some(self.code),
            etag: None,
            expires_at: None,
            retry_after: self.retry_after,
            body: serde_json::to_vec(&body).unwrap_or_default(),
        }
    }
}

/// A descriptor, bundle, record or children signature that does not verify,
/// or a key that does not match: refused before anything is stored.
impl From<IntegrityError> for CoreError {
    fn from(e: IntegrityError) -> CoreError {
        let code = match e {
            IntegrityError::KeyMismatch(_) => ErrorCode::KeyMismatch,
            IntegrityError::Malformed(_) => ErrorCode::InvalidRequest,
            _ => ErrorCode::BadSignature,
        };
        CoreError::new(code, e.to_string())
    }
}

impl From<StoreError> for CoreError {
    fn from(e: StoreError) -> CoreError {
        use ErrorCode as C;
        match e {
            StoreError::NotFound => CoreError::new(C::NotFound, "not found"),
            StoreError::Exists => CoreError::new(C::Conflict, "already exists"),
            StoreError::PreconditionFailed { current } => CoreError::new(
                C::PreconditionFailed,
                match current {
                    Some(v) => format!("precondition failed: the current version is {v}"),
                    None => "precondition failed: there is no current version".to_owned(),
                },
            ),
            StoreError::VersionMismatch { signed, assigned } => CoreError::new(
                C::VersionMismatch,
                format!("the write signs version {signed}, but it would create version {assigned}"),
            ),
            StoreError::StaleGeneration => CoreError::new(
                C::StaleGeneration,
                "written for a stale key generation; fetch the current descriptor and bundle",
            ),
            StoreError::Conflict => CoreError::new(
                C::Conflict,
                "the vault changed since this batch was built; rebuild it",
            ),
            StoreError::IncompleteRotation(why) => CoreError::new(C::IncompleteRotation, why),
            StoreError::Quota(Quota::Names) => {
                CoreError::new(C::NameQuotaExceeded, "the vault has reached its name quota")
            }
            StoreError::Quota(Quota::ValueSize) => CoreError::new(
                C::ValueTooLarge,
                "the value is larger than the per-value quota",
            ),
            StoreError::Quota(Quota::VaultBytes) => CoreError::new(
                C::VaultQuotaExceeded,
                "the vault has reached its storage quota",
            ),
            StoreError::Quota(Quota::Tokens) => CoreError::new(
                C::TokenQuotaExceeded,
                "the vault has reached its token quota",
            ),
            StoreError::Quota(Quota::Configs) => CoreError::new(
                C::ConfigQuotaExceeded,
                "the vault has reached its config quota",
            ),
            StoreError::Quota(Quota::ConfigSize) => CoreError::new(
                C::ConfigTooLarge,
                "the config is larger than the per-config quota",
            ),
            StoreError::Spent => CoreError::new(C::ChallengeReused, "already used"),
            StoreError::Journal(detail) => CoreError::new(
                C::Unavailable,
                "the operation could not be made durable, so it was not applied; retry",
            )
            .logged(format!(
                "journal write failed; operation rolled back: {detail}"
            )),
            StoreError::NotWal(_) | StoreError::Database(_) | StoreError::NewerSchema { .. } => {
                CoreError::internal().logged(format!("storage error: {e}"))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every store and integrity failure maps to one stable code, with the
    /// status the HTTP shell sends, and only failures the caller cannot act
    /// on carry a detail for the log.
    #[test]
    fn every_failure_maps_to_its_code() {
        use ErrorCode as C;
        let store = [
            (StoreError::NotFound, C::NotFound, 404),
            (StoreError::Exists, C::Conflict, 409),
            (
                StoreError::PreconditionFailed { current: Some(3) },
                C::PreconditionFailed,
                412,
            ),
            (
                StoreError::VersionMismatch {
                    signed: 1,
                    assigned: 2,
                },
                C::VersionMismatch,
                409,
            ),
            (StoreError::StaleGeneration, C::StaleGeneration, 409),
            (StoreError::Conflict, C::Conflict, 409),
            (
                StoreError::IncompleteRotation("a token is missing"),
                C::IncompleteRotation,
                422,
            ),
            (StoreError::Quota(Quota::Names), C::NameQuotaExceeded, 422),
            (StoreError::Quota(Quota::ValueSize), C::ValueTooLarge, 413),
            (
                StoreError::Quota(Quota::VaultBytes),
                C::VaultQuotaExceeded,
                422,
            ),
            (StoreError::Quota(Quota::Tokens), C::TokenQuotaExceeded, 422),
            (
                StoreError::Quota(Quota::Configs),
                C::ConfigQuotaExceeded,
                422,
            ),
            (StoreError::Quota(Quota::ConfigSize), C::ConfigTooLarge, 413),
            (StoreError::Spent, C::ChallengeReused, 409),
            (StoreError::Journal("down".into()), C::Unavailable, 503),
            (
                StoreError::NewerSchema { found: 2, known: 1 },
                C::Internal,
                500,
            ),
        ];
        for (from, code, status) in store {
            let logged = matches!(
                from,
                StoreError::Journal(_) | StoreError::NewerSchema { .. }
            );
            let e = CoreError::from(from);
            assert_eq!((e.code, e.code.status()), (code, status), "{e}");
            assert_eq!(e.detail().is_some(), logged, "{e}");
            let response = e.to_response();
            assert_eq!(response.status, status);
            assert_eq!(response.error, Some(code));
            let body: ErrorBody = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body.error, code);
            if let Some(detail) = e.detail() {
                assert!(
                    !body.message.contains(detail),
                    "a detail never reaches the caller"
                );
            }
        }

        let integrity = [
            (IntegrityError::KeyMismatch("descriptor"), C::KeyMismatch),
            (IntegrityError::Malformed("descriptor"), C::InvalidRequest),
            (IntegrityError::BadSignature("bundle"), C::BadSignature),
        ];
        for (from, code) in integrity {
            assert_eq!(CoreError::from(from).code, code);
        }
    }

    #[test]
    fn the_uniform_and_routing_errors() {
        assert_eq!(CoreError::unauthorized().to_response().status, 401);
        assert_eq!(CoreError::forbidden().to_response().status, 403);
        assert_eq!(CoreError::no_endpoint().code, ErrorCode::NotFound);
        assert_eq!(
            CoreError::method_not_allowed().code,
            ErrorCode::InvalidRequest
        );
        let limited = CoreError::rate_limited(7).to_response();
        assert_eq!((limited.status, limited.retry_after), (429, Some(7)));
    }
}
