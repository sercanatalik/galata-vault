//! Answers as HTTP responses: a core answer, or an error the shell raises
//! itself (a body over the limit, a credential in the query string). Either
//! way: a stable code, a human message, never the request body, a token,
//! ciphertext or a client address.

use std::borrow::Cow;

use axum::http::header::{CONTENT_TYPE, ETAG, RETRY_AFTER};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use galata_vault_proto::api::ErrorCode;
use galata_vault_server_core::{CoreError, CoreResponse};

use crate::EXPIRES_HEADER;

/// An error the shell answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError(pub CoreError);

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<Cow<'static, str>>) -> ApiError {
        ApiError(CoreError::new(code, message))
    }
}

impl From<CoreError> for ApiError {
    fn from(e: CoreError) -> ApiError {
        ApiError(e)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let Some(detail) = self.0.detail() {
            tracing::error!("{detail}");
        }
        into_http(self.0.to_response())
    }
}

/// A core answer as an HTTP response: the status, a JSON body, and the
/// headers the protocol reads.
pub(crate) fn into_http(answer: CoreResponse) -> Response {
    let status = StatusCode::from_u16(answer.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = (
        status,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
        answer.body,
    )
        .into_response();
    let headers = response.headers_mut();
    if let Some(version) = answer.etag {
        headers.insert(ETAG, version_tag(version));
    }
    if let Some(at) = answer.expires_at {
        headers.insert(EXPIRES_HEADER, HeaderValue::from(at));
    }
    if let Some(secs) = answer.retry_after {
        headers.insert(RETRY_AFTER, HeaderValue::from(secs));
    }
    response
}

/// `"<version>"`: digits and quotes, always a valid header value.
fn version_tag(version: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"{version}\"")).expect("digits and quotes are a valid header")
}
