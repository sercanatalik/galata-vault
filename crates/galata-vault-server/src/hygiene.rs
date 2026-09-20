//! Applied to every request and every response, before any handler runs.
//!
//! * A credential in the query string is refused with 400 and never
//!   processed: URLs end up in proxy logs, browser history and referrers.
//! * Every response says: do not sniff it, do not render it, do not frame
//!   it, do not cache it.

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header::{
    CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use galata_vault_proto::api::ErrorCode;

use crate::error::ApiError;

const CREDENTIAL_KEYS: &[&str] = &[
    "token",
    "access_token",
    "auth",
    "authorization",
    "sig",
    "signature",
    "key",
    "secret",
];

pub(crate) fn carries_credential(query: &str) -> bool {
    let lower = query.to_ascii_lowercase();
    if ["gvt1_", "gvk1_", "gvt1%5f", "gvk1%5f"]
        .iter()
        .any(|p| lower.contains(p))
    {
        return true;
    }
    lower.split('&').any(|pair| {
        let key = pair.split('=').next().unwrap_or("");
        CREDENTIAL_KEYS.contains(&key)
    })
}

pub(crate) async fn hygiene(req: Request, next: Next) -> Response {
    let refused = req.uri().query().is_some_and(carries_credential);
    let mut response = if refused {
        ApiError::new(
            ErrorCode::CredentialInQuery,
            "credentials are accepted only in the Authorization header",
        )
        .into_response()
    } else {
        next.run(req).await
    };
    let h = response.headers_mut();
    h.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    h.insert(
        CONTENT_SECURITY_POLICY,
        HeaderValue::from_static("default-src 'none'; frame-ancestors 'none'"),
    );
    h.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    h.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    h.insert(X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    response
}

#[cfg(test)]
mod tests {
    use super::carries_credential;

    #[test]
    fn credential_shapes_in_queries() {
        for q in [
            "token=abc",
            "a=1&Access_Token=x",
            "sig=1",
            "x=gvt1_AAAA",
            "x=GVK1_aaaa",
            "x=gvt1%5FAAAA",
        ] {
            assert!(carries_credential(q), "{q}");
        }
        for q in ["after=5", "limit=10&after=ab", "cursor=deadbeef"] {
            assert!(!carries_credential(q), "{q}");
        }
    }
}
