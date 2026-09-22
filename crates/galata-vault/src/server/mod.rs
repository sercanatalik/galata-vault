//! The galata-vault HTTP server (`/v1`): an axum shell over
//! `galata-vault-server-core`.
//!
//! The rules live in the core. This crate turns an HTTP request into the
//! core's canonical request (method, path and query, `Authorization`,
//! `If-Match`, `If-None-Match`, and the body under the body limit), calls the
//! core on the blocking pool, and turns its answer back into a status,
//! `ETag`, `X-GV-Expires-At` and a JSON body. What stays here is HTTP: the
//! no-render headers and the refusal of credentials in query strings
//! (`hygiene`), the loopback/TLS-proxy rule, `healthz` and `readyz`, `local`
//! mode and `check`.
//!
//! **It cannot read what it stores.** It links `galata-vault-proto`, `galata-vault-store` and
//! `galata-vault-server-core`, and never `galata-vault-keys`, `galata-vault-seal`, `age` or `crypto_box`,
//! so no code path in this binary can unseal a bundle or decrypt a value.
//! `scripts/check-server-linkage.sh` reads the resolved dependency graph and
//! fails the build if that ever stops being true.
//!
//! Every call addresses exactly one vault, chosen by the caller's credential.
//! The server knows nothing of projects, paths or names.
//!
//! There is one build, with no feature that changes what it enforces. It
//! admits every request it can authenticate, subject to the per-vault quotas:
//! it asks for no proof of work, limits no request, serves no metrics, and
//! never deletes a vault for inactivity. A configuration that asks for any of
//! those is refused at startup, naming the setting (`config`).

pub mod config;
mod error;
mod hygiene;
pub mod journal;
pub mod local;
mod state;

pub use crate::server_core::{Clock, Core, Policy, SystemClock, replay_journal};
pub use config::ServerConfig;
pub use error::ApiError;
pub use state::AppState;

use crate::proto::api::ErrorCode;
use crate::server_core::{CoreError, ROUTES, RouteId, Served};
use axum::Router;
use axum::extract::{Request, State};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::get;

/// Announces when the caller's vault expires, on every answer after
/// authentication, when the policy has an idle-expiry window. This server has
/// none, so it never sends it; a core with another policy may.
pub const EXPIRES_HEADER: &str = "x-gv-expires-at";

/// The whole HTTP surface, from the core's route table
/// (`crate::server_core::ROUTES`): the shell's own endpoints (`healthz`
/// and `readyz`) are routed here; every other path goes to the core, which
/// routes it by the same table and answers unknown ones with 404.
pub fn router(state: AppState) -> Router {
    let mut router = Router::new();
    for route in ROUTES.iter().filter(|r| r.served == Served::Shell) {
        debug_assert_eq!(route.method, "GET", "the shell serves GET only");
        router = match route.id {
            RouteId::Healthz => router.route(route.path, get(health)),
            RouteId::Readyz => router.route(route.path, get(ready)),
            _ => router,
        };
    }
    router
        .fallback(to_core)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn(hygiene::hygiene))
        .with_state(state)
}

/// Every request the shell does not answer itself: its body, read up to the
/// body limit, and its canonical parts, handed to the core.
async fn to_core(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = match axum::body::to_bytes(body, state.config().body_limit()).await {
        Ok(body) => body,
        Err(_) => {
            return ApiError::new(ErrorCode::ValueTooLarge, "the request body is too large")
                .into_response();
        }
    };
    error::into_http(state.call(parts, body).await)
}

async fn health() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

/// Red while the journal is unreachable: critical operations would all fail,
/// so the load balancer should stop sending new traffic here.
async fn ready(State(state): State<AppState>) -> Response {
    if state.journal_ready().await {
        axum::Json(serde_json::json!({ "status": "ready" })).into_response()
    } else {
        ApiError::new(ErrorCode::Unavailable, "the journal is unreachable").into_response()
    }
}

async fn method_not_allowed() -> ApiError {
    CoreError::method_not_allowed().into()
}
