//! Shared state, and the bridge from async handlers to the synchronous core.

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::HeaderName;
use axum::http::header::{AUTHORIZATION, IF_MATCH, IF_NONE_MATCH};
use axum::http::request::Parts;
use galata_vault_server_core::{
    Admission, AllowAll, CanonicalRequest, Clock, Core, CoreError, CoreResponse, Journal, Log,
    Policy,
};
use galata_vault_store::Store;

use crate::config::ServerConfig;

/// The core's reports, as log lines. Like every line this server writes,
/// they never carry a header, a body or an address.
struct TracingLog;

impl Log for TracingLog {
    fn error(&self, message: &str) {
        tracing::error!("{message}");
    }

    fn warn(&self, message: &str) {
        tracing::warn!("{message}");
    }
}

struct Inner {
    core: Core,
    config: ServerConfig,
}

#[derive(Clone)]
pub struct AppState(Arc<Inner>);

impl AppState {
    /// Validate `config`, open the core over `store` and `journal` with the
    /// policy the configuration asks for, and wrap it. The journal is
    /// replayed before this returns.
    pub fn new(
        store: Arc<dyn Store>,
        journal: Arc<dyn Journal>,
        config: ServerConfig,
        clock: Arc<dyn Clock>,
    ) -> anyhow::Result<AppState> {
        config.validate()?;
        // This server admits every request it can authenticate: the quotas
        // and the record preconditions are what bound a caller.
        let admission: Arc<dyn Admission> = Arc::new(AllowAll);
        let policy = Policy {
            admission,
            // No vault expires for inactivity, so the capabilities report
            // `idle_expiry_days` as null and no answer carries an expiry.
            idle_expiry_days: None,
            limits: config.limits,
            server: config.advertised_server(),
        };
        let core = Core::open(store, journal, policy, clock)?;
        Ok(AppState::assemble(core, config))
    }

    /// Serve a core that is already open, whatever its policy. The
    /// configuration supplies only what HTTP needs: the body limit and the
    /// proxy setting. For tests and embedders that need a policy no
    /// configuration file can ask for.
    pub fn from_core(core: Core, config: ServerConfig) -> AppState {
        AppState::assemble(core, config)
    }

    fn assemble(core: Core, config: ServerConfig) -> AppState {
        AppState(Arc::new(Inner {
            core: core.with_log(Arc::new(TracingLog)),
            config,
        }))
    }

    pub fn config(&self) -> &ServerConfig {
        &self.0.config
    }

    pub fn core(&self) -> &Core {
        &self.0.core
    }

    /// One request through the core, on the blocking pool: the store and the
    /// journal are synchronous. What the core logs goes where the request's
    /// own log lines go.
    pub(crate) async fn call(&self, parts: Parts, body: Bytes) -> CoreResponse {
        let state = self.clone();
        let dispatch = tracing::dispatcher::get_default(Clone::clone);
        tokio::task::spawn_blocking(move || {
            let header = |name: HeaderName| parts.headers.get(name).and_then(|v| v.to_str().ok());
            let request = CanonicalRequest {
                method: parts.method.as_str(),
                path_and_query: parts.uri.path_and_query().map_or("/", |pq| pq.as_str()),
                authorization: header(AUTHORIZATION),
                if_match: header(IF_MATCH),
                if_none_match: header(IF_NONE_MATCH),
                body: &body,
            };
            tracing::dispatcher::with_default(&dispatch, || state.0.core.call(request))
        })
        .await
        .unwrap_or_else(|_| CoreError::internal().to_response())
    }

    /// Is the journal reachable right now?
    pub async fn journal_ready(&self) -> bool {
        let state = self.clone();
        tokio::task::spawn_blocking(move || state.0.core.journal_ready())
            .await
            .unwrap_or(false)
    }
}
