//! The four tools. Each returns JSON text built from names and metadata
//! only; the types involved cannot carry a value, and this crate cannot
//! decrypt one.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use galata_vault_proto::audit::{Actor, AuditResult};
use galata_vault_proto::time::rfc3339;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{CallToolResult, ContentBlock};
use rmcp::schemars::JsonSchema;
use rmcp::{ErrorData, ServerHandler, tool, tool_handler, tool_router};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::env::Env;

/// The most recent audit rows returned by `audit`.
const AUDIT_ROWS: usize = 50;

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct PathArgs {
    /// A configured environment path, e.g. `acme/prod`.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[schemars(crate = "rmcp::schemars")]
pub struct DiffArgs {
    /// The first environment path, e.g. `acme/staging`.
    pub path_a: String,
    /// The second environment path, e.g. `acme/prod`.
    pub path_b: String,
}

#[derive(Clone)]
pub struct McpServer {
    envs: Arc<BTreeMap<String, Arc<Env>>>,
}

fn reply(result: Result<Value, String>) -> CallToolResult {
    match result {
        Ok(v) => CallToolResult::success(vec![ContentBlock::text(
            serde_json::to_string_pretty(&v).unwrap_or_else(|_| "{}".into()),
        )]),
        Err(e) => CallToolResult::error(vec![ContentBlock::text(e)]),
    }
}

async fn blocking(f: impl FnOnce() -> Result<Value, String> + Send + 'static) -> CallToolResult {
    match tokio::task::spawn_blocking(f).await {
        Ok(result) => reply(result),
        Err(_) => reply(Err("the request failed unexpectedly".into())),
    }
}

fn actor_text(actor: &Actor) -> String {
    match actor {
        Actor::Owner => "owner".into(),
        Actor::Token(id) => format!("token {}", id.to_hex()),
        other => format!("{other:?}"),
    }
}

impl McpServer {
    pub fn new(envs: Vec<Env>) -> McpServer {
        McpServer {
            envs: Arc::new(
                envs.into_iter()
                    .map(|e| (e.path.to_string(), Arc::new(e)))
                    .collect(),
            ),
        }
    }

    pub fn paths(&self) -> Vec<String> {
        self.envs.keys().cloned().collect()
    }

    fn env(&self, path: &str) -> Result<Arc<Env>, String> {
        self.envs.get(path).cloned().ok_or_else(|| {
            format!(
                "no token is configured for {path:?}; configured paths: {}",
                self.paths().join(", ")
            )
        })
    }

    pub fn list_secrets_json(&self, path: &str) -> Result<Value, String> {
        let env = self.env(path)?;
        let names = env.names()?;
        Ok(json!({
            "path": path,
            "count": names.len(),
            "secrets": names.iter().map(|n| json!({
                "name": n.name,
                "version": n.version,
                "updated_at": rfc3339(n.updated_at),
                "size_bytes": n.size,
            })).collect::<Vec<_>>(),
        }))
    }

    /// Two independent listings, each with its own environment's token,
    /// compared here. The server never learns the two are related.
    pub fn diff_json(&self, path_a: &str, path_b: &str) -> Result<Value, String> {
        let (a, b) = (self.env(path_a)?, self.env(path_b)?);
        let set = |env: &Env| -> Result<BTreeSet<String>, String> {
            Ok(env.names()?.into_iter().map(|n| n.name).collect())
        };
        let (sa, sb) = (set(&a)?, set(&b)?);
        let mut missing = serde_json::Map::new();
        missing.insert(
            path_a.to_owned(),
            json!(sb.difference(&sa).collect::<Vec<_>>()),
        );
        missing.insert(
            path_b.to_owned(),
            json!(sa.difference(&sb).collect::<Vec<_>>()),
        );
        Ok(json!({
            "path_a": path_a,
            "path_b": path_b,
            "missing_from": missing,
            "in_both": sa.intersection(&sb).collect::<Vec<_>>(),
        }))
    }

    pub fn audit_json(&self, path: &str) -> Result<Value, String> {
        let env = self.env(path)?;
        let names: HashMap<_, _> = env.names()?.into_iter().map(|n| (n.hmac, n.name)).collect();
        let (rows, verdict) = env.audit()?;
        let recent = &rows[rows.len().saturating_sub(AUDIT_ROWS)..];
        Ok(json!({
            "path": path,
            "chain": match &verdict {
                Ok(None) => "verified".to_owned(),
                Ok(Some(note)) => format!("verified up to a newer row format: {note}"),
                Err(e) => format!("VERIFICATION FAILED: {e}"),
            },
            "total_rows": rows.len(),
            "rows": recent.iter().map(|r| json!({
                "seq": r.seq,
                "time": rfc3339(r.ts),
                "actor": actor_text(&r.actor),
                "action": serde_json::to_value(r.action).unwrap_or(Value::Null),
                "name": r.name_hmac.map(|h| names.get(&h).cloned()
                    .unwrap_or_else(|| format!("(unknown or deleted #{})", &h.to_hex()[..8]))),
                "refused": r.result == AuditResult::Refused,
            })).collect::<Vec<_>>(),
        }))
    }

    pub fn status_json(&self, path: &str) -> Result<Value, String> {
        let env = self.env(path)?;
        let (s, me) = env.status()?;
        Ok(json!({
            "path": path,
            "generation": s.generation,
            "created_at": rfc3339(s.created_at),
            "last_active_at": rfc3339(s.last_active_at),
            // null when the server expires no vault for inactivity
            "expires_at": s.expires_at.map(rfc3339),
            "bytes_used": s.bytes_used,
            "limits": {
                "max_names": s.limits.max_names,
                "max_value_bytes": s.limits.max_value_bytes,
                "max_versions": s.limits.max_versions,
                "max_vault_bytes": s.limits.max_vault_bytes,
                "max_tokens": s.limits.max_tokens,
            },
            "this_token": {
                "id": me.token_id.to_hex(),
                "scope": me.scope.to_string(),
                "expires_at": rfc3339(me.expires_at),
            },
        }))
    }
}

#[tool_router(vis = "pub")]
impl McpServer {
    /// List the secret names in one environment, with each one's version,
    /// last-updated time and ciphertext size. Values are never available.
    #[tool(annotations(read_only_hint = true))]
    async fn list_secrets(
        &self,
        Parameters(PathArgs { path }): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let me = self.clone();
        Ok(blocking(move || me.list_secrets_json(&path)).await)
    }

    /// Compare two environments' secret names: which names each is missing.
    #[tool(annotations(read_only_hint = true))]
    async fn diff_envs(
        &self,
        Parameters(DiffArgs { path_a, path_b }): Parameters<DiffArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let me = self.clone();
        Ok(blocking(move || me.diff_json(&path_a, &path_b)).await)
    }

    /// Recent audit-log rows for one environment, with names decrypted where
    /// possible and the hash chain verified.
    #[tool(annotations(read_only_hint = true))]
    async fn audit(
        &self,
        Parameters(PathArgs { path }): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let me = self.clone();
        Ok(blocking(move || me.audit_json(&path)).await)
    }

    /// One environment's expiry, quota use, generation and the configured
    /// token's own scope and expiry.
    #[tool(annotations(read_only_hint = true))]
    async fn status(
        &self,
        Parameters(PathArgs { path }): Parameters<PathArgs>,
    ) -> Result<CallToolResult, ErrorData> {
        let me = self.clone();
        Ok(blocking(move || me.status_json(&path)).await)
    }
}

#[tool_handler(
    name = "galata-vault",
    version = "0.1.0",
    instructions = "Metadata about galata-vault environments: secret names, versions, audit logs and status. Secret values are never available through this server."
)]
impl ServerHandler for McpServer {}
