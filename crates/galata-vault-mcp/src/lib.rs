//! A metadata-only MCP server over stdio: `list_secrets`, `diff_envs`,
//! `audit` and `status`.
//!
//! **Its whole claim to safety is what it cannot do.** It holds only `meta`
//! tokens, whose bundles carry the name key and never the vault private key.
//! It also links no value-decryption code: `galata-vault-seal` and `age` are absent
//! from its dependency graph, and `scripts/check-mcp-linkage.sh` fails the
//! build if either appears. Its requests go through `galata-vault-client`, the one
//! client implementation the SDK also uses, which links neither.

pub mod config;
pub mod env;
pub mod tools;

pub use env::Env;
pub use tools::McpServer;

/// Verify every configured environment; the first refusal stops startup.
pub fn open_all(entries: Vec<config::Entry>) -> anyhow::Result<Vec<Env>> {
    entries.into_iter().map(Env::open).collect()
}
