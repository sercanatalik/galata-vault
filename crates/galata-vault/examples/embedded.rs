//! A vault service inside this process, with no server: open a data
//! directory, create a project and an environment, set a secret, and read it
//! back through a read token.
//!
//! ```text
//! cargo run -p galata-vault --features embedded --example embedded -- /tmp/gv-embedded-example
//! ```
//!
//! Keys and local state live in memory here, so every run starts a new
//! project in the same directory. An application keeps them in the OS
//! keychain and a state file (`galata_vault::store`, `galata_vault::state`).

use std::path::PathBuf;
use std::sync::Arc;

use galata_vault::client::Api;
use galata_vault::owner::Owner;
use galata_vault::state::MemoryStateStore;
use galata_vault::store::MemoryKeyStore;
use galata_vault::{EnvPath, Scope, Vault, embedded};

/// Where the project is pinned: the address `gv-server local` serves the
/// same directory on, so the project can move to a local server unchanged.
const LOCAL_SERVER: &str = "http://127.0.0.1:8750";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("gv-embedded-example"));
    let api = Api::new(embedded::open(&dir)?);

    // The owner reaches its project's "server" through the embedded API.
    let connect = api.clone();
    let mut owner = Owner::open(
        Arc::new(MemoryKeyStore::new()),
        Arc::new(MemoryStateStore::new()),
    )?
    .with_connector(move |_server| Ok(connect.clone()));
    owner
        .begin_init("acme", LOCAL_SERVER)?
        .confirm_kit_stored()?;
    let path: EnvPath = "acme/dev".parse()?;
    owner.env_add(&path)?;

    let env = owner.environment(&path)?;
    let value = b"postgres://localhost/app";
    env.set_secret("DATABASE_URL", value)?;
    let token = env.mint(Scope::Read, 0, &[])?;
    owner.close(env)?;

    // What an application holding only the read token does.
    let vault = Vault::with_api(token.expose(), &api)?;
    let secret = vault.secret("DATABASE_URL")?;
    assert_eq!(secret.expose(), value);
    println!(
        "{}: DATABASE_URL read back ({} bytes) through a read token, with no server",
        dir.display(),
        secret.expose().len()
    );
    Ok(())
}
