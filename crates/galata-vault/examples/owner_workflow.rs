//! The owner's side, end to end: create a project, add an environment, write
//! a secret, mint a read token and read with it, then rotate.
//!
//! ```text
//! gv-server local &                      # or any galata-vault server
//! GV_SERVER=http://127.0.0.1:8750 cargo run -p galata-vault --example owner_workflow
//! ```
//!
//! Keys live in a small in-memory `KeyStore` (a product would use its own
//! secure storage; `gv` uses the OS keychain), and local state in a
//! `FileStateStore` under the system temp directory. The recovery kit is
//! printed to stderr: in real use, it is the only way to recover the project.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use galata_vault::owner::Owner;
use galata_vault::{EnvPath, FileStateStore, KeyName, KeyStore, Scope, StoreError, Vault};
use zeroize::Zeroizing;

/// Node keys in memory. They are gone when the process exits: only the
/// recovery kit survives.
#[derive(Default)]
struct MemoryKeys(Mutex<HashMap<String, Zeroizing<String>>>);

impl MemoryKeys {
    fn map(
        &self,
    ) -> Result<std::sync::MutexGuard<'_, HashMap<String, Zeroizing<String>>>, StoreError> {
        self.0
            .lock()
            .map_err(|_| StoreError::new("the key store lock is poisoned"))
    }
}

impl KeyStore for MemoryKeys {
    fn get(&self, key: &KeyName) -> Result<Option<Zeroizing<String>>, StoreError> {
        Ok(self.map()?.get(&key.entry()).cloned())
    }

    fn set(&self, key: &KeyName, value: &str) -> Result<(), StoreError> {
        self.map()?
            .insert(key.entry(), Zeroizing::new(value.to_owned()));
        Ok(())
    }

    fn delete(&self, key: &KeyName) -> Result<(), StoreError> {
        self.map()?.remove(&key.entry());
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let server = std::env::var("GV_SERVER")
        .map_err(|_| "set GV_SERVER to a galata-vault server (for example `gv-server local`)")?;
    let project = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("example{}", std::process::id()));
    let dir = std::env::temp_dir().join(format!("galata-vault-example-{}", std::process::id()));
    let mut owner = Owner::open(
        Arc::new(MemoryKeys::default()),
        Arc::new(FileStateStore::new(&dir)),
    )?;

    // Nothing reaches the server until the kit is acknowledged.
    let init = owner.begin_init(&project, &server)?;
    eprintln!(
        "store this recovery kit somewhere safe:\n{}",
        init.recovery_kit().render()?.as_str()
    );
    let info = init.confirm_kit_stored()?;
    println!("created project {} (vault {})", info.path, info.vault_id);

    let dev: EnvPath = format!("{project}/dev").parse()?;
    owner.env_add(&dev)?;
    let env = owner.environment(&dev)?;
    env.set_secret("DATABASE_URL", b"postgres://db/example")?;
    let token = env.mint(Scope::Read, 0, &[])?;
    owner.close(env)?;

    // The token is shown once: hand it to the application, then drop it.
    let reader = Vault::new(token.expose(), &server)?;
    drop(token);
    let db = reader.secret("DATABASE_URL")?;
    println!(
        "a read token sees DATABASE_URL at version {} ({} bytes)",
        db.version(),
        db.len()
    );

    let env = owner.environment(&dev)?;
    let generation = env.rotate()?;
    owner.close(env)?;
    println!(
        "rotated {dev} to generation {generation}; local state is in {}",
        dir.display()
    );
    Ok(())
}
