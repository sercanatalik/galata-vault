//! Read one secret with a token.
//!
//! ```text
//! GV_SERVER=https://vault.example GV_TOKEN_FILE=./token \
//!     cargo run -p galata-vault --example token_read -- DATABASE_URL
//! ```
//!
//! It prints the secret's version and length, never its value.

use galata_vault::Vault;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "DATABASE_URL".to_owned());
    // GV_SERVER, and exactly one of GV_TOKEN or GV_TOKEN_FILE.
    let vault = Vault::from_env()?;
    let secret = vault.secret(&name)?;
    println!(
        "{} is at version {} ({} bytes) in vault {}",
        secret.name(),
        secret.version(),
        secret.len(),
        vault.vault_id()
    );
    if let Some(at) = vault.expiry().token_expires_at {
        println!("the token expires at {at} (Unix seconds)");
    }
    Ok(())
}
