//! A config document edited safely: read it, change it, and write it back
//! only if nobody wrote in between (`expect_version`).
//!
//! ```text
//! gv token mint --scope config-write --env acme/dev   # or admin
//! GV_SERVER=http://127.0.0.1:8750 GV_TOKEN=gvt1_… \
//!     cargo run -p galata-vault --example config_document
//! ```
//!
//! The first run creates `app` (a TOML document); later runs bump its
//! `revision`. A concurrent edit makes the write fail with `Conflict`, naming
//! both versions, and nothing is overwritten: read again and retry.

use galata_vault::{Error, NewConfig, Vault};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // GV_SERVER, and exactly one of GV_TOKEN or GV_TOKEN_FILE.
    let vault = Vault::from_env()?;

    let written = match vault.config("app") {
        Ok(doc) => {
            let mut table: toml::Table = doc.deserialize()?;
            let revision = table
                .get("revision")
                .and_then(toml::Value::as_integer)
                .unwrap_or(0);
            table.insert("revision".into(), toml::Value::Integer(revision + 1));
            // Refused before any request if the body does not parse or holds
            // a credential literal; refused by the server if `app` moved on.
            let edit = NewConfig::toml(toml::to_string(&table)?).expect_version(doc.version());
            vault.set_config("app", edit)
        }
        Err(e) if e.code() == galata_vault::code::NOT_FOUND => {
            vault.set_config("app", NewConfig::toml("revision = 1\n"))
        }
        Err(e) => return Err(e.into()),
    };

    match written {
        Ok(version) => println!("app is now at version {version}"),
        Err(Error::Conflict {
            expected, current, ..
        }) => {
            println!(
                "someone else wrote app first (expected {expected:?}, now {current:?}); nothing was overwritten"
            )
        }
        Err(e) => return Err(e.into()),
    }
    Ok(())
}
