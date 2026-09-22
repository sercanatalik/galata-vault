//! The journal a server writes its critical operations to.
//!
//! The [`Journal`] trait and the [`FileJournal`] live in `galata-vault-server-core`,
//! which writes to them inside the store's transaction; they are re-exported
//! here. A directory beside the database is the only journal this server
//! writes: it undoes a restored older copy of the database, and does not
//! survive the loss of the disk the two share.

use std::sync::Arc;

pub use crate::server_core::journal::{FileJournal, Journal};

use crate::server::config::JournalConfig;

/// Open the configured journal. A bucket is refused: the configuration check
/// names it first, and this is the same answer if one ever reaches here.
pub fn open(config: &JournalConfig) -> Result<Arc<dyn Journal>, String> {
    match config {
        JournalConfig::File { dir } => Ok(Arc::new(FileJournal::open(dir)?)),
        JournalConfig::Other(kind) => Err(format!(
            "a {kind:?} journal is no longer supported: this server journals to a directory \
             beside its database"
        )),
    }
}
