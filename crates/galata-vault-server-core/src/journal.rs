//! The critical-operation journal.
//!
//! Revocation, rotation and vault deletion are acknowledged only once their
//! journal record is durable. Before the core serves anything, the records
//! newer than the database are replayed, so a database restored or copied
//! back from an older state cannot bring back a revoked token, undo a
//! rotation, or revive a deleted vault.
//!
//! [`FileJournal`], a directory beside the database, is what every caller
//! here opens: `gv-server`, local mode and the embedded transport. It undoes
//! a restored older copy of `vault.db`. It does not survive the loss of the
//! disk the two share, so the data directory must be backed up.
//!
//! `Journal` is synchronous on purpose: it runs inside the store's commit
//! hook, while the transaction is open.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use galata_vault_store::{JournalRecord, Store, StoreError};

pub trait Journal: Send + Sync {
    /// Durably store one record, or fail (and so roll the operation back).
    fn put(&self, record: &JournalRecord) -> Result<(), String>;
    /// Every record with a sequence above `after`, in sequence order.
    fn list_after(&self, after: u64) -> Result<Vec<JournalRecord>, String>;
    /// Reachable right now (readiness).
    fn check(&self) -> Result<(), String>;
    fn describe(&self) -> String;
    /// For `gv-server check`: write a probe object outside `journal/` (so
    /// replay never sees it), read it back and compare. Returns where it went.
    fn probe(&self) -> Result<String, String> {
        Err(format!("{} cannot be probed", self.describe()))
    }
}

/// A unique name for a probe object.
fn probe_id() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}-{:09}", now.as_secs(), now.subsec_nanos())
}

/// A probe object's bytes: plainly not a journal record.
fn probe_body(id: &str) -> Vec<u8> {
    format!("{{\"probe\":\"{id}\",\"note\":\"written by gv-server check; not a journal record\"}}")
        .into_bytes()
}

/// The sequence number in a journal object key (`journal/<seq>.json`).
fn seq_of(key: &str) -> Option<u64> {
    key.strip_prefix("journal/")?
        .strip_suffix(".json")?
        .parse()
        .ok()
}

fn io(e: std::io::Error) -> String {
    e.to_string()
}

#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error("cannot read the journal: {0}")]
    Journal(String),
    #[error("cannot replay the journal into the database: {0}")]
    Store(#[from] StoreError),
}

/// Bring a database that may be behind the journal (after a restore) up to
/// date. Returns how many records were replayed; more than zero means a
/// restore happened, which is a security-relevant event.
pub fn replay_journal(store: &dyn Store, journal: &dyn Journal) -> Result<usize, ReplayError> {
    let after = store.journal_applied()?;
    let records = journal.list_after(after).map_err(ReplayError::Journal)?;
    for record in &records {
        store.replay(record)?;
    }
    Ok(records.len())
}

// ------------------------------------------------------------ file

/// A directory beside the database. It survives a restored or copied-back
/// older `vault.db`; it does not survive the loss of the disk they share.
pub struct FileJournal {
    root: PathBuf,
}

impl FileJournal {
    pub fn open(root: impl Into<PathBuf>) -> Result<FileJournal, String> {
        let root = root.into();
        fs::create_dir_all(root.join("journal"))
            .map_err(|e| format!("cannot create {}: {e}", root.display()))?;
        Ok(FileJournal { root })
    }
}

impl Journal for FileJournal {
    fn put(&self, record: &JournalRecord) -> Result<(), String> {
        let path = self.root.join(record.object_key());
        if path.exists() {
            return Err(format!(
                "journal record {} already exists; is a second server writing?",
                record.seq
            ));
        }
        let tmp = path.with_extension("tmp");
        let mut file = fs::File::create(&tmp).map_err(io)?;
        file.write_all(&record.to_json()).map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(&tmp, &path).map_err(io)?;
        let dir = path
            .parent()
            .expect("a journal record lives in a directory");
        sync_dir(dir)
    }

    fn list_after(&self, after: u64) -> Result<Vec<JournalRecord>, String> {
        let mut records = Vec::new();
        for entry in fs::read_dir(self.root.join("journal")).map_err(io)? {
            let entry = entry.map_err(io)?;
            let key = format!("journal/{}", entry.file_name().to_string_lossy());
            let Some(seq) = seq_of(&key) else { continue };
            if seq <= after {
                continue;
            }
            let bytes = fs::read(entry.path()).map_err(io)?;
            records.push(
                JournalRecord::from_json(&bytes)
                    .map_err(|e| format!("journal record {seq} is corrupt: {e}"))?,
            );
        }
        records.sort_by_key(|r| r.seq);
        Ok(records)
    }

    fn check(&self) -> Result<(), String> {
        fs::metadata(self.root.join("journal"))
            .map(|_| ())
            .map_err(io)
    }

    fn probe(&self) -> Result<String, String> {
        let dir = self.root.join("probe");
        fs::create_dir_all(&dir).map_err(io)?;
        let id = probe_id();
        let path = dir.join(format!("{id}.json"));
        let body = probe_body(&id);
        fs::write(&path, &body).map_err(io)?;
        let back = fs::read(&path).map_err(io)?;
        fs::remove_file(&path).map_err(io)?;
        if back != body {
            return Err(format!(
                "the probe {} read back differently",
                path.display()
            ));
        }
        Ok(path.display().to_string())
    }

    fn describe(&self) -> String {
        format!(
            "file journal at {} (on the database's disk: it undoes a restored older copy, not the loss of the disk)",
            self.root.display()
        )
    }
}

/// Make a rename durable: on Unix, the directory entry is flushed with the
/// directory. Other platforms have no directory handle to flush.
#[cfg(unix)]
fn sync_dir(dir: &std::path::Path) -> Result<(), String> {
    fs::File::open(dir).and_then(|d| d.sync_all()).map_err(io)
}

#[cfg(not(unix))]
fn sync_dir(_dir: &std::path::Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use galata_vault_proto::ids::VaultId;
    use galata_vault_store::JournalOp;

    fn record(seq: u64) -> JournalRecord {
        JournalRecord {
            seq,
            ts: 1,
            op: JournalOp::DeleteVault {
                vault_id: VaultId([seq as u8; 16]),
            },
        }
    }

    #[test]
    fn file_journal_roundtrips_in_order_and_refuses_duplicates() {
        let dir = tempfile::tempdir().unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        for seq in [3, 1, 2] {
            j.put(&record(seq)).unwrap();
        }
        assert!(j.put(&record(2)).is_err(), "a sequence is written once");
        let after_one: Vec<u64> = j.list_after(1).unwrap().iter().map(|r| r.seq).collect();
        assert_eq!(after_one, [2, 3]);
        assert!(j.list_after(3).unwrap().is_empty());
        assert!(j.check().is_ok());
    }

    #[test]
    fn the_file_probe_round_trips_and_leaves_nothing_for_replay() {
        let dir = tempfile::tempdir().unwrap();
        let j = FileJournal::open(dir.path()).unwrap();
        let at = j.probe().unwrap();
        assert!(at.contains("probe"), "{at}");
        assert!(!std::path::Path::new(&at).exists(), "the probe is removed");
        assert!(j.list_after(0).unwrap().is_empty());
    }

    #[test]
    fn keys_parse_back_to_sequences() {
        assert_eq!(seq_of(&record(42).object_key()), Some(42));
        assert_eq!(seq_of("journal/x.json"), None);
        assert_eq!(seq_of("other/00000000000000000001.json"), None);
    }
}
