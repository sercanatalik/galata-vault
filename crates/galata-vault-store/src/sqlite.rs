//! The SQLite (WAL) implementation of [`Store`].
//!
//! One writer connection behind a mutex, every write in `BEGIN IMMEDIATE`;
//! a small pool of reader connections for everything else. The server calls
//! these methods from a blocking pool.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

use galata_vault_proto::api::{Limits, RotatedVersion, RotationRequest, Scope, SignedBundle};
use galata_vault_proto::audit::{
    Actor, AuditAction, AuditEvent, AuditResult, AuditRow, ChainHead, GENESIS,
};
use galata_vault_proto::children::ChildrenBlob;
use galata_vault_proto::descriptor::SignedDescriptor;
use galata_vault_proto::ids::{B64, Hash32, Key32, NameHmac, Sig64, TokenId, VaultId};
use rusqlite::types::Type;
use rusqlite::{Connection, OptionalExtension, Row, Transaction, TransactionBehavior, params};

use crate::journal::{CommitHook, JournalOp, JournalRecord};
use crate::schema;
use crate::{
    Ctx, HeadRow, NewToken, NewVault, Precondition, Quota, RecordKind, RecordWrite, SpentKind,
    Store, StoreError, TokenRow, VaultPk, VaultRow, VersionRow,
};

/// Activity is recorded at most this often per vault, so reads do not turn
/// into a write each.
const TOUCH_GRANULARITY_SECS: i64 = 60;

/// Each kind's tables, quotas and audit actions. The table names are
/// constants, never input.
impl RecordKind {
    fn records(self) -> &'static str {
        match self {
            RecordKind::Secret => "secrets",
            RecordKind::Config => "configs",
        }
    }

    fn heads(self) -> &'static str {
        match self {
            RecordKind::Secret => "heads",
            RecordKind::Config => "config_heads",
        }
    }

    fn put_action(self) -> AuditAction {
        match self {
            RecordKind::Secret => AuditAction::SecretPut,
            RecordKind::Config => AuditAction::ConfigWrite,
        }
    }

    fn delete_action(self) -> AuditAction {
        match self {
            RecordKind::Secret => AuditAction::SecretDelete,
            RecordKind::Config => AuditAction::ConfigDelete,
        }
    }

    fn max_value(self, l: &Limits) -> usize {
        match self {
            RecordKind::Secret => l.max_value_bytes as usize,
            RecordKind::Config => l.max_config_bytes as usize,
        }
    }

    fn max_live(self, l: &Limits) -> u32 {
        match self {
            RecordKind::Secret => l.max_names,
            RecordKind::Config => l.max_configs,
        }
    }

    fn max_versions(self, l: &Limits) -> u32 {
        match self {
            RecordKind::Secret => l.max_versions,
            RecordKind::Config => l.max_config_versions,
        }
    }

    fn size_quota(self) -> Quota {
        match self {
            RecordKind::Secret => Quota::ValueSize,
            RecordKind::Config => Quota::ConfigSize,
        }
    }

    fn live_quota(self) -> Quota {
        match self {
            RecordKind::Secret => Quota::Names,
            RecordKind::Config => Quota::Configs,
        }
    }
}

#[derive(Debug, Clone)]
pub struct StoreConfig {
    pub path: PathBuf,
    /// Running under `litestream replicate -exec`: Litestream owns
    /// checkpoints, so SQLite's automatic checkpoint is turned off.
    pub litestream: bool,
    pub readers: usize,
}

impl StoreConfig {
    pub fn new(path: impl Into<PathBuf>) -> StoreConfig {
        StoreConfig {
            path: path.into(),
            litestream: false,
            readers: 4,
        }
    }
}

pub struct SqliteStore {
    config: StoreConfig,
    writer: Mutex<Connection>,
    readers: Mutex<Vec<Connection>>,
}

/// A write that either happened, or was refused and audited as refused.
/// Both commit; an `Err` from the closure rolls back.
enum Done<T> {
    Ok(T),
    Refused(StoreError),
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn configure(conn: &Connection, config: &StoreConfig) -> Result<(), StoreError> {
    let mode: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !mode.eq_ignore_ascii_case("wal") {
        return Err(StoreError::NotWal(mode));
    }
    conn.busy_timeout(Duration::from_secs(5))?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    conn.pragma_update(None, "foreign_keys", "ON")?;
    if config.litestream {
        conn.pragma_update(None, "wal_autocheckpoint", 0)?;
    }
    Ok(())
}

impl SqliteStore {
    /// Open or create the database. A new file is put in WAL mode; an
    /// existing file that is not in WAL mode is refused, never converted.
    pub fn open(config: StoreConfig) -> Result<SqliteStore, StoreError> {
        let fresh = std::fs::metadata(&config.path).map_or(true, |m| m.len() == 0);
        let writer = Connection::open(&config.path)?;
        if fresh {
            let mode: String = writer.query_row("PRAGMA journal_mode = WAL", [], |r| r.get(0))?;
            if !mode.eq_ignore_ascii_case("wal") {
                return Err(StoreError::NotWal(mode));
            }
        }
        configure(&writer, &config)?;
        schema::migrate(&writer)?;
        Ok(SqliteStore {
            config,
            writer: Mutex::new(writer),
            readers: Mutex::new(Vec::new()),
        })
    }

    /// Fold the WAL into the main file. For tests and for operators taking a
    /// file copy; under Litestream, Litestream does this.
    pub fn checkpoint(&self) -> Result<(), StoreError> {
        lock(&self.writer).query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))?;
        Ok(())
    }

    fn read<T>(
        &self,
        f: impl FnOnce(&Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let pooled = lock(&self.readers).pop();
        let conn = match pooled {
            Some(c) => c,
            None => {
                let c = Connection::open(&self.config.path)?;
                configure(&c, &self.config)?;
                c
            }
        };
        let out = f(&conn);
        let mut readers = lock(&self.readers);
        if readers.len() < self.config.readers {
            readers.push(conn);
        }
        out
    }

    fn write<T>(
        &self,
        f: impl FnOnce(&Transaction<'_>) -> Result<Done<T>, StoreError>,
    ) -> Result<T, StoreError> {
        let mut conn = lock(&self.writer);
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        match f(&tx)? {
            Done::Ok(value) => {
                tx.commit()?;
                Ok(value)
            }
            Done::Refused(e) => {
                tx.commit()?;
                Err(e)
            }
        }
    }
}

// ------------------------------------------------------------ row mapping

fn conversion(i: usize) -> rusqlite::Error {
    rusqlite::Error::FromSqlConversionFailure(i, Type::Blob, "unexpected stored value".into())
}

fn blob<const N: usize>(r: &Row<'_>, i: usize) -> rusqlite::Result<[u8; N]> {
    let v: Vec<u8> = r.get(i)?;
    v.try_into().map_err(|_| conversion(i))
}

fn actor_at(r: &Row<'_>, i: usize) -> rusqlite::Result<Actor> {
    let v: Option<Vec<u8>> = r.get(i)?;
    match v {
        None => Ok(Actor::Owner),
        Some(b) => Ok(Actor::Token(TokenId(
            b.try_into().map_err(|_| conversion(i))?,
        ))),
    }
}

/// How an actor is stored: NULL for the owner, a token id otherwise. An
/// actor kind this store has no column for is refused, never stored as
/// something else.
fn actor_blob(actor: Actor) -> Result<Option<Vec<u8>>, StoreError> {
    match actor {
        Actor::Owner => Ok(None),
        Actor::Token(id) => Ok(Some(id.0.to_vec())),
        other => Err(StoreError::Database(format!(
            "an actor this store cannot record: {other:?}"
        ))),
    }
}

/// Every vault column, with the current generation's descriptor joined in.
const VAULT_SELECT: &str = "SELECT v.pk, v.vault_id, v.owner_sign_pub, v.owner_box_pub, v.owner_bundle, \
     v.owner_bundle_sig, v.generation, v.revision, v.created_at, v.last_active_at, v.bytes_used, \
     d.descriptor, d.sig \
     FROM vaults v JOIN descriptors d ON d.vault_pk = v.pk AND d.generation = v.generation";

fn vault_row(r: &Row<'_>) -> rusqlite::Result<VaultRow> {
    Ok(VaultRow {
        pk: r.get(0)?,
        vault_id: VaultId(blob(r, 1)?),
        owner_sign_pub: Key32(blob(r, 2)?),
        owner_box_pub: Key32(blob(r, 3)?),
        owner_bundle: SignedBundle::new(B64(r.get(4)?), Sig64(blob(r, 5)?)),
        generation: r.get(6)?,
        revision: r.get::<_, i64>(7)? as u64,
        created_at: r.get(8)?,
        last_active_at: r.get(9)?,
        bytes_used: r.get::<_, i64>(10)? as u64,
        descriptor: SignedDescriptor::from_parts(B64(r.get(11)?), Sig64(blob(r, 12)?)),
    })
}

const TOKEN_COLS: &str = "token_id, vault_pk, auth_pub, box_pub, scope, created_at, expires_at, \
                          bundle, bundle_sig, generation, allow_list";

fn token_row(r: &Row<'_>) -> rusqlite::Result<TokenRow> {
    let scope: String = r.get(4)?;
    let allow: Option<String> = r.get(10)?;
    Ok(TokenRow {
        token_id: TokenId(blob(r, 0)?),
        vault_pk: r.get(1)?,
        auth_pub: Key32(blob(r, 2)?),
        box_pub: Key32(blob(r, 3)?),
        scope: Scope::parse(&scope).ok_or_else(|| conversion(4))?,
        created_at: r.get(5)?,
        expires_at: r.get(6)?,
        bundle: SignedBundle::new(B64(r.get(7)?), Sig64(blob(r, 8)?)),
        generation: r.get(9)?,
        allow_list: allow
            .map(|s| serde_json::from_str(&s))
            .transpose()
            .map_err(|_| conversion(10))?,
    })
}

const VERSION_COLS: &str =
    "name_hmac, version, name_ct, value_ct, generation, written_at, written_by, tombstone, sig";

fn version_row(r: &Row<'_>) -> rusqlite::Result<VersionRow> {
    Ok(VersionRow {
        name_hmac: NameHmac(blob(r, 0)?),
        version: r.get::<_, i64>(1)? as u64,
        name_ct: r.get(2)?,
        value_ct: r.get(3)?,
        generation: r.get(4)?,
        written_at: r.get(5)?,
        written_by: actor_at(r, 6)?,
        tombstone: r.get(7)?,
        sig: Sig64(blob(r, 8)?),
    })
}

const AUDIT_COLS: &str =
    "seq, ts, actor, action, name_hmac, subject, result, version, ct_hash, prev, hash, v";

fn audit_row(r: &Row<'_>) -> rusqlite::Result<AuditRow> {
    let name: Option<Vec<u8>> = r.get(4)?;
    let subject: Option<Vec<u8>> = r.get(5)?;
    let ct_hash: Option<Vec<u8>> = r.get(8)?;
    let event = AuditEvent {
        actor: actor_at(r, 2)?,
        action: AuditAction::from_code(r.get(3)?).ok_or_else(|| conversion(3))?,
        name_hmac: name
            .map(|b| b.try_into().map(NameHmac).map_err(|_| conversion(4)))
            .transpose()?,
        subject: subject
            .map(|b| b.try_into().map(TokenId).map_err(|_| conversion(5)))
            .transpose()?,
        result: AuditResult::from_code(r.get(6)?).ok_or_else(|| conversion(6))?,
        version: r.get::<_, i64>(7)? as u64,
        ct_hash: ct_hash
            .map(|b| b.try_into().map(Hash32).map_err(|_| conversion(8)))
            .transpose()?,
    };
    Ok(AuditRow::stored(
        r.get(11)?,
        r.get::<_, i64>(0)? as u64,
        r.get(1)?,
        Hash32(blob(r, 9)?),
        Hash32(blob(r, 10)?),
        event,
    ))
}

// ------------------------------------------------------------ helpers

fn load_vault(c: &Connection, pk: VaultPk) -> Result<Option<VaultRow>, StoreError> {
    Ok(
        c.query_row(&format!("{VAULT_SELECT} WHERE v.pk = ?1"), [pk], vault_row)
            .optional()?,
    )
}

fn load_vault_by_id(c: &Connection, id: &VaultId) -> Result<Option<VaultRow>, StoreError> {
    Ok(c.query_row(
        &format!("{VAULT_SELECT} WHERE v.vault_id = ?1"),
        [&id.0[..]],
        vault_row,
    )
    .optional()?)
}

fn load_head(
    c: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    name: &NameHmac,
) -> Result<Option<(u64, bool)>, StoreError> {
    Ok(c.query_row(
        &format!(
            "SELECT current_version, tombstone FROM {} WHERE vault_pk = ?1 AND name_hmac = ?2",
            kind.heads()
        ),
        params![pk, &name.0[..]],
        |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, bool>(1)?)),
    )
    .optional()?)
}

fn event(
    actor: Actor,
    action: AuditAction,
    name_hmac: Option<NameHmac>,
    subject: Option<TokenId>,
    result: AuditResult,
) -> AuditEvent {
    AuditEvent {
        subject,
        ..AuditEvent::simple(actor, action, name_hmac, result)
    }
}

/// An event that names the version it wrote, and the hash of what it wrote.
fn written(
    actor: Actor,
    action: AuditAction,
    name_hmac: Option<NameHmac>,
    version: u64,
    ct_hash: Option<Hash32>,
) -> AuditEvent {
    AuditEvent {
        version,
        ct_hash,
        ..AuditEvent::simple(actor, action, name_hmac, AuditResult::Ok)
    }
}

/// Append one row to the vault's chain, and move its head.
fn append_audit(tx: &Connection, pk: VaultPk, e: AuditEvent, now: i64) -> Result<(), StoreError> {
    let (seq, head): (i64, Vec<u8>) = tx.query_row(
        "SELECT audit_seq, audit_head FROM vaults WHERE pk = ?1",
        [pk],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let prev = Hash32(
        head.try_into()
            .map_err(|_| StoreError::Database("corrupt audit head".into()))?,
    );
    let row = AuditRow::from_event(seq as u64 + 1, now, prev, e);
    tx.execute(
        "INSERT INTO audit (vault_pk, seq, ts, actor, action, name_hmac, subject, result, version,
                            ct_hash, prev, hash, v)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
        params![
            pk,
            row.seq as i64,
            row.ts,
            actor_blob(e.actor)?,
            e.action.code(),
            e.name_hmac.map(|n| n.0.to_vec()),
            e.subject.map(|s| s.0.to_vec()),
            e.result.code(),
            e.version as i64,
            e.ct_hash.map(|h| h.0.to_vec()),
            &prev.0[..],
            &row.hash.0[..],
            row.v,
        ],
    )?;
    tx.execute(
        "UPDATE vaults SET audit_seq = ?1, audit_head = ?2 WHERE pk = ?3",
        params![row.seq as i64, &row.hash.0[..], pk],
    )?;
    Ok(())
}

fn bump_revision(tx: &Connection, pk: VaultPk) -> Result<(), StoreError> {
    tx.execute(
        "UPDATE vaults SET revision = revision + 1 WHERE pk = ?1",
        [pk],
    )?;
    Ok(())
}

/// Allocate the next journal sequence and hand the record to the hook while
/// the transaction is still open.
fn journal(
    tx: &Connection,
    op: JournalOp,
    now: i64,
    hook: CommitHook<'_>,
) -> Result<(), StoreError> {
    let last: i64 = tx.query_row(
        "SELECT last_applied FROM journal_state WHERE id = 1",
        [],
        |r| r.get(0),
    )?;
    let record = JournalRecord {
        seq: last as u64 + 1,
        ts: now,
        op,
    };
    tx.execute(
        "UPDATE journal_state SET last_applied = ?1 WHERE id = 1",
        [record.seq as i64],
    )?;
    hook(&record).map_err(StoreError::Journal)
}

/// Oldest versions of `name` that must go to keep `max_versions` once one
/// more is written: `(version, bytes)`.
fn prunable(
    tx: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    name: &NameHmac,
    max_versions: u32,
) -> Result<Vec<(u64, u64)>, StoreError> {
    let mut stmt = tx.prepare(&format!(
        "SELECT version, length(name_ct) + COALESCE(length(value_ct), 0)
         FROM {} WHERE vault_pk = ?1 AND name_hmac = ?2 ORDER BY version ASC",
        kind.records()
    ))?;
    let all = stmt
        .query_map(params![pk, &name.0[..]], |r| {
            Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let excess = (all.len() + 1).saturating_sub(max_versions.max(1) as usize);
    Ok(all.into_iter().take(excess).collect())
}

/// SHA-256 of a value ciphertext, or of an empty value for a tombstone: what
/// a record signature binds.
fn value_hash(value_ct: Option<&[u8]>) -> Hash32 {
    Hash32::sha256(value_ct.unwrap_or(&[]))
}

struct Insert<'a> {
    name: &'a NameHmac,
    version: u64,
    name_ct: &'a [u8],
    value_ct: Option<&'a [u8]>,
    generation: u32,
    written_at: i64,
    written_by: Actor,
    sig: &'a Sig64,
}

fn insert_version(
    tx: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    v: Insert<'_>,
) -> Result<(), StoreError> {
    tx.execute(
        &format!(
            "INSERT INTO {} (vault_pk, name_hmac, version, name_ct, value_ct, ct_hash, generation,
                             written_at, written_by, tombstone, sig)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            kind.records()
        ),
        params![
            pk,
            &v.name.0[..],
            v.version as i64,
            v.name_ct,
            v.value_ct,
            &value_hash(v.value_ct).0[..],
            v.generation,
            v.written_at,
            actor_blob(v.written_by)?,
            v.value_ct.is_none(),
            &v.sig.0[..],
        ],
    )?;
    Ok(())
}

fn set_head(
    tx: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    name: &NameHmac,
    version: u64,
    tombstone: bool,
) -> Result<(), StoreError> {
    tx.execute(
        &format!(
            "INSERT INTO {} (vault_pk, name_hmac, current_version, tombstone) VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT (vault_pk, name_hmac)
             DO UPDATE SET current_version = excluded.current_version, tombstone = excluded.tombstone",
            kind.heads()
        ),
        params![pk, &name.0[..], version as i64, tombstone],
    )?;
    Ok(())
}

fn delete_versions(
    tx: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    name: &NameHmac,
    versions: &[(u64, u64)],
) -> Result<(), StoreError> {
    for (version, _) in versions {
        tx.execute(
            &format!(
                "DELETE FROM {} WHERE vault_pk = ?1 AND name_hmac = ?2 AND version = ?3",
                kind.records()
            ),
            params![pk, &name.0[..], *version as i64],
        )?;
    }
    Ok(())
}

/// One version as rewritten by a rotation.
struct Rewritten {
    name: NameHmac,
    version: u64,
    name_ct: Vec<u8>,
    value_ct: Option<Vec<u8>>,
    written_at: i64,
    written_by: Actor,
    sig: Sig64,
}

/// Replace a vault's records of one kind wholesale (rotation). Returns the
/// bytes they now take.
fn replace_records(
    tx: &Connection,
    kind: RecordKind,
    pk: VaultPk,
    generation: u32,
    rows: &[Rewritten],
) -> Result<u64, StoreError> {
    tx.execute(
        &format!("DELETE FROM {} WHERE vault_pk = ?1", kind.heads()),
        [pk],
    )?;
    tx.execute(
        &format!("DELETE FROM {} WHERE vault_pk = ?1", kind.records()),
        [pk],
    )?;
    let mut heads: HashMap<NameHmac, (u64, bool)> = HashMap::new();
    let mut bytes = 0u64;
    for r in rows {
        insert_version(
            tx,
            kind,
            pk,
            Insert {
                name: &r.name,
                version: r.version,
                name_ct: &r.name_ct,
                value_ct: r.value_ct.as_deref(),
                generation,
                written_at: r.written_at,
                written_by: r.written_by,
                sig: &r.sig,
            },
        )?;
        bytes += (r.name_ct.len() + r.value_ct.as_ref().map_or(0, Vec::len)) as u64;
        let head = heads
            .entry(r.name)
            .or_insert((r.version, r.value_ct.is_none()));
        if r.version >= head.0 {
            *head = (r.version, r.value_ct.is_none());
        }
    }
    for (name, (version, tombstone)) in heads {
        set_head(tx, kind, pk, &name, version, tombstone)?;
    }
    Ok(bytes)
}

fn tokens_of(c: &Connection, pk: VaultPk) -> Result<Vec<TokenRow>, StoreError> {
    let mut stmt = c.prepare(&format!(
        "SELECT {TOKEN_COLS} FROM tokens WHERE vault_pk = ?1 ORDER BY created_at, token_id"
    ))?;
    let rows = stmt
        .query_map([pk], token_row)?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(rows)
}

fn delete_tokens(
    tx: &Connection,
    pk: VaultPk,
    ids: &[TokenId],
) -> Result<Vec<TokenId>, StoreError> {
    let mut removed = Vec::new();
    for id in ids {
        let n = tx.execute(
            "DELETE FROM tokens WHERE vault_pk = ?1 AND token_id = ?2",
            params![pk, &id.0[..]],
        )?;
        if n == 1 {
            removed.push(*id);
        }
    }
    Ok(removed)
}

type Meta = HashMap<(NameHmac, u64), (i64, Actor, bool)>;

fn version_meta(tx: &Connection, kind: RecordKind, pk: VaultPk) -> Result<Meta, StoreError> {
    let mut stmt = tx.prepare(&format!(
        "SELECT name_hmac, version, written_at, written_by, tombstone FROM {} WHERE vault_pk = ?1",
        kind.records()
    ))?;
    let rows = stmt
        .query_map([pk], |r| {
            Ok((
                (NameHmac(blob(r, 0)?), r.get::<_, i64>(1)? as u64),
                (r.get(2)?, actor_at(r, 3)?, r.get(4)?),
            ))
        })?
        .collect::<rusqlite::Result<Meta>>()?;
    Ok(rows)
}

/// Every retained version of one kind must be re-encrypted exactly once,
/// keeping its write time, and tombstones must stay tombstones.
fn check_complete(batch: &[RotatedVersion], meta: &Meta) -> Result<(), StoreError> {
    let keys: HashSet<(NameHmac, u64)> =
        batch.iter().map(|s| (s.old_name_hmac, s.version)).collect();
    let stored: HashSet<(NameHmac, u64)> = meta.keys().copied().collect();
    if keys.len() != batch.len() || keys != stored {
        return Err(StoreError::IncompleteRotation(
            "every retained version must be re-encrypted exactly once",
        ));
    }
    if batch
        .iter()
        .any(|s| meta[&(s.old_name_hmac, s.version)].2 != s.value_ct.is_none())
    {
        return Err(StoreError::IncompleteRotation(
            "tombstones must stay tombstones",
        ));
    }
    if batch
        .iter()
        .any(|s| meta[&(s.old_name_hmac, s.version)].0 != s.written_at)
    {
        return Err(StoreError::IncompleteRotation(
            "every version must keep its write time",
        ));
    }
    Ok(())
}

/// A batch of one kind as rows, keeping each version's writer.
fn rewritten(
    batch: &[RotatedVersion],
    meta: &Meta,
    ctx: Ctx,
) -> Result<Vec<Rewritten>, StoreError> {
    let renamed: HashSet<(NameHmac, u64)> =
        batch.iter().map(|s| (s.name_hmac, s.version)).collect();
    if renamed.len() != batch.len() {
        return Err(StoreError::IncompleteRotation(
            "two versions map to the same new name",
        ));
    }
    Ok(batch
        .iter()
        .map(|s| {
            let written_by = meta
                .get(&(s.old_name_hmac, s.version))
                .map_or(ctx.actor, |m| m.1);
            Rewritten {
                name: s.name_hmac,
                version: s.version,
                name_ct: s.name_ct.0.clone(),
                value_ct: s.value_ct.as_ref().map(|v| v.0.clone()),
                written_at: s.written_at,
                written_by,
                sig: s.sig,
            }
        })
        .collect())
}

/// Apply a rotation. `strict` is the live path; replay after a restore is
/// lenient, because the restored database may be older than the state the
/// batch was built from, and the batch itself is the whole new state.
fn rotate(
    tx: &Connection,
    vault: &VaultRow,
    r: &RotationRequest,
    ctx: Ctx,
    strict: bool,
) -> Result<u32, StoreError> {
    let pk = vault.pk;
    let meta = version_meta(tx, RecordKind::Secret, pk)?;
    let config_meta = version_meta(tx, RecordKind::Config, pk)?;
    let existing_tokens: HashSet<TokenId> =
        tokens_of(tx, pk)?.into_iter().map(|t| t.token_id).collect();
    let revoke: HashSet<TokenId> = r.revoke.iter().copied().collect();

    if strict {
        if vault.generation != r.from_generation || vault.revision != r.from_revision {
            return Err(StoreError::Conflict);
        }
        check_complete(&r.secrets, &meta)?;
        check_complete(&r.configs, &config_meta)?;
        if !revoke.is_subset(&existing_tokens) {
            return Err(StoreError::IncompleteRotation(
                "revoke names a token not in this vault",
            ));
        }
        let survivors: HashSet<TokenId> = existing_tokens.difference(&revoke).copied().collect();
        let resealed: HashSet<TokenId> = r.tokens.iter().map(|t| t.token_id).collect();
        if resealed.len() != r.tokens.len() || resealed != survivors {
            return Err(StoreError::IncompleteRotation(
                "every surviving token needs exactly one resealed bundle",
            ));
        }
    } else if vault.generation > r.from_generation {
        return Ok(vault.generation); // already applied
    }

    let generation = r.from_generation + 1;
    let secret_rows = rewritten(&r.secrets, &meta, ctx)?;
    let config_rows = rewritten(&r.configs, &config_meta, ctx)?;
    let bytes = replace_records(tx, RecordKind::Secret, pk, generation, &secret_rows)?
        + replace_records(tx, RecordKind::Config, pk, generation, &config_rows)?;

    tx.execute(
        "INSERT INTO descriptors (vault_pk, generation, descriptor, sig) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (vault_pk, generation) DO NOTHING",
        params![
            pk,
            generation,
            &r.descriptor.descriptor.0,
            &r.descriptor.sig.0[..]
        ],
    )?;
    let revoked = delete_tokens(tx, pk, &r.revoke)?;
    for t in &r.tokens {
        tx.execute(
            "UPDATE tokens SET bundle = ?1, bundle_sig = ?2, generation = ?3
             WHERE vault_pk = ?4 AND token_id = ?5",
            params![
                &t.bundle.sealed.0,
                &t.bundle.sig.0[..],
                generation,
                pk,
                &t.token_id.0[..]
            ],
        )?;
    }
    tx.execute(
        "UPDATE vaults SET generation = ?1, owner_bundle = ?2, owner_bundle_sig = ?3,
                           bytes_used = ?4, revision = revision + 1
         WHERE pk = ?5",
        params![
            generation,
            &r.owner_bundle.sealed.0,
            &r.owner_bundle.sig.0[..],
            bytes as i64,
            pk
        ],
    )?;
    append_audit(
        tx,
        pk,
        written(
            ctx.actor,
            AuditAction::VaultRotate,
            None,
            0,
            Some(Hash32::sha256(&r.descriptor.descriptor.0)),
        ),
        ctx.now,
    )?;
    for id in revoked {
        append_audit(
            tx,
            pk,
            event(
                ctx.actor,
                AuditAction::TokenRevoke,
                None,
                Some(id),
                AuditResult::Ok,
            ),
            ctx.now,
        )?;
    }
    Ok(generation)
}

// ------------------------------------------------------------ Store

impl Store for SqliteStore {
    fn create_vault(&self, v: &NewVault, now: i64) -> Result<VaultRow, StoreError> {
        self.write(|tx| {
            if tx
                .query_row(
                    "SELECT 1 FROM vaults WHERE vault_id = ?1",
                    [&v.vault_id.0[..]],
                    |_| Ok(()),
                )
                .optional()?
                .is_some()
            {
                return Ok(Done::Refused(StoreError::Exists));
            }
            tx.execute(
                "INSERT INTO vaults (vault_id, owner_sign_pub, owner_box_pub, owner_bundle,
                                     owner_bundle_sig, generation, revision, created_at,
                                     last_active_at, bytes_used, audit_seq, audit_head)
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 1, ?6, ?6, 0, 0, ?7)",
                params![
                    &v.vault_id.0[..],
                    &v.owner_sign_pub.0[..],
                    &v.owner_box_pub.0[..],
                    &v.owner_bundle.sealed.0,
                    &v.owner_bundle.sig.0[..],
                    now,
                    &GENESIS.0[..],
                ],
            )?;
            let pk = tx.last_insert_rowid();
            tx.execute(
                "INSERT INTO descriptors (vault_pk, generation, descriptor, sig) VALUES (?1, 1, ?2, ?3)",
                params![pk, &v.descriptor.descriptor.0, &v.descriptor.sig.0[..]],
            )?;
            append_audit(
                tx,
                pk,
                written(
                    Actor::Owner,
                    AuditAction::VaultCreate,
                    None,
                    0,
                    Some(Hash32::sha256(&v.descriptor.descriptor.0)),
                ),
                now,
            )?;
            Ok(Done::Ok(load_vault(tx, pk)?.ok_or(StoreError::NotFound)?))
        })
    }

    fn vault_by_id(&self, id: &VaultId) -> Result<Option<VaultRow>, StoreError> {
        self.read(|c| load_vault_by_id(c, id))
    }

    fn vault_by_pk(&self, pk: VaultPk) -> Result<Option<VaultRow>, StoreError> {
        self.read(|c| load_vault(c, pk))
    }

    fn touch(&self, pk: VaultPk, now: i64) -> Result<(), StoreError> {
        let stale = self.read(|c| {
            Ok(c.query_row(
                "SELECT last_active_at FROM vaults WHERE pk = ?1",
                [pk],
                |r| r.get::<_, i64>(0),
            )
            .optional()?
            .is_some_and(|t| t < now - TOUCH_GRANULARITY_SECS))
        })?;
        if stale {
            self.write(|tx| {
                tx.execute(
                    "UPDATE vaults SET last_active_at = ?1 WHERE pk = ?2 AND last_active_at < ?1",
                    params![now, pk],
                )?;
                Ok(Done::Ok(()))
            })?;
        }
        Ok(())
    }

    fn descriptors(&self, pk: VaultPk, after: u32) -> Result<Vec<SignedDescriptor>, StoreError> {
        self.read(|c| {
            let mut stmt = c.prepare(
                "SELECT descriptor, sig FROM descriptors
                 WHERE vault_pk = ?1 AND generation > ?2 ORDER BY generation",
            )?;
            let rows = stmt
                .query_map(params![pk, after], |r| {
                    Ok(SignedDescriptor::from_parts(
                        B64(r.get(0)?),
                        Sig64(blob(r, 1)?),
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    fn register_token(
        &self,
        pk: VaultPk,
        t: &NewToken,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<TokenRow, StoreError> {
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            let refuse = |e: StoreError| -> Result<Done<TokenRow>, StoreError> {
                append_audit(
                    tx,
                    pk,
                    event(
                        ctx.actor,
                        AuditAction::TokenMint,
                        None,
                        Some(t.token_id),
                        AuditResult::Refused,
                    ),
                    ctx.now,
                )?;
                Ok(Done::Refused(e))
            };
            if t.generation != vault.generation {
                return refuse(StoreError::StaleGeneration);
            }
            let active: i64 = tx.query_row(
                "SELECT COUNT(*) FROM tokens WHERE vault_pk = ?1 AND expires_at > ?2",
                params![pk, ctx.now],
                |r| r.get(0),
            )?;
            if active >= i64::from(limits.max_tokens) {
                return refuse(StoreError::Quota(Quota::Tokens));
            }
            let allow = t
                .allow_list
                .as_ref()
                .map(|l| serde_json::to_string(l).expect("hex ids serialize"));
            tx.execute(
                "INSERT INTO tokens (token_id, vault_pk, auth_pub, box_pub, scope, created_at,
                                     expires_at, bundle, bundle_sig, generation, allow_list)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
                params![
                    &t.token_id.0[..],
                    pk,
                    &t.auth_pub.0[..],
                    &t.box_pub.0[..],
                    t.scope.to_string(),
                    ctx.now,
                    t.expires_at,
                    &t.bundle.sealed.0,
                    &t.bundle.sig.0[..],
                    t.generation,
                    allow,
                ],
            )?;
            bump_revision(tx, pk)?;
            append_audit(
                tx,
                pk,
                event(
                    ctx.actor,
                    AuditAction::TokenMint,
                    None,
                    Some(t.token_id),
                    AuditResult::Ok,
                ),
                ctx.now,
            )?;
            let row = tx.query_row(
                &format!("SELECT {TOKEN_COLS} FROM tokens WHERE token_id = ?1"),
                [&t.token_id.0[..]],
                token_row,
            )?;
            Ok(Done::Ok(row))
        })
    }

    fn token_by_id(&self, id: &TokenId) -> Result<Option<TokenRow>, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                &format!("SELECT {TOKEN_COLS} FROM tokens WHERE token_id = ?1"),
                [&id.0[..]],
                token_row,
            )
            .optional()?)
        })
    }

    fn tokens(&self, pk: VaultPk) -> Result<Vec<TokenRow>, StoreError> {
        self.read(|c| tokens_of(c, pk))
    }

    fn revoke_tokens(
        &self,
        pk: VaultPk,
        ids: &[TokenId],
        reported: bool,
        ctx: Ctx,
        hook: CommitHook<'_>,
    ) -> Result<Vec<TokenId>, StoreError> {
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            let removed = delete_tokens(tx, pk, ids)?;
            if removed.is_empty() {
                return Err(StoreError::NotFound);
            }
            bump_revision(tx, pk)?;
            let action = if reported {
                AuditAction::TokenReport
            } else {
                AuditAction::TokenRevoke
            };
            for id in &removed {
                append_audit(
                    tx,
                    pk,
                    event(ctx.actor, action, None, Some(*id), AuditResult::Ok),
                    ctx.now,
                )?;
            }
            journal(
                tx,
                JournalOp::RevokeTokens {
                    vault_id: vault.vault_id,
                    token_ids: removed.clone(),
                    actor: ctx.actor,
                    reported,
                },
                ctx.now,
                hook,
            )?;
            Ok(Done::Ok(removed))
        })
    }

    fn list_records(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        after: Option<&NameHmac>,
        limit: usize,
    ) -> Result<Vec<HeadRow>, StoreError> {
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT h.name_hmac, s.name_ct, h.current_version, s.written_at,
                        COALESCE(length(s.value_ct), 0), h.tombstone, s.generation, s.ct_hash, s.sig
                 FROM {heads} h
                 JOIN {records} s ON s.vault_pk = h.vault_pk AND s.name_hmac = h.name_hmac
                                AND s.version = h.current_version
                 WHERE h.vault_pk = ?1 AND (?2 IS NULL OR h.name_hmac > ?2)
                 ORDER BY h.name_hmac
                 LIMIT ?3",
                heads = kind.heads(),
                records = kind.records(),
            ))?;
            let rows = stmt
                .query_map(
                    params![pk, after.map(|n| n.0.to_vec()), limit as i64],
                    |r| {
                        Ok(HeadRow {
                            name_hmac: NameHmac(blob(r, 0)?),
                            name_ct: r.get(1)?,
                            version: r.get::<_, i64>(2)? as u64,
                            written_at: r.get(3)?,
                            size: r.get::<_, i64>(4)? as u32,
                            tombstone: r.get(5)?,
                            generation: r.get(6)?,
                            value_ct_hash: Hash32(blob(r, 7)?),
                            sig: Sig64(blob(r, 8)?),
                        })
                    },
                )?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    fn latest_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
    ) -> Result<Option<VersionRow>, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                &format!(
                    "SELECT {VERSION_COLS} FROM {records}
                     WHERE vault_pk = ?1 AND name_hmac = ?2
                       AND version = (SELECT current_version FROM {heads} WHERE vault_pk = ?1 AND name_hmac = ?2)",
                    records = kind.records(),
                    heads = kind.heads(),
                ),
                params![pk, &name.0[..]],
                version_row,
            )
            .optional()?)
        })
    }

    fn record_version(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        version: u64,
    ) -> Result<Option<VersionRow>, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                &format!(
                    "SELECT {VERSION_COLS} FROM {records} WHERE vault_pk = ?1 AND name_hmac = ?2 AND version = ?3",
                    records = kind.records(),
                ),
                params![pk, &name.0[..], version as i64],
                version_row,
            )
            .optional()?)
        })
    }

    fn record_versions(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
    ) -> Result<Vec<VersionRow>, StoreError> {
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {VERSION_COLS} FROM {records} WHERE vault_pk = ?1 AND name_hmac = ?2 ORDER BY version",
                records = kind.records(),
            ))?;
            let rows = stmt
                .query_map(params![pk, &name.0[..]], version_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    fn all_record_versions(
        &self,
        pk: VaultPk,
        kind: RecordKind,
    ) -> Result<Vec<VersionRow>, StoreError> {
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {VERSION_COLS} FROM {records} WHERE vault_pk = ?1 ORDER BY name_hmac, version",
                records = kind.records(),
            ))?;
            let rows = stmt
                .query_map([pk], version_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(rows)
        })
    }

    fn put_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        pre: Precondition,
        w: &RecordWrite,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError> {
        let Some(value_ct) = w.value_ct.as_deref() else {
            return Err(StoreError::Database(
                "a put needs a value; a tombstone is a delete".into(),
            ));
        };
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            let refuse = |e: StoreError| -> Result<Done<u64>, StoreError> {
                append_audit(
                    tx,
                    pk,
                    event(
                        ctx.actor,
                        kind.put_action(),
                        Some(*name),
                        None,
                        AuditResult::Refused,
                    ),
                    ctx.now,
                )?;
                Ok(Done::Refused(e))
            };
            if w.generation != vault.generation {
                return refuse(StoreError::StaleGeneration);
            }
            if value_ct.len() > kind.max_value(limits) {
                return refuse(StoreError::Quota(kind.size_quota()));
            }
            let head = load_head(tx, kind, pk, name)?;
            let next = match (pre, head) {
                (Precondition::IfNoneMatch, None) => 1,
                (Precondition::IfNoneMatch, Some((v, true))) => v + 1,
                (Precondition::IfMatch(x), Some((v, false))) if x == v => v + 1,
                (_, current) => {
                    return refuse(StoreError::PreconditionFailed {
                        current: current.map(|(v, _)| v),
                    });
                }
            };
            if w.version != next {
                return refuse(StoreError::VersionMismatch {
                    signed: w.version,
                    assigned: next,
                });
            }
            if head.is_none_or(|(_, tombstone)| tombstone) {
                let live: i64 = tx.query_row(
                    &format!(
                        "SELECT COUNT(*) FROM {} WHERE vault_pk = ?1 AND tombstone = 0",
                        kind.heads()
                    ),
                    [pk],
                    |r| r.get(0),
                )?;
                if live >= i64::from(kind.max_live(limits)) {
                    return refuse(StoreError::Quota(kind.live_quota()));
                }
            }
            let pruned = prunable(tx, kind, pk, name, kind.max_versions(limits))?;
            let freed: u64 = pruned.iter().map(|(_, b)| b).sum();
            let total = vault.bytes_used + (w.name_ct.len() + value_ct.len()) as u64 - freed;
            if total > limits.max_vault_bytes {
                return refuse(StoreError::Quota(Quota::VaultBytes));
            }
            insert_version(
                tx,
                kind,
                pk,
                Insert {
                    name,
                    version: next,
                    name_ct: &w.name_ct,
                    value_ct: Some(value_ct),
                    generation: w.generation,
                    written_at: w.written_at,
                    written_by: ctx.actor,
                    sig: &w.sig,
                },
            )?;
            set_head(tx, kind, pk, name, next, false)?;
            delete_versions(tx, kind, pk, name, &pruned)?;
            tx.execute(
                "UPDATE vaults SET bytes_used = ?1, revision = revision + 1 WHERE pk = ?2",
                params![total as i64, pk],
            )?;
            append_audit(
                tx,
                pk,
                written(
                    ctx.actor,
                    kind.put_action(),
                    Some(*name),
                    next,
                    Some(Hash32::sha256(value_ct)),
                ),
                ctx.now,
            )?;
            Ok(Done::Ok(next))
        })
    }

    fn delete_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        if_match: u64,
        w: &RecordWrite,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError> {
        if w.value_ct.is_some() {
            return Err(StoreError::Database(
                "a delete writes a tombstone, with no value".into(),
            ));
        }
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            let refuse = |e: StoreError| -> Result<Done<u64>, StoreError> {
                append_audit(
                    tx,
                    pk,
                    event(
                        ctx.actor,
                        kind.delete_action(),
                        Some(*name),
                        None,
                        AuditResult::Refused,
                    ),
                    ctx.now,
                )?;
                Ok(Done::Refused(e))
            };
            let current = match load_head(tx, kind, pk, name)? {
                None | Some((_, true)) => return Err(StoreError::NotFound),
                Some((v, false)) => v,
            };
            if w.generation != vault.generation {
                return refuse(StoreError::StaleGeneration);
            }
            if if_match != current {
                return refuse(StoreError::PreconditionFailed {
                    current: Some(current),
                });
            }
            let next = current + 1;
            if w.version != next {
                return refuse(StoreError::VersionMismatch {
                    signed: w.version,
                    assigned: next,
                });
            }
            let pruned = prunable(tx, kind, pk, name, kind.max_versions(limits))?;
            let freed: u64 = pruned.iter().map(|(_, b)| b).sum();
            insert_version(
                tx,
                kind,
                pk,
                Insert {
                    name,
                    version: next,
                    name_ct: &w.name_ct,
                    value_ct: None,
                    generation: w.generation,
                    written_at: w.written_at,
                    written_by: ctx.actor,
                    sig: &w.sig,
                },
            )?;
            set_head(tx, kind, pk, name, next, true)?;
            delete_versions(tx, kind, pk, name, &pruned)?;
            let total = (vault.bytes_used + w.name_ct.len() as u64).saturating_sub(freed);
            tx.execute(
                "UPDATE vaults SET bytes_used = ?1, revision = revision + 1 WHERE pk = ?2",
                params![total as i64, pk],
            )?;
            append_audit(
                tx,
                pk,
                written(ctx.actor, kind.delete_action(), Some(*name), next, None),
                ctx.now,
            )?;
            Ok(Done::Ok(next))
        })
    }

    fn live_records(&self, pk: VaultPk, kind: RecordKind) -> Result<u32, StoreError> {
        self.read(|c| {
            let n: i64 = c.query_row(
                &format!(
                    "SELECT COUNT(*) FROM {} WHERE vault_pk = ?1 AND tombstone = 0",
                    kind.heads()
                ),
                [pk],
                |r| r.get(0),
            )?;
            Ok(n as u32)
        })
    }

    fn children(&self, pk: VaultPk) -> Result<Option<ChildrenBlob>, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                "SELECT version, ct, sig FROM children WHERE vault_pk = ?1",
                [pk],
                |r| {
                    Ok(ChildrenBlob::new(
                        r.get::<_, i64>(0)? as u64,
                        B64(r.get(1)?),
                        Sig64(blob(r, 2)?),
                    ))
                },
            )
            .optional()?)
        })
    }

    fn put_children(
        &self,
        pk: VaultPk,
        pre: Precondition,
        blob: &ChildrenBlob,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError> {
        self.write(|tx| {
            if load_vault(tx, pk)?.is_none() {
                return Err(StoreError::NotFound);
            }
            let refuse = |e: StoreError| -> Result<Done<u64>, StoreError> {
                append_audit(
                    tx,
                    pk,
                    event(
                        ctx.actor,
                        AuditAction::ChildrenWrite,
                        None,
                        None,
                        AuditResult::Refused,
                    ),
                    ctx.now,
                )?;
                Ok(Done::Refused(e))
            };
            // The children record is small, but a node may have many children:
            // it takes the per-config limit, not the per-secret one.
            if blob.ct.0.len() > limits.max_config_bytes as usize {
                return refuse(StoreError::Quota(Quota::ValueSize));
            }
            let current: Option<u64> = tx
                .query_row(
                    "SELECT version FROM children WHERE vault_pk = ?1",
                    [pk],
                    |r| r.get::<_, i64>(0),
                )
                .optional()?
                .map(|v| v as u64);
            let next = match (pre, current) {
                (Precondition::IfNoneMatch, None) => 1,
                (Precondition::IfMatch(x), Some(v)) if x == v => v + 1,
                (_, current) => return refuse(StoreError::PreconditionFailed { current }),
            };
            if blob.version != next {
                return refuse(StoreError::VersionMismatch {
                    signed: blob.version,
                    assigned: next,
                });
            }
            tx.execute(
                "INSERT INTO children (vault_pk, version, ct, sig) VALUES (?1, ?2, ?3, ?4)
                 ON CONFLICT (vault_pk)
                 DO UPDATE SET version = excluded.version, ct = excluded.ct, sig = excluded.sig",
                params![pk, next as i64, &blob.ct.0, &blob.sig.0[..]],
            )?;
            append_audit(
                tx,
                pk,
                written(
                    ctx.actor,
                    AuditAction::ChildrenWrite,
                    None,
                    next,
                    Some(Hash32::sha256(&blob.ct.0)),
                ),
                ctx.now,
            )?;
            Ok(Done::Ok(next))
        })
    }

    fn record(&self, pk: VaultPk, e: AuditEvent, now: i64) -> Result<(), StoreError> {
        self.write(|tx| {
            if tx
                .query_row("SELECT 1 FROM vaults WHERE pk = ?1", [pk], |_| Ok(()))
                .optional()?
                .is_none()
            {
                return Err(StoreError::NotFound);
            }
            append_audit(tx, pk, e, now)?;
            Ok(Done::Ok(()))
        })
    }

    fn audit_after(
        &self,
        pk: VaultPk,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<AuditRow>, Option<ChainHead>), StoreError> {
        self.read(|c| {
            let mut stmt = c.prepare(&format!(
                "SELECT {AUDIT_COLS} FROM audit WHERE vault_pk = ?1 AND seq > ?2 ORDER BY seq LIMIT ?3"
            ))?;
            let rows = stmt
                .query_map(params![pk, after as i64, limit as i64], audit_row)?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            let head = c
                .query_row(
                    "SELECT audit_seq, audit_head FROM vaults WHERE pk = ?1",
                    [pk],
                    |r| Ok((r.get::<_, i64>(0)?, blob::<32>(r, 1)?)),
                )
                .optional()?
                .filter(|(seq, _)| *seq > 0)
                .map(|(seq, hash)| ChainHead::new(seq as u64, Hash32(hash)));
            Ok((rows, head))
        })
    }

    fn apply_rotation(
        &self,
        pk: VaultPk,
        r: &RotationRequest,
        ctx: Ctx,
        hook: CommitHook<'_>,
    ) -> Result<u32, StoreError> {
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            let generation = rotate(tx, &vault, r, ctx, true)?;
            journal(
                tx,
                JournalOp::Rotate {
                    vault_id: vault.vault_id,
                    actor: ctx.actor,
                    request: r.clone(),
                },
                ctx.now,
                hook,
            )?;
            Ok(Done::Ok(generation))
        })
    }

    fn delete_vault(&self, pk: VaultPk, now: i64, hook: CommitHook<'_>) -> Result<(), StoreError> {
        self.write(|tx| {
            let vault = load_vault(tx, pk)?.ok_or(StoreError::NotFound)?;
            tx.execute("DELETE FROM vaults WHERE pk = ?1", [pk])?;
            journal(
                tx,
                JournalOp::DeleteVault {
                    vault_id: vault.vault_id,
                },
                now,
                hook,
            )?;
            Ok(Done::Ok(()))
        })
    }

    fn spend(
        &self,
        kind: SpentKind,
        id: &[u8],
        expires_at: i64,
        now: i64,
    ) -> Result<(), StoreError> {
        self.write(|tx| {
            tx.execute("DELETE FROM spent WHERE expires_at < ?1", [now])?;
            match tx.execute(
                "INSERT INTO spent (kind, id, expires_at) VALUES (?1, ?2, ?3)",
                params![kind as i64, id, expires_at],
            ) {
                Ok(_) => Ok(Done::Ok(())),
                Err(e) => match StoreError::from(e) {
                    StoreError::Exists => Ok(Done::Refused(StoreError::Spent)),
                    other => Err(other),
                },
            }
        })
    }

    fn journal_applied(&self) -> Result<u64, StoreError> {
        self.read(|c| {
            Ok(c.query_row(
                "SELECT last_applied FROM journal_state WHERE id = 1",
                [],
                |r| r.get::<_, i64>(0),
            )? as u64)
        })
    }

    fn replay(&self, record: &JournalRecord) -> Result<bool, StoreError> {
        self.write(|tx| {
            let last: i64 = tx.query_row(
                "SELECT last_applied FROM journal_state WHERE id = 1",
                [],
                |r| r.get(0),
            )?;
            if record.seq <= last as u64 {
                return Ok(Done::Ok(false));
            }
            let applied = match &record.op {
                JournalOp::RevokeTokens {
                    vault_id,
                    token_ids,
                    actor,
                    reported,
                } => match load_vault_by_id(tx, vault_id)? {
                    None => false,
                    Some(vault) => {
                        let removed = delete_tokens(tx, vault.pk, token_ids)?;
                        let action = if *reported {
                            AuditAction::TokenReport
                        } else {
                            AuditAction::TokenRevoke
                        };
                        for id in &removed {
                            append_audit(
                                tx,
                                vault.pk,
                                event(*actor, action, None, Some(*id), AuditResult::Ok),
                                record.ts,
                            )?;
                        }
                        if !removed.is_empty() {
                            bump_revision(tx, vault.pk)?;
                        }
                        !removed.is_empty()
                    }
                },
                JournalOp::Rotate {
                    vault_id,
                    actor,
                    request,
                } => match load_vault_by_id(tx, vault_id)? {
                    Some(vault) if vault.generation == request.from_generation => {
                        rotate(
                            tx,
                            &vault,
                            request,
                            Ctx {
                                actor: *actor,
                                now: record.ts,
                            },
                            false,
                        )?;
                        true
                    }
                    _ => false,
                },
                JournalOp::DeleteVault { vault_id } => {
                    tx.execute("DELETE FROM vaults WHERE vault_id = ?1", [&vault_id.0[..]])? > 0
                }
            };
            tx.execute(
                "UPDATE journal_state SET last_applied = ?1 WHERE id = 1",
                [record.seq as i64],
            )?;
            Ok(Done::Ok(applied))
        })
    }
}
