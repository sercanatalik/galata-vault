//! The schema. Portable SQL: no `WITHOUT ROWID`, no SQLite-only types,
//! `ON CONFLICT … DO UPDATE` rather than `INSERT OR REPLACE`.
//!
//! Note what is absent: no project, path or plaintext name column, and no
//! client address anywhere. `spent` holds challenge ids and signature nonces.
//!
//! A database a newer binary has migrated is refused, never written to.

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;

use crate::backend::StoreError;

/// The first schema version.
const FIRST: i64 = 1;

const MIGRATIONS: &[(i64, &str)] = &[(
    FIRST,
    r#"
CREATE TABLE vaults (
    pk               INTEGER PRIMARY KEY,
    vault_id         BLOB    NOT NULL UNIQUE,
    owner_sign_pub   BLOB    NOT NULL,
    owner_box_pub    BLOB    NOT NULL,
    owner_bundle     BLOB    NOT NULL,
    owner_bundle_sig BLOB    NOT NULL,
    generation       INTEGER NOT NULL,
    revision         INTEGER NOT NULL,
    created_at       INTEGER NOT NULL,
    last_active_at   INTEGER NOT NULL,
    bytes_used       INTEGER NOT NULL,
    audit_seq        INTEGER NOT NULL,
    audit_head       BLOB    NOT NULL
);
CREATE INDEX vaults_last_active ON vaults (last_active_at);

CREATE TABLE descriptors (
    vault_pk   INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    generation INTEGER NOT NULL,
    descriptor BLOB    NOT NULL,
    sig        BLOB    NOT NULL,
    PRIMARY KEY (vault_pk, generation)
);

CREATE TABLE tokens (
    token_id    BLOB    PRIMARY KEY,
    vault_pk    INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    auth_pub    BLOB    NOT NULL,
    box_pub     BLOB    NOT NULL,
    scope       TEXT    NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    bundle      BLOB    NOT NULL,
    bundle_sig  BLOB    NOT NULL,
    generation  INTEGER NOT NULL,
    allow_list  TEXT
);
CREATE INDEX tokens_vault ON tokens (vault_pk);

CREATE TABLE secrets (
    vault_pk   INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    name_hmac  BLOB    NOT NULL,
    version    INTEGER NOT NULL,
    name_ct    BLOB    NOT NULL,
    value_ct   BLOB,
    ct_hash    BLOB    NOT NULL,
    generation INTEGER NOT NULL,
    written_at INTEGER NOT NULL,
    written_by BLOB,
    tombstone  INTEGER NOT NULL,
    sig        BLOB    NOT NULL,
    PRIMARY KEY (vault_pk, name_hmac, version)
);

CREATE TABLE heads (
    vault_pk        INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    name_hmac       BLOB    NOT NULL,
    current_version INTEGER NOT NULL,
    tombstone       INTEGER NOT NULL,
    PRIMARY KEY (vault_pk, name_hmac)
);

CREATE TABLE configs (
    vault_pk   INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    name_hmac  BLOB    NOT NULL,
    version    INTEGER NOT NULL,
    name_ct    BLOB    NOT NULL,
    value_ct   BLOB,
    ct_hash    BLOB    NOT NULL,
    generation INTEGER NOT NULL,
    written_at INTEGER NOT NULL,
    written_by BLOB,
    tombstone  INTEGER NOT NULL,
    sig        BLOB    NOT NULL,
    PRIMARY KEY (vault_pk, name_hmac, version)
);

CREATE TABLE config_heads (
    vault_pk        INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    name_hmac       BLOB    NOT NULL,
    current_version INTEGER NOT NULL,
    tombstone       INTEGER NOT NULL,
    PRIMARY KEY (vault_pk, name_hmac)
);

CREATE TABLE children (
    vault_pk INTEGER PRIMARY KEY REFERENCES vaults (pk) ON DELETE CASCADE,
    version  INTEGER NOT NULL,
    ct       BLOB    NOT NULL,
    sig      BLOB    NOT NULL
);

CREATE TABLE audit (
    vault_pk  INTEGER NOT NULL REFERENCES vaults (pk) ON DELETE CASCADE,
    seq       INTEGER NOT NULL,
    ts        INTEGER NOT NULL,
    actor     BLOB,
    action    INTEGER NOT NULL,
    name_hmac BLOB,
    subject   BLOB,
    result    INTEGER NOT NULL,
    version   INTEGER NOT NULL,
    ct_hash   BLOB,
    prev      BLOB    NOT NULL,
    hash      BLOB    NOT NULL,
    v         INTEGER NOT NULL,
    PRIMARY KEY (vault_pk, seq)
);

CREATE TABLE journal_state (
    id           INTEGER PRIMARY KEY CHECK (id = 1),
    last_applied INTEGER NOT NULL
);
INSERT INTO journal_state (id, last_applied) VALUES (1, 0);

CREATE TABLE spent (
    kind       INTEGER NOT NULL,
    id         BLOB    NOT NULL,
    expires_at INTEGER NOT NULL,
    PRIMARY KEY (kind, id)
);
CREATE INDEX spent_expiry ON spent (expires_at);
"#,
)];

pub(crate) fn migrate(conn: &Connection) -> Result<(), StoreError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
             version    INTEGER PRIMARY KEY,
             applied_at INTEGER NOT NULL
         )",
    )?;
    let newest: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migrations",
        [],
        |r| r.get(0),
    )?;
    // A database a newer binary has migrated is refused, so this binary can
    // never write, say, a rotation that leaves out a record kind it does not
    // know.
    let known = MIGRATIONS.last().map_or(0, |(v, _)| *v);
    if newest > known {
        return Err(StoreError::NewerSchema {
            found: newest,
            known,
        });
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs() as i64);
    for (version, sql) in MIGRATIONS {
        let applied: bool = conn.query_row(
            "SELECT EXISTS (SELECT 1 FROM schema_migrations WHERE version = ?1)",
            [version],
            |r| r.get(0),
        )?;
        if applied {
            continue;
        }
        let tx = conn.unchecked_transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?1, ?2)",
            [*version, now],
        )?;
        tx.commit()?;
    }
    check_shape(conn)
}

/// Every table this binary's migrations define, compared column by column
/// with the table on disk.
///
/// The expected shape is what `MIGRATIONS` produce in a fresh in-memory
/// database — never a second, hand-kept list that a later migration could
/// forget to update. Found on 2026-09-25: version 1's SQL had been edited in
/// place before the first release, so a pre-release database recorded
/// version 1, was skipped by `migrate`, and failed at its first write.
fn check_shape(conn: &Connection) -> Result<(), StoreError> {
    let fresh = Connection::open_in_memory()?;
    for (_, sql) in MIGRATIONS {
        fresh.execute_batch(sql)?;
    }
    let mut tables = fresh.prepare(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
    )?;
    let names: Vec<String> = tables
        .query_map([], |r| r.get(0))?
        .collect::<Result<_, _>>()?;
    for table in names {
        let want = columns(&fresh, &table)?;
        let have = columns(conn, &table)?;
        if have.is_empty() {
            return Err(StoreError::ReshapedSchema {
                table,
                detail: "it is missing".into(),
            });
        }
        if let Some((name, kind)) = want.iter().find(|c| !have.contains(c)) {
            return Err(StoreError::ReshapedSchema {
                table,
                detail: format!("column {name} {kind} is missing"),
            });
        }
        if let Some((name, kind)) = have.iter().find(|c| !want.contains(c)) {
            return Err(StoreError::ReshapedSchema {
                table,
                detail: format!("column {name} {kind} is not in this build's schema"),
            });
        }
    }
    Ok(())
}

/// A table's columns as (name, declared type), in declaration order.
fn columns(conn: &Connection, table: &str) -> Result<Vec<(String, String)>, StoreError> {
    // `table` comes from sqlite_master of this binary's own migrations, never
    // from input; PRAGMA takes no bound parameter.
    let mut stmt = conn.prepare(&format!("PRAGMA table_info(\"{table}\")"))?;
    let cols = stmt
        .query_map([], |r| Ok((r.get::<_, String>(1)?, r.get::<_, String>(2)?)))?
        .collect::<Result<_, _>>()?;
    Ok(cols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_database_this_binary_made_opens() {
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        // And again: an opened store is reopened on every start.
        migrate(&conn).unwrap();
    }

    #[test]
    fn a_reshaped_version_1_database_is_refused_by_name() {
        // What a pre-release database looks like: version 1 recorded, and
        // `vaults` without the column version 1 gained before release.
        let conn = Connection::open_in_memory().unwrap();
        migrate(&conn).unwrap();
        conn.execute_batch("ALTER TABLE vaults DROP COLUMN owner_bundle_sig")
            .unwrap();
        match migrate(&conn) {
            Err(StoreError::ReshapedSchema { table, detail }) => {
                assert_eq!(table, "vaults");
                assert!(detail.contains("owner_bundle_sig"), "{detail}");
            }
            other => panic!("expected ReshapedSchema, got {other:?}"),
        }
    }
}
