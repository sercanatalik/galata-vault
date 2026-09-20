//! The store's contract, one behaviour per test.

use galata_vault_proto::api::{
    Limits, ResealedBundle, RotatedVersion, RotationRequest, Scope, SignedBundle,
};
use galata_vault_proto::audit::{Actor, AuditAction, AuditEvent, AuditResult, verify_chain};
use galata_vault_proto::children::ChildrenBlob;
use galata_vault_proto::descriptor::SignedDescriptor;
use galata_vault_proto::ids::{B64, Hash32, Key32, NameHmac, Sig64, TokenId, VaultId};
use galata_vault_store::{
    Ctx, JournalOp, JournalRecord, NewToken, NewVault, Precondition, Quota, RecordKind,
    RecordWrite, SpentKind, SqliteStore, Store, StoreConfig, StoreError, VaultRow,
};
use tempfile::TempDir;

const T0: i64 = 1_757_500_000;
const DAY: i64 = 86_400;

fn owner(now: i64) -> Ctx {
    Ctx {
        actor: Actor::Owner,
        now,
    }
}

fn open() -> (TempDir, SqliteStore) {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(StoreConfig::new(dir.path().join("vault.db"))).unwrap();
    (dir, store)
}

fn sig(n: u8) -> Sig64 {
    Sig64([n; 64])
}

fn bundle(n: u8) -> SignedBundle {
    SignedBundle::new(B64(vec![n; 70]), sig(n))
}

fn descriptor(n: u8) -> SignedDescriptor {
    SignedDescriptor::from_parts(B64(vec![n; 189]), sig(n))
}

fn new_vault(store: &SqliteStore, seed: u8) -> VaultRow {
    store
        .create_vault(
            &NewVault {
                vault_id: VaultId([seed; 16]),
                owner_sign_pub: Key32([seed; 32]),
                owner_box_pub: Key32([seed.wrapping_add(1); 32]),
                descriptor: descriptor(seed),
                owner_bundle: bundle(seed),
            },
            T0,
        )
        .unwrap()
}

fn name(n: u8) -> NameHmac {
    NameHmac([n; 32])
}

/// A signed write of `value` as `version`. The store does not verify
/// signatures (the server does); it stores them.
fn write(generation: u32, version: u64, value: &[u8]) -> RecordWrite {
    RecordWrite {
        name_ct: b"nm".to_vec(),
        value_ct: Some(value.to_vec()),
        generation,
        version,
        written_at: T0 + version as i64,
        sig: sig(version as u8),
    }
}

fn tombstone(generation: u32, version: u64) -> RecordWrite {
    RecordWrite {
        value_ct: None,
        ..write(generation, version, b"")
    }
}

fn token(seed: u8, scope: Scope, generation: u32, expires_at: i64) -> NewToken {
    NewToken {
        token_id: TokenId([seed; 16]),
        auth_pub: Key32([seed; 32]),
        box_pub: Key32([seed.wrapping_add(1); 32]),
        scope,
        expires_at,
        bundle: bundle(seed),
        generation,
        allow_list: None,
    }
}

fn ok(_: &JournalRecord) -> Result<(), String> {
    Ok(())
}

fn limits() -> Limits {
    Limits::default()
}

#[test]
fn create_and_refuse_a_duplicate() {
    let (_d, store) = open();
    let v = new_vault(&store, 1);
    assert_eq!((v.generation, v.revision, v.bytes_used), (1, 1, 0));
    assert_eq!(v.descriptor, descriptor(1));
    assert_eq!(v.owner_bundle, bundle(1));
    assert_eq!(
        store.vault_by_id(&VaultId([1; 16])).unwrap(),
        Some(v.clone())
    );
    let again = store.create_vault(
        &NewVault {
            vault_id: VaultId([1; 16]),
            owner_sign_pub: Key32([9; 32]),
            owner_box_pub: Key32([9; 32]),
            descriptor: descriptor(9),
            owner_bundle: bundle(9),
        },
        T0,
    );
    assert_eq!(again, Err(StoreError::Exists));
    assert_eq!(store.descriptors(v.pk, 0).unwrap(), [descriptor(1)]);
    // The creation row names the descriptor it registered.
    let (rows, _) = store.audit_after(v.pk, 0, 10).unwrap();
    assert_eq!(rows[0].action, AuditAction::VaultCreate);
    assert_eq!(rows[0].ct_hash, Some(Hash32::sha256(&[1; 189])));
}

#[test]
fn refuses_a_database_not_in_wal_mode() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("legacy.db");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.query_row("PRAGMA journal_mode = DELETE", [], |_| Ok(()))
        .unwrap();
    c.execute_batch("CREATE TABLE t (x INTEGER)").unwrap();
    drop(c);
    assert!(matches!(
        SqliteStore::open(StoreConfig::new(&path)),
        Err(StoreError::NotWal(mode)) if mode == "delete"
    ));
}

#[test]
fn refuses_a_database_a_newer_binary_migrated() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("newer.db");
    let c = rusqlite::Connection::open(&path).unwrap();
    c.query_row("PRAGMA journal_mode = WAL", [], |_| Ok(()))
        .unwrap();
    c.execute_batch(
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
         INSERT INTO schema_migrations VALUES (1, 0), (2, 0);",
    )
    .unwrap();
    drop(c);
    let err = SqliteStore::open(StoreConfig::new(&path)).err().unwrap();
    assert_eq!(err, StoreError::NewerSchema { found: 2, known: 1 });
    assert!(err.to_string().contains("newer"));
}

#[test]
fn conditional_writes_and_the_signed_version() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let n = name(1);
    let put = |pre, version, v: &[u8]| {
        store.put_record(
            pk,
            RecordKind::Secret,
            &n,
            pre,
            &write(1, version, v),
            owner(T0),
            &limits(),
        )
    };

    assert_eq!(put(Precondition::IfNoneMatch, 1, b"a"), Ok(1));
    assert_eq!(
        put(Precondition::IfNoneMatch, 1, b"b"),
        Err(StoreError::PreconditionFailed { current: Some(1) })
    );
    // The precondition holds, but the writer signed the wrong version.
    assert_eq!(
        put(Precondition::IfMatch(1), 5, b"b"),
        Err(StoreError::VersionMismatch {
            signed: 5,
            assigned: 2
        })
    );
    assert_eq!(put(Precondition::IfMatch(1), 2, b"b"), Ok(2));
    assert_eq!(
        put(Precondition::IfMatch(1), 2, b"c"),
        Err(StoreError::PreconditionFailed { current: Some(2) })
    );
    assert_eq!(
        store.put_record(
            pk,
            RecordKind::Secret,
            &name(2),
            Precondition::IfMatch(5),
            &write(1, 6, b"x"),
            owner(T0),
            &limits()
        ),
        Err(StoreError::PreconditionFailed { current: None })
    );
    let latest = store
        .latest_record(pk, RecordKind::Secret, &n)
        .unwrap()
        .unwrap();
    assert_eq!(
        (latest.version, latest.value_ct.as_deref(), latest.sig),
        (2, Some(&b"b"[..]), sig(2))
    );
    assert_eq!(latest.written_at, T0 + 2, "the signed write time is kept");
    // Two successful writes; refusals do not move the revision.
    assert_eq!(store.vault_by_pk(pk).unwrap().unwrap().revision, 3);
    // Every refusal is audited; every write names its version and ciphertext.
    let (rows, _) = store.audit_after(pk, 0, 100).unwrap();
    assert_eq!(
        rows.iter()
            .filter(|r| r.result == AuditResult::Refused)
            .count(),
        4
    );
    let last_put = rows
        .iter()
        .rev()
        .find(|r| r.action == AuditAction::SecretPut && r.result == AuditResult::Ok)
        .unwrap();
    assert_eq!(
        (last_put.version, last_put.ct_hash),
        (2, Some(Hash32::sha256(b"b")))
    );
}

#[test]
fn stale_generation_is_refused_and_audited() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let r = store.put_record(
        pk,
        RecordKind::Secret,
        &name(1),
        Precondition::IfNoneMatch,
        &write(2, 1, b"x"),
        owner(T0),
        &limits(),
    );
    assert_eq!(r, Err(StoreError::StaleGeneration));
    let (rows, _) = store.audit_after(pk, 0, 100).unwrap();
    let kinds: Vec<_> = rows.iter().map(|r| (r.action, r.result)).collect();
    assert_eq!(
        kinds,
        [
            (AuditAction::VaultCreate, AuditResult::Ok),
            (AuditAction::SecretPut, AuditResult::Refused)
        ]
    );
}

#[test]
fn versions_are_pruned_and_bytes_tracked() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let l = {
        let mut patched = limits();
        patched.max_versions = 3;
        patched
    };
    let n = name(1);
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &n,
            Precondition::IfNoneMatch,
            &write(1, 1, b"0123"),
            owner(T0),
            &l,
        )
        .unwrap();
    for v in 1..5 {
        store
            .put_record(
                pk,
                RecordKind::Secret,
                &n,
                Precondition::IfMatch(v),
                &write(1, v + 1, b"0123"),
                owner(T0),
                &l,
            )
            .unwrap();
    }
    let kept: Vec<u64> = store
        .record_versions(pk, RecordKind::Secret, &n)
        .unwrap()
        .iter()
        .map(|v| v.version)
        .collect();
    assert_eq!(kept, [3, 4, 5]);
    // 3 versions × (2-byte name_ct + 4-byte value).
    assert_eq!(store.vault_by_pk(pk).unwrap().unwrap().bytes_used, 18);
}

#[test]
fn delete_writes_a_signed_tombstone_and_revives() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let n = name(1);
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &n,
            Precondition::IfNoneMatch,
            &write(1, 1, b"v"),
            owner(T0),
            &limits(),
        )
        .unwrap();
    assert_eq!(
        store.delete_record(
            pk,
            RecordKind::Secret,
            &n,
            7,
            &tombstone(1, 8),
            owner(T0),
            &limits()
        ),
        Err(StoreError::PreconditionFailed { current: Some(1) })
    );
    assert_eq!(
        store.delete_record(
            pk,
            RecordKind::Secret,
            &n,
            1,
            &tombstone(1, 3),
            owner(T0),
            &limits()
        ),
        Err(StoreError::VersionMismatch {
            signed: 3,
            assigned: 2
        })
    );
    assert_eq!(
        store.delete_record(
            pk,
            RecordKind::Secret,
            &n,
            1,
            &tombstone(1, 2),
            owner(T0),
            &limits()
        ),
        Ok(2)
    );
    let latest = store
        .latest_record(pk, RecordKind::Secret, &n)
        .unwrap()
        .unwrap();
    assert!(latest.tombstone && latest.value_ct.is_none());
    assert_eq!(latest.sig, sig(2), "the tombstone keeps its signature");
    assert_eq!(
        store.delete_record(
            pk,
            RecordKind::Secret,
            &n,
            2,
            &tombstone(1, 3),
            owner(T0),
            &limits()
        ),
        Err(StoreError::NotFound)
    );
    assert_eq!(
        store.put_record(
            pk,
            RecordKind::Secret,
            &n,
            Precondition::IfMatch(2),
            &write(1, 3, b"w"),
            owner(T0),
            &limits()
        ),
        Err(StoreError::PreconditionFailed { current: Some(2) })
    );
    assert_eq!(
        store.put_record(
            pk,
            RecordKind::Secret,
            &n,
            Precondition::IfNoneMatch,
            &write(1, 3, b"w"),
            owner(T0),
            &limits()
        ),
        Ok(3)
    );
    let heads = store
        .list_records(pk, RecordKind::Secret, None, 10)
        .unwrap();
    assert_eq!(
        (heads.len(), heads[0].version, heads[0].tombstone),
        (1, 3, false)
    );
    assert_eq!(heads[0].value_ct_hash, Hash32::sha256(b"w"));
    assert_eq!((heads[0].generation, heads[0].sig), (1, sig(3)));
}

#[test]
fn a_listed_tombstone_carries_the_hash_of_an_empty_value() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &name(1),
            Precondition::IfNoneMatch,
            &write(1, 1, b"v"),
            owner(T0),
            &limits(),
        )
        .unwrap();
    store
        .delete_record(
            pk,
            RecordKind::Secret,
            &name(1),
            1,
            &tombstone(1, 2),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let head = &store
        .list_records(pk, RecordKind::Secret, None, 10)
        .unwrap()[0];
    assert!(head.tombstone);
    assert_eq!(head.value_ct_hash, Hash32::sha256(b""));
}

#[test]
fn quotas_are_enforced_and_named() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let l = {
        let mut patched = limits();
        patched.max_names = 2;
        patched.max_value_bytes = 8;
        patched.max_vault_bytes = 30;
        patched.max_tokens = 1;
        patched
    };
    let put = |n: u8, pre, version, v: &[u8]| {
        store.put_record(
            pk,
            RecordKind::Secret,
            &name(n),
            pre,
            &write(1, version, v),
            owner(T0),
            &l,
        )
    };
    assert_eq!(
        put(1, Precondition::IfNoneMatch, 1, b"123456789"),
        Err(StoreError::Quota(Quota::ValueSize))
    );
    assert_eq!(put(1, Precondition::IfNoneMatch, 1, b"1234"), Ok(1));
    assert_eq!(put(2, Precondition::IfNoneMatch, 1, b"1234"), Ok(1));
    assert_eq!(
        put(3, Precondition::IfNoneMatch, 1, b"1234"),
        Err(StoreError::Quota(Quota::Names))
    );
    // Updating an existing name is not a new name. Each version is 2 bytes of
    // name_ct plus its value: 6 + 6 + 6 + 10 = 28 fits in 30; another 6 does not.
    assert_eq!(put(1, Precondition::IfMatch(1), 2, b"1234"), Ok(2));
    assert_eq!(put(1, Precondition::IfMatch(2), 3, b"12345678"), Ok(3));
    assert_eq!(
        put(1, Precondition::IfMatch(3), 4, b"1234"),
        Err(StoreError::Quota(Quota::VaultBytes))
    );

    store
        .register_token(pk, &token(1, Scope::Read, 1, T0 + DAY), owner(T0), &l)
        .unwrap();
    assert_eq!(
        store.register_token(pk, &token(2, Scope::Read, 1, T0 + DAY), owner(T0), &l),
        Err(StoreError::Quota(Quota::Tokens))
    );
    // An expired token no longer counts.
    assert!(
        store
            .register_token(
                pk,
                &token(3, Scope::Read, 1, T0 + 2 * DAY),
                owner(T0 + DAY + 1),
                &l
            )
            .is_ok()
    );
}

#[test]
fn tokens_store_public_keys_and_their_signed_bundle() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let row = store
        .register_token(
            pk,
            &token(4, Scope::Config, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    assert_eq!(
        (row.auth_pub, row.box_pub, row.bundle.clone()),
        (Key32([4; 32]), Key32([5; 32]), bundle(4))
    );
    assert_eq!(store.token_by_id(&TokenId([4; 16])).unwrap(), Some(row));
    assert_eq!(
        store.register_token(
            pk,
            &token(5, Scope::Read, 2, T0 + DAY),
            owner(T0),
            &limits()
        ),
        Err(StoreError::StaleGeneration)
    );
}

#[test]
fn the_audit_chain_verifies_and_records_refusals() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let n = name(1);
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &n,
            Precondition::IfNoneMatch,
            &write(1, 1, b"a"),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let _ = store.put_record(
        pk,
        RecordKind::Secret,
        &n,
        Precondition::IfNoneMatch,
        &write(1, 1, b"b"),
        owner(T0),
        &limits(),
    );
    store
        .register_token(
            pk,
            &token(5, Scope::Meta, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    store
        .record(
            pk,
            AuditEvent {
                version: 1,
                ct_hash: Some(Hash32::sha256(b"a")),
                ..AuditEvent::simple(
                    Actor::Token(TokenId([5; 16])),
                    AuditAction::SecretRead,
                    Some(n),
                    AuditResult::Ok,
                )
            },
            T0 + 1,
        )
        .unwrap();
    let (rows, head) = store.audit_after(pk, 0, 1000).unwrap();
    assert_eq!(verify_chain(None, &rows).unwrap(), head);
    assert_eq!(
        rows.iter()
            .filter(|r| r.result == AuditResult::Refused)
            .count(),
        1
    );
    let mint = rows
        .iter()
        .find(|r| r.action == AuditAction::TokenMint)
        .unwrap();
    assert_eq!(mint.subject, Some(TokenId([5; 16])));
    let read = rows.last().unwrap();
    assert_eq!(
        (read.version, read.ct_hash),
        (1, Some(Hash32::sha256(b"a")))
    );
    // Paging continues the chain from a remembered head.
    let (tail, _) = store.audit_after(pk, 2, 1000).unwrap();
    assert!(verify_chain(Some(&rows[1].head()), &tail).is_ok());
}

#[test]
fn the_children_record_is_versioned() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    let blob =
        |version: u64| ChildrenBlob::new(version, B64(vec![version as u8; 48]), sig(version as u8));
    assert_eq!(store.children(pk).unwrap(), None);
    assert_eq!(
        store.put_children(pk, Precondition::IfMatch(1), &blob(2), owner(T0), &limits()),
        Err(StoreError::PreconditionFailed { current: None })
    );
    assert_eq!(
        store.put_children(
            pk,
            Precondition::IfNoneMatch,
            &blob(1),
            owner(T0),
            &limits()
        ),
        Ok(1)
    );
    assert_eq!(
        store.put_children(
            pk,
            Precondition::IfNoneMatch,
            &blob(2),
            owner(T0),
            &limits()
        ),
        Err(StoreError::PreconditionFailed { current: Some(1) })
    );
    assert_eq!(
        store.put_children(pk, Precondition::IfMatch(1), &blob(3), owner(T0), &limits()),
        Err(StoreError::VersionMismatch {
            signed: 3,
            assigned: 2
        })
    );
    assert_eq!(
        store.put_children(pk, Precondition::IfMatch(1), &blob(2), owner(T0), &limits()),
        Ok(2)
    );
    assert_eq!(store.children(pk).unwrap(), Some(blob(2)));
    let (rows, _) = store.audit_after(pk, 0, 100).unwrap();
    let last = rows.last().unwrap();
    assert_eq!(
        (last.action, last.version, last.ct_hash),
        (
            AuditAction::ChildrenWrite,
            2,
            Some(Hash32::sha256(&[2; 48]))
        )
    );
    // A children write is not a record: a rotation built before it still applies.
    assert_eq!(store.vault_by_pk(pk).unwrap().unwrap().revision, 1);
}

#[test]
fn revocation_goes_through_the_journal() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    for seed in [1, 2] {
        store
            .register_token(
                pk,
                &token(seed, Scope::Read, 1, T0 + DAY),
                owner(T0),
                &limits(),
            )
            .unwrap();
    }
    let mut seen = Vec::new();
    let removed = store
        .revoke_tokens(
            pk,
            &[TokenId([1; 16])],
            false,
            owner(T0),
            &mut |r: &JournalRecord| {
                seen.push(r.clone());
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(removed, [TokenId([1; 16])]);
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].seq, 1);
    assert!(
        matches!(&seen[0].op, JournalOp::RevokeTokens { token_ids, reported: false, .. } if token_ids == &[TokenId([1; 16])])
    );
    assert!(store.token_by_id(&TokenId([1; 16])).unwrap().is_none());
    assert_eq!(store.tokens(pk).unwrap().len(), 1);
    assert_eq!(
        store.revoke_tokens(pk, &[TokenId([1; 16])], false, owner(T0), &mut ok),
        Err(StoreError::NotFound)
    );
    assert_eq!(store.journal_applied().unwrap(), 1);
}

#[test]
fn a_failed_journal_write_rolls_everything_back() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    store
        .register_token(
            pk,
            &token(1, Scope::Read, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let before = store.vault_by_pk(pk).unwrap().unwrap();
    let r = store.revoke_tokens(
        pk,
        &[TokenId([1; 16])],
        false,
        owner(T0),
        &mut |_: &JournalRecord| Err("journal bucket unreachable".to_string()),
    );
    assert!(matches!(r, Err(StoreError::Journal(_))));
    assert!(store.token_by_id(&TokenId([1; 16])).unwrap().is_some());
    assert_eq!(store.vault_by_pk(pk).unwrap().unwrap(), before);
    assert_eq!(store.journal_applied().unwrap(), 0);
}

/// Two names (one with two versions), one tombstone, a read token to revoke
/// and a meta token that survives.
fn rotation_fixture(store: &SqliteStore) -> (i64, RotationRequest) {
    let pk = new_vault(store, 1).pk;
    let put = |n: u8, pre, version| {
        store
            .put_record(
                pk,
                RecordKind::Secret,
                &name(n),
                pre,
                &write(1, version, b"old"),
                owner(T0),
                &limits(),
            )
            .unwrap()
    };
    put(1, Precondition::IfNoneMatch, 1);
    put(1, Precondition::IfMatch(1), 2);
    put(2, Precondition::IfNoneMatch, 1);
    store
        .delete_record(
            pk,
            RecordKind::Secret,
            &name(2),
            1,
            &tombstone(1, 2),
            owner(T0),
            &limits(),
        )
        .unwrap();
    store
        .register_token(
            pk,
            &token(7, Scope::Read, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    store
        .register_token(
            pk,
            &token(8, Scope::Meta, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let vault = store.vault_by_pk(pk).unwrap().unwrap();
    let secrets = store
        .all_record_versions(pk, RecordKind::Secret)
        .unwrap()
        .into_iter()
        .map(|v| {
            RotatedVersion::new(
                v.name_hmac,
                v.version,
                NameHmac([v.name_hmac.0[0] + 100; 32]),
                B64(b"new-nm".to_vec()),
                v.value_ct.map(|_| B64(b"new-value".to_vec())),
                v.written_at,
                sig(99),
            )
        })
        .collect();
    let request = RotationRequest::new(
        vault.generation,
        vault.revision,
        descriptor(42),
        bundle(42),
        secrets,
        Vec::new(),
        vec![ResealedBundle::new(TokenId([8; 16]), bundle(88))],
        vec![TokenId([7; 16])],
    );
    (pk, request)
}

#[test]
fn rotation_applies_atomically() {
    let (_d, store) = open();
    let (pk, request) = rotation_fixture(&store);
    let before = store.all_record_versions(pk, RecordKind::Secret).unwrap();
    assert_eq!(
        store.apply_rotation(pk, &request, owner(T0 + 9), &mut ok),
        Ok(2)
    );

    let vault = store.vault_by_pk(pk).unwrap().unwrap();
    assert_eq!(
        (
            vault.generation,
            vault.descriptor.clone(),
            vault.owner_bundle.clone()
        ),
        (2, descriptor(42), bundle(42))
    );
    assert_eq!(
        store.descriptors(pk, 0).unwrap(),
        [descriptor(1), descriptor(42)]
    );
    assert_eq!(store.descriptors(pk, 1).unwrap(), [descriptor(42)]);
    let after = store.all_record_versions(pk, RecordKind::Secret).unwrap();
    assert_eq!(after.len(), before.len());
    for (old, new) in before.iter().zip(&after) {
        assert_eq!(new.name_hmac.0[0], old.name_hmac.0[0] + 100);
        assert_eq!(
            (new.version, new.tombstone, new.written_at),
            (old.version, old.tombstone, old.written_at)
        );
        assert_eq!((new.generation, new.sig), (2, sig(99)));
    }
    let tokens = store.tokens(pk).unwrap();
    assert_eq!(tokens.len(), 1);
    assert_eq!(
        (
            tokens[0].token_id,
            tokens[0].generation,
            tokens[0].bundle.clone()
        ),
        (TokenId([8; 16]), 2, bundle(88))
    );
    // The tombstoned name is still a tombstone under its new index.
    let heads = store
        .list_records(pk, RecordKind::Secret, None, 10)
        .unwrap();
    assert_eq!(heads.iter().filter(|h| h.tombstone).count(), 1);
    // The rotation row names the new descriptor.
    let (rows, _) = store.audit_after(pk, 0, 100).unwrap();
    let rotate = rows
        .iter()
        .find(|r| r.action == AuditAction::VaultRotate)
        .unwrap();
    assert_eq!(rotate.ct_hash, Some(Hash32::sha256(&[42; 189])));
    // Rotated vaults accept writes only for the new generation.
    assert_eq!(
        store.put_record(
            pk,
            RecordKind::Secret,
            &name(101),
            Precondition::IfMatch(2),
            &write(1, 3, b"x"),
            owner(T0),
            &limits()
        ),
        Err(StoreError::StaleGeneration)
    );
}

#[test]
fn stale_or_incomplete_rotations_are_refused() {
    let (_d, store) = open();
    let (pk, request) = rotation_fixture(&store);

    let mut stale = request.clone();
    stale.from_revision -= 1;
    assert_eq!(
        store.apply_rotation(pk, &stale, owner(T0), &mut ok),
        Err(StoreError::Conflict)
    );

    let mut missing_version = request.clone();
    missing_version.secrets.pop();
    assert!(matches!(
        store.apply_rotation(pk, &missing_version, owner(T0), &mut ok),
        Err(StoreError::IncompleteRotation(_))
    ));

    let mut missing_token = request.clone();
    missing_token.tokens.clear();
    assert!(matches!(
        store.apply_rotation(pk, &missing_token, owner(T0), &mut ok),
        Err(StoreError::IncompleteRotation(_))
    ));

    let mut untombstoned = request.clone();
    for s in &mut untombstoned.secrets {
        s.value_ct.get_or_insert(B64(vec![1]));
    }
    assert!(matches!(
        store.apply_rotation(pk, &untombstoned, owner(T0), &mut ok),
        Err(StoreError::IncompleteRotation(_))
    ));

    let mut retimed = request.clone();
    retimed.secrets[0].written_at += 1;
    assert!(matches!(
        store.apply_rotation(pk, &retimed, owner(T0), &mut ok),
        Err(StoreError::IncompleteRotation(_))
    ));

    assert_eq!(
        store.vault_by_pk(pk).unwrap().unwrap().generation,
        1,
        "nothing was applied"
    );
}

#[test]
fn deleting_a_vault_removes_everything_and_is_journaled() {
    let (_d, store) = open();
    let pk = new_vault(&store, 1).pk;
    store
        .register_token(
            pk,
            &token(1, Scope::Read, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &name(1),
            Precondition::IfNoneMatch,
            &write(1, 1, b"v"),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let mut ops = Vec::new();
    store
        .delete_vault(pk, T0, &mut |r: &JournalRecord| {
            ops.push(r.op.clone());
            Ok(())
        })
        .unwrap();
    assert!(
        matches!(ops.as_slice(), [JournalOp::DeleteVault { vault_id }] if *vault_id == VaultId([1; 16]))
    );
    assert!(store.vault_by_pk(pk).unwrap().is_none());
    assert!(store.token_by_id(&TokenId([1; 16])).unwrap().is_none());
    assert!(
        store
            .all_record_versions(pk, RecordKind::Secret)
            .unwrap()
            .is_empty()
    );
    assert!(store.descriptors(pk, 0).unwrap().is_empty());
}

#[test]
fn identifiers_are_single_use_until_they_expire() {
    let (_d, store) = open();
    assert_eq!(
        store.spend(SpentKind::Challenge, b"abc", T0 + 600, T0),
        Ok(())
    );
    assert_eq!(
        store.spend(SpentKind::Challenge, b"abc", T0 + 600, T0 + 1),
        Err(StoreError::Spent)
    );
    assert_eq!(
        store.spend(SpentKind::Nonce, b"abc", T0 + 600, T0 + 1),
        Ok(()),
        "kinds are separate"
    );
    assert_eq!(
        store.spend(SpentKind::Challenge, b"abc", T0 + 1200, T0 + 601),
        Ok(()),
        "purged after expiry"
    );
}

/// Take a file copy (the "backup"), make acknowledged changes, restore the
/// copy, replay the journal: the changes come back.
#[test]
fn journal_replay_restores_acknowledged_operations() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live.db");
    let backup = dir.path().join("backup.db");
    let store = SqliteStore::open(StoreConfig::new(&live)).unwrap();
    let pk = new_vault(&store, 1).pk;
    store
        .register_token(
            pk,
            &token(1, Scope::Read, 1, T0 + DAY),
            owner(T0),
            &limits(),
        )
        .unwrap();
    let doomed = new_vault(&store, 2).pk;
    store.checkpoint().unwrap();
    std::fs::copy(&live, &backup).unwrap();

    let mut journal = Vec::new();
    let mut capture = |r: &JournalRecord| {
        journal.push(JournalRecord::from_json(&r.to_json()).unwrap());
        Ok(())
    };
    store
        .revoke_tokens(pk, &[TokenId([1; 16])], false, owner(T0 + 5), &mut capture)
        .unwrap();
    store.delete_vault(doomed, T0 + 6, &mut capture).unwrap();
    assert_eq!(journal.iter().map(|r| r.seq).collect::<Vec<_>>(), [1, 2]);
    drop(store);

    let restored = SqliteStore::open(StoreConfig::new(&backup)).unwrap();
    assert!(
        restored.token_by_id(&TokenId([1; 16])).unwrap().is_some(),
        "the backup predates the revocation"
    );
    assert_eq!(restored.journal_applied().unwrap(), 0);
    for record in &journal {
        assert!(restored.replay(record).unwrap());
    }
    assert!(restored.token_by_id(&TokenId([1; 16])).unwrap().is_none());
    assert!(restored.vault_by_id(&VaultId([2; 16])).unwrap().is_none());
    assert_eq!(restored.journal_applied().unwrap(), 2);
    // Idempotent: a second replay changes nothing.
    for record in &journal {
        assert!(!restored.replay(record).unwrap());
    }
    // The restored chain still verifies, including the replayed revocation.
    let (rows, head) = restored.audit_after(pk, 0, 100).unwrap();
    assert_eq!(verify_chain(None, &rows).unwrap(), head);
}

/// A rotation journaled after the backup is replayed onto the restored copy,
/// descriptor included.
#[test]
fn journal_replay_restores_a_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let live = dir.path().join("live.db");
    let backup = dir.path().join("backup.db");
    let store = SqliteStore::open(StoreConfig::new(&live)).unwrap();
    let (pk, request) = rotation_fixture(&store);
    store.checkpoint().unwrap();
    std::fs::copy(&live, &backup).unwrap();
    let mut journal = Vec::new();
    store
        .apply_rotation(pk, &request, owner(T0 + 9), &mut |r: &JournalRecord| {
            journal.push(r.clone());
            Ok(())
        })
        .unwrap();
    drop(store);

    let restored = SqliteStore::open(StoreConfig::new(&backup)).unwrap();
    assert!(restored.replay(&journal[0]).unwrap());
    let vault = restored.vault_by_pk(pk).unwrap().unwrap();
    assert_eq!((vault.generation, vault.descriptor), (2, descriptor(42)));
    assert!(restored.token_by_id(&TokenId([7; 16])).unwrap().is_none());
}
