//! Concurrency: no lost updates, and a rotation built on a stale view of the
//! vault is refused rather than silently dropping a write.

use std::sync::{Arc, Mutex};
use std::thread;

use galata_vault::backend::{
    Ctx, JournalRecord, NewVault, Precondition, RecordKind, RecordWrite, SqliteStore, Store,
    StoreConfig, StoreError,
};
use galata_vault::proto::api::{Limits, RotatedVersion, RotationRequest, SignedBundle};
use galata_vault::proto::audit::Actor;
use galata_vault::proto::descriptor::SignedDescriptor;
use galata_vault::proto::ids::{B64, Key32, NameHmac, Sig64, VaultId};

const T0: i64 = 1_757_500_000;

fn ctx() -> Ctx {
    Ctx {
        actor: Actor::Owner,
        now: T0,
    }
}

fn write(version: u64, value: &str) -> RecordWrite {
    RecordWrite {
        name_ct: b"nm".to_vec(),
        value_ct: Some(value.as_bytes().to_vec()),
        generation: 1,
        version,
        written_at: T0,
        sig: Sig64([1; 64]),
    }
}

fn bundle(n: u8) -> SignedBundle {
    SignedBundle::new(B64(vec![n; 70]), Sig64([n; 64]))
}

fn setup() -> (tempfile::TempDir, Arc<SqliteStore>, i64) {
    let dir = tempfile::tempdir().unwrap();
    let store = SqliteStore::open(StoreConfig::new(dir.path().join("vault.db"))).unwrap();
    let pk = store
        .create_vault(
            &NewVault {
                vault_id: VaultId([1; 16]),
                owner_sign_pub: Key32([1; 32]),
                owner_box_pub: Key32([2; 32]),
                descriptor: SignedDescriptor::from_parts(B64(vec![1; 189]), Sig64([1; 64])),
                owner_bundle: bundle(1),
            },
            T0,
        )
        .unwrap()
        .pk;
    (dir, Arc::new(store), pk)
}

#[test]
fn many_writers_on_one_secret_lose_no_update() {
    let (_dir, store, pk) = setup();
    let name = NameHmac([7; 32]);
    let limits = {
        let mut patched = Limits::default();
        patched.max_versions = 10_000;
        patched
    };
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &name,
            Precondition::IfNoneMatch,
            &write(1, "seed"),
            ctx(),
            &limits,
        )
        .unwrap();

    let won = Arc::new(Mutex::new(Vec::new()));
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let (store, won) = (Arc::clone(&store), Arc::clone(&won));
            thread::spawn(move || {
                let mut conflicts = 0;
                for i in 0..25 {
                    let current = store
                        .latest_record(pk, RecordKind::Secret, &name)
                        .unwrap()
                        .unwrap()
                        .version;
                    // Each writer signs the version its precondition would create.
                    match store.put_record(
                        pk,
                        RecordKind::Secret,
                        &name,
                        Precondition::IfMatch(current),
                        &write(current + 1, &format!("t{t}-{i}")),
                        ctx(),
                        &limits,
                    ) {
                        Ok(v) => won.lock().unwrap().push((v, format!("t{t}-{i}"))),
                        Err(StoreError::PreconditionFailed { .. }) => conflicts += 1,
                        Err(e) => panic!("unexpected: {e}"),
                    }
                }
                conflicts
            })
        })
        .collect();
    let conflicts: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();

    let mut won = won.lock().unwrap().clone();
    won.sort();
    let last = store
        .latest_record(pk, RecordKind::Secret, &name)
        .unwrap()
        .unwrap()
        .version;
    // Every successful write got a distinct version, and they are exactly 2..=last.
    assert_eq!(
        won.iter().map(|(v, _)| *v).collect::<Vec<_>>(),
        (2..=last).collect::<Vec<_>>()
    );
    assert_eq!(won.len() + conflicts, 8 * 25);
    // And each stored version holds the value of the writer that won it.
    for (version, value) in &won {
        let row = store
            .record_version(pk, RecordKind::Secret, &name, *version)
            .unwrap()
            .unwrap();
        assert_eq!(row.value_ct.unwrap(), value.as_bytes());
    }
}

#[test]
fn a_rotation_built_before_a_concurrent_write_is_refused() {
    let (_dir, store, pk) = setup();
    let name = NameHmac([7; 32]);
    let limits = Limits::default();
    store
        .put_record(
            pk,
            RecordKind::Secret,
            &name,
            Precondition::IfNoneMatch,
            &write(1, "v1"),
            ctx(),
            &limits,
        )
        .unwrap();

    // The rotating client reads the vault...
    let vault = store.vault_by_pk(pk).unwrap().unwrap();
    let request = RotationRequest::new(
        vault.generation,
        vault.revision,
        SignedDescriptor::from_parts(B64(vec![9; 189]), Sig64([9; 64])),
        bundle(9),
        store
            .all_record_versions(pk, RecordKind::Secret)
            .unwrap()
            .into_iter()
            .map(|v| {
                RotatedVersion::new(
                    v.name_hmac,
                    v.version,
                    NameHmac([8; 32]),
                    B64(b"n".to_vec()),
                    Some(B64(b"re-encrypted".to_vec())),
                    v.written_at,
                    Sig64([9; 64]),
                )
            })
            .collect(),
        Vec::new(),
        vec![],
        vec![],
    );

    // ...another writer lands in between...
    let writer = {
        let store = Arc::clone(&store);
        thread::spawn(move || {
            store
                .put_record(
                    pk,
                    RecordKind::Secret,
                    &name,
                    Precondition::IfMatch(1),
                    &write(2, "v2"),
                    ctx(),
                    &Limits::default(),
                )
                .unwrap()
        })
    };
    assert_eq!(writer.join().unwrap(), 2);

    // ...so the batch would drop v2. It is refused, and nothing changes.
    let mut hook =
        |_: &JournalRecord| -> Result<(), String> { panic!("must not journal a refused rotation") };
    assert_eq!(
        store.apply_rotation(pk, &request, ctx(), &mut hook),
        Err(StoreError::Conflict)
    );
    let after = store.vault_by_pk(pk).unwrap().unwrap();
    assert_eq!(after.generation, 1);
    assert_eq!(
        store
            .latest_record(pk, RecordKind::Secret, &name)
            .unwrap()
            .unwrap()
            .value_ct
            .unwrap(),
        b"v2"
    );
}
