//! The journaled operations: revoke, report, rotate, delete, and the replay
//! that makes them survive a restore. The protocol has no rekey endpoint: a
//! re-root is client-driven (new vaults, ordinary writes, deletions).

mod common;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{Harness, Pre};
use galata_vault_keys::{FullBundle, TokenKeys};
use galata_vault_proto::api::{
    DescriptorList, ReportTokenRequest, RevokeResponse, RotationRequest, Scope, SecretVersion,
};
use galata_vault_proto::audit::AuditAction;
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{Hash32, Sig64, TokenId};
use galata_vault_proto::record::RecordKind;
use galata_vault_seal::{Writer, build_rotation, open_secret};
use galata_vault_server::journal::{FileJournal, Journal};
use galata_vault_server::replay_journal;
use galata_vault_store::{JournalOp, JournalRecord, SqliteStore, Store, StoreConfig};

struct Down;

impl Journal for Down {
    fn put(&self, _: &JournalRecord) -> Result<(), String> {
        Err("journal bucket unreachable".into())
    }
    // Opening the core replays the journal, so this one lists nothing
    // rather than fail: its puts are what the tests break.
    fn list_after(&self, _: u64) -> Result<Vec<JournalRecord>, String> {
        Ok(vec![])
    }
    fn check(&self) -> Result<(), String> {
        Err("journal bucket unreachable".into())
    }
    fn describe(&self) -> String {
        "down".into()
    }
}

fn journal_of(h: &Harness) -> Vec<JournalRecord> {
    FileJournal::open(&h.journal_dir)
        .unwrap()
        .list_after(0)
        .unwrap()
}

fn token_path(t: &TokenKeys) -> String {
    format!("/v1/tokens/{}", t.id().to_hex())
}

#[tokio::test]
async fn revocation_is_journaled_before_it_is_acknowledged() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let read = h.mint(&v, Scope::Read).await;

    let r = h
        .send(h.signed(&v.owner, "DELETE", &token_path(&read), vec![]))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let revoked: RevokeResponse = serde_json::from_value(r.body).unwrap();
    assert_eq!(revoked.revoked, [read.id()]);

    let journal = journal_of(&h);
    assert!(
        matches!(&journal[..], [JournalRecord { op: JournalOp::RevokeTokens { token_ids, reported: false, .. }, .. }] if token_ids == &[read.id()])
    );
    assert_eq!(
        h.get(&read, "/v1/vault").await.code(),
        "unauthorized",
        "a revoked token is refused like an unknown one"
    );
}

#[tokio::test]
async fn a_failed_journal_write_is_a_503_and_changes_nothing() {
    let h = Harness::with_journal(Arc::new(Down));
    let v = h.create_vault().await;
    let read = h.mint(&v, Scope::Read).await;
    let r = h
        .send(h.signed(&v.owner, "DELETE", &token_path(&read), vec![]))
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::SERVICE_UNAVAILABLE, "unavailable")
    );
    assert_eq!(
        h.get(&read, "/v1/vault").await.status,
        StatusCode::OK,
        "the revocation was not applied"
    );
    let r = h
        .send(Request::get("/readyz").body(Body::empty()).unwrap())
        .await;
    assert_eq!(
        r.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness goes red"
    );
    // Ordinary writes never wait on the journal: they carry on.
    assert_eq!(
        h.write(&v, "DURING_OUTAGE", b"v", Pre::Create).await.status,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn admins_revoke_but_only_the_owner_rotates_or_deletes() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let admin = h.mint(&v, Scope::Admin).await;
    let meta = h.mint(&v, Scope::Meta).await;
    let victim = h.mint(&v, Scope::Read).await;

    let path = token_path(&victim);
    assert_eq!(
        h.send(h.signed(&meta, "DELETE", &path, vec![]))
            .await
            .code(),
        "forbidden"
    );
    assert_eq!(
        h.send(h.signed(&admin, "DELETE", &path, vec![]))
            .await
            .status,
        StatusCode::OK
    );
    for (method, path) in [("POST", "/v1/vault/rotations"), ("DELETE", "/v1/vault")] {
        let r = h.send(h.signed(&admin, method, path, b"{}".to_vec())).await;
        assert_eq!(r.code(), "forbidden", "{method} {path}");
    }
    // There is no server-side rekey in the protocol.
    let r = h
        .send(h.signed(&v.owner, "POST", "/v1/vault/rekey", b"{}".to_vec()))
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
}

#[tokio::test]
async fn a_leaked_token_is_reported_by_proving_possession() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let leaked = h.mint(&v, Scope::Read).await;
    let report = |body: Vec<u8>| {
        h.send(
            Request::post("/v1/tokens/report")
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
    };
    let signed = |token_id: TokenId, ts: i64, sig: Sig64| {
        serde_json::to_vec(&ReportTokenRequest::new(token_id, ts, sig)).unwrap()
    };
    let now = h.now();

    // Every failure is the same 401: a signature by another key, a stale
    // time, an unknown token.
    let other = TokenKeys::generate(v.id());
    let unknown = TokenKeys::generate(v.id());
    let mut bodies = Vec::new();
    for body in [
        signed(leaked.id(), now, other.sign_report(now)),
        signed(leaked.id(), now - 301, leaked.sign_report(now - 301)),
        signed(unknown.id(), now, unknown.sign_report(now)),
    ] {
        let r = report(body).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.body);
        bodies.push(r.body);
    }
    assert!(bodies.windows(2).all(|w| w[0] == w[1]));
    // The token string itself is never sent, and never accepted.
    let with_string = serde_json::json!({ "token": leaked.token_string().as_str() });
    let r = report(with_string.to_string().into_bytes()).await;
    assert_eq!(r.code(), "invalid_request");
    assert_eq!(
        h.get(&leaked, "/v1/vault").await.status,
        StatusCode::OK,
        "nothing was revoked"
    );

    let r = report(signed(leaked.id(), now, leaked.sign_report(now))).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let revoked: RevokeResponse = serde_json::from_value(r.body).unwrap();
    assert_eq!(revoked.revoked, [leaked.id()]);
    assert_eq!(h.get(&leaked, "/v1/vault").await.code(), "unauthorized");

    let (rows, _) = h.store.audit_after(h.pk(&v), 0, 1000).unwrap();
    let row = rows
        .iter()
        .find(|r| r.action == AuditAction::TokenReport)
        .unwrap();
    assert_eq!(row.subject, Some(leaked.id()));
    assert!(
        journal_of(&h)
            .iter()
            .any(|r| matches!(r.op, JournalOp::RevokeTokens { reported: true, .. }))
    );
}

#[tokio::test]
async fn a_client_driven_rotation_moves_the_whole_vault() {
    let h = Harness::new();
    let mut v = h.create_vault().await;
    h.write(&v, "DATABASE_URL", b"postgres://secret", Pre::Create)
        .await;
    h.write(&v, "STRIPE_KEY", b"sk_live", Pre::Create).await;
    let meta = h.mint(&v, Scope::Meta).await;
    let read = h.mint(&v, Scope::Read).await;
    let (old_full, old_descriptor) = (v.full.clone(), v.descriptor.clone());

    let (r, rotation) = h.rotate(&v, &[read.id()]).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["generation"], 2);
    let replayed = rotation.request.clone();
    v.rotated(rotation);

    // The owner verifies the new generation and reads the re-encrypted value.
    let status = h.status(&v.owner).await;
    let d = status
        .descriptor
        .verify_for(&v.id(), &status.owner_sign_pub)
        .unwrap();
    assert_eq!(d, v.descriptor);
    assert!(d.follows(&old_descriptor));
    let next = v
        .owner
        .open_own_bundle(&status.owner_bundle.unwrap(), 2)
        .unwrap();
    assert!(next.matches(&d));
    let latest: SecretVersion = h.fetch(&v.owner, &v.secret_path("DATABASE_URL")).await;
    let opened = open_secret(&d, &next.name_key, &next.vault_secret, &latest).unwrap();
    assert_eq!(opened.value.unwrap().as_slice(), b"postgres://secret");
    assert!(
        open_secret(
            &old_descriptor,
            &old_full.name_key,
            &old_full.vault_secret,
            &latest
        )
        .is_err(),
        "the old generation neither verifies nor opens it"
    );

    // The revoked token is gone; the surviving meta token holds generation 2.
    assert_eq!(h.get(&read, "/v1/vault").await.code(), "unauthorized");
    let (_, md, names) = h.token_bundle(&meta).await;
    assert_eq!((md.generation, names.generation()), (2, 2));

    // Every holder can walk the chain from generation 1.
    let chain: DescriptorList = h.fetch(&meta, "/v1/vault/descriptors").await;
    let chain: Vec<Descriptor> = chain
        .descriptors
        .iter()
        .map(|s| s.verify_for(&v.id(), &v.owner.sign_pub()).unwrap())
        .collect();
    assert_eq!(chain.len(), 2);
    assert!(chain[0].is_first() && chain[1].follows(&chain[0]));
    assert_eq!((&chain[0], &chain[1]), (&old_descriptor, &v.descriptor));
    let newer: DescriptorList = h.fetch(&meta, "/v1/vault/descriptors?after=1").await;
    assert_eq!(newer.descriptors.len(), 1);

    // A write still signed for the old generation is refused.
    let old_writer = Writer {
        descriptor: &old_descriptor,
        name_key: &old_full.name_key,
        writer: &old_full.secret_writer,
    };
    let stale = old_writer.secret("NEW", b"x", 1, h.now()).unwrap();
    assert_eq!(
        h.put(&v.owner, &stale, Pre::Create).await.code(),
        "stale_generation"
    );

    // A second batch built from the old state is refused.
    let r = h
        .send(h.signed(
            &v.owner,
            "POST",
            "/v1/vault/rotations",
            serde_json::to_vec(&replayed).unwrap(),
        ))
        .await;
    assert_eq!(r.code(), "conflict");
    assert!(
        journal_of(&h)
            .iter()
            .any(|r| matches!(r.op, JournalOp::Rotate { .. }))
    );
}

#[tokio::test]
async fn a_rotation_is_verified_before_anything_changes() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "K", b"v", Pre::Create).await;
    h.mint(&v, Scope::Meta).await;
    let status = h.status(&v.owner).await;
    let build = || {
        build_rotation(
            &v.owner,
            &status,
            &v.descriptor,
            &v.full,
            &h.versions(&v, RecordKind::Secret),
            &h.versions(&v, RecordKind::Config),
            &[],
            h.now(),
        )
        .unwrap()
        .request
    };
    let submit = |request: RotationRequest| {
        h.send(h.signed(
            &v.owner,
            "POST",
            "/v1/vault/rotations",
            serde_json::to_vec(&request).unwrap(),
        ))
    };

    // A new generation that does not link to the current one.
    let mut unlinked = build();
    let rogue = FullBundle::generate(2).descriptor(v.id(), Hash32([9; 32]), h.now());
    unlinked.descriptor = v.owner.sign_descriptor(&rogue);
    assert_eq!(submit(unlinked).await.code(), "key_mismatch");

    // A record, the owner bundle or a token bundle whose signature fails.
    let mut record = build();
    record.secrets[0].sig = Sig64([0; 64]);
    let mut owner_bundle = build();
    owner_bundle.owner_bundle.sig = Sig64([0; 64]);
    let mut token_bundle = build();
    token_bundle.tokens[0].bundle.sig = Sig64([0; 64]);
    for bad in [record, owner_bundle, token_bundle] {
        let r = submit(bad).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::UNPROCESSABLE_ENTITY, "bad_signature")
        );
    }
    assert_eq!(h.status(&v.owner).await.generation, 1, "nothing changed");
    assert!(journal_of(&h).is_empty());
}

#[tokio::test]
async fn deleting_a_vault_removes_it_and_its_tokens() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let meta = h.mint(&v, Scope::Meta).await;
    let r = h
        .send(h.signed(&v.owner, "DELETE", "/v1/vault", vec![]))
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(h.get(&v.owner, "/v1/vault").await.code(), "unauthorized");
    assert_eq!(h.get(&meta, "/v1/vault").await.code(), "unauthorized");
    assert!(
        journal_of(&h)
            .iter()
            .any(|r| matches!(r.op, JournalOp::DeleteVault { .. }))
    );
}

#[tokio::test]
async fn replay_brings_a_restored_database_back_to_what_was_acknowledged() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let read = h.mint(&v, Scope::Read).await;
    let backup = h.dir.path().join("backup.db");
    h.store.checkpoint().unwrap();
    std::fs::copy(h.db_path(), &backup).unwrap();

    let r = h
        .send(h.signed(&v.owner, "DELETE", &token_path(&read), vec![]))
        .await;
    assert_eq!(r.status, StatusCode::OK);

    let restored = SqliteStore::open(StoreConfig::new(&backup)).unwrap();
    assert!(
        restored.token_by_id(&read.id()).unwrap().is_some(),
        "the backup predates the revocation"
    );
    let journal = FileJournal::open(&h.journal_dir).unwrap();
    assert_eq!(replay_journal(&restored, &journal).unwrap(), 1);
    assert!(restored.token_by_id(&read.id()).unwrap().is_none());
    assert_eq!(
        replay_journal(&restored, &journal).unwrap(),
        0,
        "nothing left to replay"
    );
}
