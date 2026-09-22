//! The HTTP surface, driven in-process by a real client: vaults, request
//! signatures for owners and tokens, scopes, the descriptor chain, the
//! children record and hygiene.

#[path = "server_common/mod.rs"]
mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use std::io::Write;
use std::sync::{Arc, Mutex};

use common::{As, DAY, Harness, Pre, Reply, record_path, with_header};
use galata_vault::backend::Store;
use galata_vault::keys::{FullBundle, NodeKey, TokenKeys, seal_for_scope, seal_owner_bundle};
use galata_vault::proto::api::{DescriptorList, Scope, VaultStatus};
use galata_vault::proto::audit::{AuditAction, AuditResult};
use galata_vault::proto::children::{ChildEntry, ChildMode, ChildrenBlob, ChildrenRecord};
use galata_vault::proto::ids::{Hash32, VaultId};
use galata_vault::proto::path::Segment;
use zeroize::Zeroizing;

#[tokio::test]
async fn a_vault_is_created_without_registration() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let r = h.get(&v.owner, "/v1/vault").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(r.headers.get("x-gv-expires-at").is_none());
    let status: VaultStatus = serde_json::from_value(r.body).unwrap();
    assert_eq!(status.vault_id, v.id());
    assert_eq!(status.generation, 1);
    assert_eq!(status.tokens, Some(vec![]));
    // What every client checks: the owner key hashes to the pinned id and
    // signed both the descriptor and the owner bundle.
    let d = status
        .descriptor
        .verify_for(&v.id(), &status.owner_sign_pub)
        .unwrap();
    assert_eq!(d, v.descriptor);
    let bundle = v
        .owner
        .open_own_bundle(&status.owner_bundle.unwrap(), 1)
        .unwrap();
    assert!(bundle.matches(&d));
}

/// What creation refuses. `defaults.rs` covers the challenge this server
/// never issues.
#[tokio::test]
async fn creation_refusals() {
    let h = Harness::new();

    let (v, mut mismatch) = h.creation(&NodeKey::generate()).await;
    mismatch.vault_id = VaultId([7; 16]);
    assert_eq!(
        h.submit(&v.owner, &mismatch).await.code(),
        "vault_id_mismatch"
    );

    let (_, wrong_signer) = h.creation(&NodeKey::generate()).await;
    let r = h.submit(&NodeKey::generate().owner(), &wrong_signer).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNAUTHORIZED, "unauthorized")
    );

    // Generation 1's descriptor and owner bundle must be the owner's.
    let (v, mut foreign) = h.creation(&NodeKey::generate()).await;
    let impostor = NodeKey::generate().owner();
    foreign.descriptor =
        impostor.sign_descriptor(&v.full.descriptor(impostor.vault_id(), Hash32([0; 32]), 0));
    assert_eq!(h.submit(&v.owner, &foreign).await.code(), "bad_signature");

    let (v, mut later) = h.creation(&NodeKey::generate()).await;
    later.descriptor =
        v.owner
            .sign_descriptor(&FullBundle::generate(2).descriptor(v.id(), Hash32([1; 32]), 0));
    assert_eq!(h.submit(&v.owner, &later).await.code(), "invalid_request");

    let (v, mut foreign_bundle) = h.creation(&NodeKey::generate()).await;
    foreign_bundle.owner_bundle = seal_owner_bundle(&NodeKey::generate().owner(), &v.full).unwrap();
    assert_eq!(
        h.submit(&v.owner, &foreign_bundle).await.code(),
        "bad_signature"
    );

    // The same node twice: its vault id already exists.
    let node = NodeKey::generate();
    let (v, first) = h.creation(&node).await;
    assert_eq!(h.submit(&v.owner, &first).await.status, StatusCode::CREATED);
    let (v, second) = h.creation(&node).await;
    assert_eq!(h.submit(&v.owner, &second).await.code(), "conflict");
}

#[tokio::test]
async fn request_signatures_resist_replay_skew_and_tampering() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let meta = h.mint(&v, Scope::Meta).await;

    // Owner and token requests alike: each signature is spent once.
    for req in [
        h.signed(&v.owner, "GET", "/v1/vault", vec![]),
        h.signed(&meta, "GET", "/v1/vault", vec![]),
    ] {
        let auth = req.headers()["authorization"].clone();
        assert_eq!(h.send(req).await.status, StatusCode::OK);
        let replay = Request::get("/v1/vault")
            .header("authorization", auth)
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            h.send(replay).await.code(),
            "unauthorized",
            "a replay is refused"
        );
    }

    let stale = h.req_at(
        &v.owner,
        "GET",
        "/v1/vault",
        vec![],
        Pre::None,
        h.now() - 301,
    );
    assert_eq!(h.send(stale).await.code(), "unauthorized");

    // Signed for one body, sent with another.
    let t = TokenKeys::generate(v.id());
    let signed_body = serde_json::to_vec(&Harness::registration(&v, &t, Scope::Meta, 0)).unwrap();
    let mut tampered = h.signed(&v.owner, "POST", "/v1/tokens", signed_body);
    *tampered.body_mut() =
        Body::from(serde_json::to_vec(&Harness::registration(&v, &t, Scope::Read, 0)).unwrap());
    assert_eq!(h.send(tampered).await.code(), "unauthorized");

    // A precondition is signed: one added or changed afterwards fails.
    let rec = v.secret("K", b"v", 1, h.now());
    let body = serde_json::to_vec(&rec.put_request().unwrap()).unwrap();
    let added = with_header(
        h.signed(&v.owner, "PUT", &record_path(&rec), body.clone()),
        "if-none-match",
        "*",
    );
    assert_eq!(h.send(added).await.code(), "unauthorized");
    let changed = with_header(
        h.req(&v.owner, "PUT", &record_path(&rec), body, Pre::Create),
        "if-none-match",
        "\"1\"",
    );
    assert_eq!(h.send(changed).await.code(), "unauthorized");
    assert_eq!(
        h.put(&v.owner, &rec, Pre::Create).await.status,
        StatusCode::CREATED,
        "signed as sent, it lands"
    );
}

#[tokio::test]
async fn bearer_v1_and_unknown_credentials_fail_uniformly() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let meta = h.mint(&v, Scope::Meta).await;

    let r = h.get(&meta, "/v1/vault").await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert!(
        r.body["tokens"].is_null(),
        "only owner and admin see the token list"
    );
    assert!(r.body["owner_bundle"].is_null());

    // The token string as a bearer credential, a v=1 signature, a malformed
    // one, and none at all.
    let signed = h.signed(&meta, "GET", "/v1/vault", vec![]);
    let signed_auth = signed.headers()["authorization"]
        .to_str()
        .unwrap()
        .to_owned();
    let mut bodies = Vec::new();
    for header in [
        Some(format!("Bearer {}", meta.token_string().as_str())),
        Some(signed_auth.replacen("v=1", "v=2", 1)),
        Some("GV-Sig v=1,actor=token".to_owned()),
        None,
    ] {
        let mut req = Request::get("/v1/vault");
        if let Some(value) = header {
            req = req.header("authorization", value);
        }
        let r = h.send(req.body(Body::empty()).unwrap()).await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED, "{:?}", r.body);
        bodies.push(r.body);
    }
    // An unknown token, the right id with the wrong secret, and the right id
    // presented for another vault.
    let unknown = TokenKeys::generate(v.id());
    let wrong_secret = TokenKeys::from_parts(meta.id(), v.id(), Zeroizing::new([9; 32]));
    let elsewhere = TokenKeys::from_parts(meta.id(), VaultId([7; 16]), Zeroizing::new([9; 32]));
    for t in [&unknown, &wrong_secret, &elsewhere] {
        let r = h.get(t, "/v1/vault").await;
        assert_eq!(r.status, StatusCode::UNAUTHORIZED);
        bodies.push(r.body);
    }
    assert!(
        bodies.windows(2).all(|w| w[0] == w[1]),
        "failures are indistinguishable"
    );

    // Only a holder that proved possession learns its token expired.
    let short = h.mint_with(&v, Scope::Meta, 60).await;
    h.advance(61);
    let r = h.get(&short, "/v1/vault").await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNAUTHORIZED, "token_expired")
    );
}

#[tokio::test]
async fn only_the_owner_mints_tokens_and_refusals_are_audited() {
    let h = Harness::new();
    let v = h.create_vault().await;
    for scope in Scope::ALL {
        let t = h.mint(&v, scope).await;
        let request = Harness::registration(&v, &TokenKeys::generate(v.id()), Scope::Meta, 0);
        let r = h.register(&t, &request).await;
        assert_eq!(
            (r.status, r.code()),
            (StatusCode::FORBIDDEN, "forbidden"),
            "{scope}"
        );
    }
    let (rows, _) = h.store.audit_after(h.pk(&v), 0, 1000).unwrap();
    let refused = rows
        .iter()
        .filter(|r| r.action == AuditAction::TokenMint && r.result == AuditResult::Refused)
        .count();
    assert_eq!(refused, Scope::ALL.len(), "admin included");
}

#[tokio::test]
async fn token_registration_is_validated() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let t = TokenKeys::generate(v.id());

    let too_long = Harness::registration(&v, &t, Scope::Admin, 31 * DAY as u64);
    assert_eq!(h.register(&v.owner, &too_long).await.code(), "ttl_too_long");

    let mut listed_meta = Harness::registration(&v, &t, Scope::Meta, 0);
    listed_meta.allow_list = Some(vec![v.full.name_key.hmac("X")]);
    assert_eq!(
        h.register(&v.owner, &listed_meta).await.code(),
        "invalid_request"
    );

    // The bundle is owner-signed for exactly this token, scope and generation.
    let mut other_scope = Harness::registration(&v, &t, Scope::Meta, 0);
    other_scope.scope = Scope::Config;
    assert_eq!(
        h.register(&v.owner, &other_scope).await.code(),
        "bad_signature"
    );
    let mut other_token = Harness::registration(&v, &t, Scope::Meta, 0);
    other_token.token_id = TokenKeys::generate(v.id()).id();
    assert_eq!(
        h.register(&v.owner, &other_token).await.code(),
        "bad_signature"
    );
    let mut forged = Harness::registration(&v, &t, Scope::Meta, 0);
    forged.bundle = seal_for_scope(
        &NodeKey::generate().owner(),
        &t.box_pub(),
        &t.id(),
        Scope::Meta,
        &v.full,
    )
    .unwrap();
    assert_eq!(h.register(&v.owner, &forged).await.code(), "bad_signature");

    // Honestly signed, for a generation the vault is not at.
    let mut stale = Harness::registration(&v, &t, Scope::Meta, 0);
    stale.generation = 2;
    stale.bundle = seal_for_scope(
        &v.owner,
        &t.box_pub(),
        &t.id(),
        Scope::Meta,
        &FullBundle::generate(2),
    )
    .unwrap();
    assert_eq!(
        h.register(&v.owner, &stale).await.code(),
        "stale_generation"
    );

    let ok = Harness::registration(&v, &t, Scope::Meta, 0);
    assert_eq!(h.register(&v.owner, &ok).await.status, StatusCode::CREATED);
    assert_eq!(
        h.register(&v.owner, &ok).await.code(),
        "conflict",
        "a token id registers once"
    );

    let junk = br#"{"scope":"meta","secret":"sk_live_123"}"#.to_vec();
    let r = h.send(h.signed(&v.owner, "POST", "/v1/tokens", junk)).await;
    assert_eq!(r.code(), "invalid_request");
    assert!(
        !r.body.to_string().contains("sk_live_123"),
        "errors never echo the body"
    );
}

#[tokio::test]
async fn a_token_verifies_its_vault_and_opens_its_bundle() {
    let h = Harness::new();
    let v = h.create_vault().await;
    for scope in Scope::ALL {
        let t = h.mint(&v, scope).await;
        let (me, d, bundle) = h.token_bundle(&t).await;
        assert_eq!(
            (me.token_id, me.scope.get(), me.vault_id),
            (t.id(), Some(scope), v.id())
        );
        assert_eq!(d, v.descriptor);
        assert!(bundle.matches(&d), "{scope}");
        assert_eq!(
            bundle.holds_vault_secret(),
            scope.bundle_holds_vault_key(),
            "{scope}"
        );
    }
    let r = h.get(&v.owner, "/v1/tokens/self").await;
    assert_eq!(r.code(), "invalid_request");
}

#[tokio::test]
async fn every_holder_fetches_the_descriptor_chain() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let meta = h.mint(&v, Scope::Meta).await;
    let list: DescriptorList = h.fetch(&meta, "/v1/vault/descriptors").await;
    assert_eq!(list.descriptors.len(), 1);
    assert_eq!(
        list.descriptors[0]
            .verify_for(&v.id(), &v.owner.sign_pub())
            .unwrap(),
        v.descriptor
    );
    let later: DescriptorList = h.fetch(&meta, "/v1/vault/descriptors?after=1").await;
    assert!(later.descriptors.is_empty());
    assert_eq!(
        h.get(&meta, "/v1/vault/descriptors?after=x").await.code(),
        "invalid_request"
    );
}

async fn put_children(h: &Harness, who: As<'_>, blob: &ChildrenBlob, pre: Pre) -> Reply {
    let body = serde_json::to_vec(blob).unwrap();
    h.send(h.req(who, "PUT", "/v1/vault/children", body, pre))
        .await
}

#[tokio::test]
async fn the_children_record_is_owner_only_signed_and_versioned() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let owner = As::Owner(&v.owner);
    let admin = h.mint(&v, Scope::Admin).await;
    let mut record = ChildrenRecord::new();
    record
        .insert(ChildEntry::new(
            Segment::new("prod").unwrap(),
            1,
            ChildMode::Derived,
        ))
        .unwrap();

    assert_eq!(
        h.get(&v.owner, "/v1/vault/children").await.code(),
        "not_found"
    );

    // No token writes or reads it, whatever its scope.
    let first = v.owner.seal_children(1, &record).unwrap();
    let r = put_children(&h, As::Token(&admin), &first, Pre::Create).await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, "forbidden"));
    assert_eq!(
        h.get(&admin, "/v1/vault/children").await.status,
        StatusCode::FORBIDDEN
    );

    let r = put_children(&h, owner, &first, Pre::Create).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.headers["etag"], "\"1\"");

    // It signs the version it creates, and a stale precondition loses.
    let r = put_children(
        &h,
        owner,
        &v.owner.seal_children(1, &record).unwrap(),
        Pre::Match(1),
    )
    .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, "version_mismatch")
    );
    let second = v.owner.seal_children(2, &record).unwrap();
    for pre in [Pre::Match(7), Pre::Create] {
        let r = put_children(&h, owner, &second, pre).await;
        assert_eq!(r.code(), "precondition_failed", "{pre:?}");
    }

    // A record the owner did not sign.
    let forged = {
        let mut patched = second.clone();
        patched.sig = NodeKey::generate()
            .owner()
            .seal_children(2, &record)
            .unwrap()
            .sig;
        patched
    };
    let r = put_children(&h, owner, &forged, Pre::Match(1)).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "bad_signature")
    );

    let r = put_children(&h, owner, &second, Pre::Match(1)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let got: ChildrenBlob = h.fetch(&v.owner, "/v1/vault/children").await;
    assert_eq!(got.version, 2);
    assert_eq!(v.owner.open_children(&got).unwrap(), record);

    let (rows, _) = h.store.audit_after(h.pk(&v), 0, 1000).unwrap();
    let writes = |result: AuditResult| {
        rows.iter()
            .filter(|r| r.action == AuditAction::ChildrenWrite && r.result == result)
            .count()
    };
    assert_eq!(writes(AuditResult::Ok), 2);
    assert_eq!(
        writes(AuditResult::Refused),
        5,
        "the token's attempt, the version mismatch, both stale preconditions and the forgery"
    );
}

#[tokio::test]
async fn hygiene_applies_to_every_response() {
    let h = Harness::new();
    let r = h
        .send(Request::get("/nope").body(Body::empty()).unwrap())
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
    for (header, value) in [
        ("x-content-type-options", "nosniff"),
        ("cache-control", "no-store"),
        (
            "content-security-policy",
            "default-src 'none'; frame-ancestors 'none'",
        ),
    ] {
        assert_eq!(r.headers[header], value);
    }

    let r = h
        .send(
            Request::get("/v1/vault?token=gvt1_abc")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::BAD_REQUEST, "credential_in_query")
    );
    assert!(!r.body.to_string().contains("gvt1_abc"));

    // Paths under another protocol version are not served.
    let r = h
        .send(Request::get("/v0/vault").body(Body::empty()).unwrap())
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));

    let r = h
        .send(
            Request::get("/healthz")
                .header("accept", "text/html")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(r.body["status"], "ok");

    let r = h
        .send(Request::delete("/healthz").body(Body::empty()).unwrap())
        .await;
    assert!(r.body.is_object(), "even a 405 is JSON");
}

/// Quotas are what bound a vault, in the one build there is. They are not an
/// abuse control, and each is refused by its own code.
#[tokio::test]
async fn quotas_are_refused_with_named_codes_over_http() {
    let h = Harness::with_config(|c| {
        c.limits.max_names = 1;
        c.limits.max_tokens = 1;
        // age adds a random-length grease stanza to every header, so one
        // small value's ciphertext varies by a few hundred bytes: leave room.
        c.limits.max_vault_bytes = 2000;
    });
    let v = h.create_vault().await;
    assert_eq!(
        h.write(&v, "A", b"x", Pre::Create).await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        h.write(&v, "B", b"x", Pre::Create).await.code(),
        "name_quota_exceeded"
    );

    h.mint(&v, Scope::Meta).await;
    let second = Harness::registration(&v, &TokenKeys::generate(v.id()), Scope::Meta, 0);
    assert_eq!(
        h.register(&v.owner, &second).await.code(),
        "token_quota_exceeded"
    );

    assert_eq!(
        h.write(&v, "A", &[b'y'; 5000], Pre::Match(1)).await.code(),
        "vault_quota_exceeded"
    );
}

#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

const CLIENT_IP: &str = "203.0.113.77";
const PROXIED_IP: &str = "198.51.100.23";

/// Requests from a known address (direct, and through a proxy); afterwards
/// the address appears nowhere: database, WAL or logs. Nothing here keeps a
/// client address at all, so there is no store for one to leak from.
#[tokio::test]
async fn client_addresses_are_never_persisted() {
    let logs = Captured::default();
    let writer = logs.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(move || writer.clone())
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let h = Harness::with_journal(Arc::new(down::Down));
    let v = h.create_vault().await;
    let read = h.mint(&v, Scope::Read).await;
    h.send(with_header(
        h.signed(&v.owner, "GET", "/v1/vault", vec![]),
        "x-forwarded-for",
        PROXIED_IP,
    ))
    .await;
    let wrong = TokenKeys::generate(v.id());
    h.get(&wrong, "/v1/vault").await;
    // A failing journal write is logged, so the log capture is not vacuous.
    let r = h
        .send(h.signed(
            &v.owner,
            "DELETE",
            &format!("/v1/tokens/{}", read.id().to_hex()),
            vec![],
        ))
        .await;
    assert_eq!(r.code(), "unavailable");

    let logged = logs.0.lock().unwrap().clone();
    assert!(!logged.is_empty(), "the capture saw log output");
    h.store.checkpoint().unwrap();
    let mut stored = std::fs::read(h.db_path()).unwrap();
    if let Ok(wal) = std::fs::read(h.db_path().with_extension("db-wal")) {
        stored.extend(wal);
    }
    for ip in [CLIENT_IP, PROXIED_IP] {
        assert!(!contains(&logged, ip.as_bytes()), "{ip} was logged");
        assert!(
            !contains(&stored, ip.as_bytes()),
            "{ip} reached the database"
        );
    }
    assert!(
        !contains(&stored, &[203, 0, 113, 77]),
        "not even as raw octets"
    );
}

mod down {
    use galata_vault::backend::JournalRecord;
    use galata_vault::server::journal::Journal;

    pub struct Down;

    impl Journal for Down {
        fn put(&self, _: &JournalRecord) -> Result<(), String> {
            Err("the journal is unreachable".into())
        }
        fn list_after(&self, _: u64) -> Result<Vec<JournalRecord>, String> {
            Ok(vec![])
        }
        fn check(&self) -> Result<(), String> {
            Err("the journal is unreachable".into())
        }
        fn describe(&self) -> String {
            "down".into()
        }
    }
}
