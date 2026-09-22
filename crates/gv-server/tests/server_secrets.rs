//! The records API, scenario by scenario, with values encrypted, signed,
//! verified and decrypted by the real client crypto. The server only ever
//! sees ciphertext and signatures, and checks every signature it stores.

#[path = "server_common/mod.rs"]
mod common;

use axum::http::StatusCode;
use common::{Harness, Pre, Vault};
use galata_vault::backend::Store;
use galata_vault::keys::{TokenKeys, WriterKey};
use galata_vault::proto::api::{AuditPage, Scope, SecretList, SecretVersion, VersionList};
use galata_vault::proto::audit::{AuditAction, AuditResult, verify_chain};
use galata_vault::proto::ids::{Hash32, Sig64};
use galata_vault::proto::record::{RecordContext, RecordKind};
use galata_vault::seal::{
    Writer, WrittenRecord, open_name, open_secret, verify_listed, verify_meta,
};

/// The context a record's signature covers, from the record itself.
fn ctx_of(v: &Vault, rec: &WrittenRecord) -> RecordContext {
    RecordContext::new(
        v.id(),
        rec.generation,
        rec.kind,
        rec.name_hmac,
        rec.version,
        rec.written_at,
        &rec.name_ct,
        rec.value_ct.as_deref(),
    )
}

fn refusals(h: &Harness, v: &Vault, action: AuditAction) -> usize {
    let (rows, _) = h.store.audit_after(h.pk(v), 0, 1000).unwrap();
    rows.iter()
        .filter(|r| r.action == action && r.result == AuditResult::Refused)
        .count()
}

#[tokio::test]
async fn plaintext_stale_and_forged_writes_are_refused() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let now = h.now();

    let mut plaintext = v.secret("K", b"v", 1, now);
    plaintext.value_ct = Some(b"hunter2".to_vec());
    let r = h.put(&v.owner, &plaintext, Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "not_age_ciphertext")
    );

    let mut stale = v.secret("K", b"v", 1, now);
    stale.generation = 2;
    let r = h.put(&v.owner, &stale, Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, "stale_generation")
    );

    // Signed by a key the descriptor does not name.
    let mut forged = v.secret("K", b"v", 1, now);
    forged.sig = WriterKey::generate().sign(&ctx_of(&v, &forged));
    let r = h.put(&v.owner, &forged, Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "bad_signature")
    );

    // Honestly signed, then given another ciphertext.
    let mut swapped = v.secret("K", b"v", 1, now);
    swapped.value_ct = v.secret("K", b"other", 1, now).value_ct;
    assert_eq!(
        h.put(&v.owner, &swapped, Pre::Create).await.code(),
        "bad_signature"
    );

    assert_eq!(
        h.get(&v.owner, &v.secret_path("K")).await.code(),
        "not_found"
    );
    assert_eq!(
        refusals(&h, &v, AuditAction::SecretPut),
        3,
        "every refused generation or signature is audited"
    );
}

#[tokio::test]
async fn a_write_signs_the_version_the_server_assigns() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let now = h.now();

    let r = h
        .put(&v.owner, &v.secret("K", b"v", 2, now), Pre::Create)
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::CONFLICT, "version_mismatch")
    );
    assert_eq!(
        h.write(&v, "K", b"v1", Pre::Create).await.status,
        StatusCode::CREATED
    );
    let r = h
        .put(&v.owner, &v.secret("K", b"v", 3, now), Pre::Match(1))
        .await;
    assert_eq!(r.code(), "version_mismatch");

    // A signed write lands once; sent again, its precondition fails.
    let second = v.secret("K", b"v2", 2, now);
    assert_eq!(
        h.put(&v.owner, &second, Pre::Match(1)).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.put(&v.owner, &second, Pre::Match(1)).await.code(),
        "precondition_failed"
    );
}

#[tokio::test]
async fn every_write_needs_a_precondition_and_lost_updates_are_prevented() {
    let h = Harness::new();
    let v = h.create_vault().await;

    let r = h.write(&v, "API_KEY", b"v1", Pre::Create).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(r.headers["etag"], "\"1\"");
    assert_eq!(r.body["version"], 1);

    let r = h.write(&v, "API_KEY", b"again", Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::PRECONDITION_FAILED, "precondition_failed")
    );

    // Two clients both read version 1; the first update wins.
    assert_eq!(
        h.write(&v, "API_KEY", b"first", Pre::Match(1)).await.status,
        StatusCode::OK
    );
    let r = h.write(&v, "API_KEY", b"second", Pre::Match(1)).await;
    assert_eq!(r.code(), "precondition_failed");
    assert!(
        !r.headers.contains_key("x-gv-expires-at"),
        "this server announces no expiry, on an error as on a success"
    );

    let r = h
        .put(&v.owner, &v.secret("API_KEY", b"x", 3, h.now()), Pre::None)
        .await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::PRECONDITION_REQUIRED, "precondition_required")
    );
    let r = h
        .put(
            &v.owner,
            &v.secret("API_KEY", b"x", 3, h.now()),
            Pre::Both(2),
        )
        .await;
    assert_eq!(r.code(), "invalid_request");

    let latest: SecretVersion = h.fetch(&v.owner, &v.secret_path("API_KEY")).await;
    assert_eq!(latest.version, 2);
    let opened = open_secret(
        &v.descriptor,
        &v.full.name_key,
        &v.full.vault_secret,
        &latest,
    )
    .unwrap();
    assert_eq!(opened.name, "API_KEY");
    assert_eq!(opened.value.unwrap().as_slice(), b"first");
}

#[tokio::test]
async fn values_history_and_reads_are_audited() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "DATABASE_URL", b"postgres://1", Pre::Create)
        .await;
    for ver in 1..3u64 {
        let value = format!("postgres://{}", ver + 1);
        let r = h
            .write(&v, "DATABASE_URL", value.as_bytes(), Pre::Match(ver))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
    let path = v.secret_path("DATABASE_URL");
    let index = v.full.name_key.hmac("DATABASE_URL");

    let read = h.mint(&v, Scope::Read).await;
    let (_, d, bundle) = h.token_bundle(&read).await;
    let vault_secret = bundle.vault_secret().unwrap();
    let r = h.get(&read, &path).await;
    assert_eq!(r.headers["etag"], "\"3\"");
    let latest: SecretVersion = serde_json::from_value(r.body).unwrap();
    let opened = open_secret(&d, bundle.name_key(), vault_secret, &latest).unwrap();
    assert_eq!(opened.value.unwrap().as_slice(), b"postgres://3");
    let second: SecretVersion = h.fetch(&read, &format!("{path}/versions/2")).await;
    let opened = open_secret(&d, bundle.name_key(), vault_secret, &second).unwrap();
    assert_eq!(opened.value.unwrap().as_slice(), b"postgres://2");

    // A holder that cannot decrypt still verifies the history and the listing.
    let meta = h.mint(&v, Scope::Meta).await;
    let history: VersionList = h.fetch(&meta, &format!("{path}/versions")).await;
    assert_eq!(
        history
            .versions
            .iter()
            .map(|m| m.version)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    for m in &history.versions {
        verify_meta(&d, RecordKind::Secret, &index, m).unwrap();
    }
    let list: SecretList = h.fetch(&meta, "/v1/secrets").await;
    verify_listed(&d, RecordKind::Secret, &list.items[0]).unwrap();

    let audit: AuditPage = h.fetch(&meta, "/v1/audit").await;
    assert_eq!(verify_chain(None, &audit.rows).unwrap(), audit.head);
    let reads: Vec<_> = audit
        .rows
        .iter()
        .filter(|r| r.action == AuditAction::SecretRead && r.result == AuditResult::Ok)
        .collect();
    assert_eq!(
        reads.len(),
        2,
        "each value read is an audit row; the history listing is not"
    );
    // Each read names the version and the exact ciphertext it served.
    assert_eq!((reads[0].version, reads[1].version), (3, 2));
    assert_eq!(
        reads[0].ct_hash,
        Some(Hash32::sha256(&latest.value_ct.as_ref().unwrap().0))
    );
}

#[tokio::test]
async fn old_versions_are_pruned_beyond_the_limit() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "K", b"1", Pre::Create).await;
    for ver in 1..21u64 {
        let r = h
            .write(&v, "K", ver.to_string().as_bytes(), Pre::Match(ver))
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
    let history: VersionList = h
        .fetch(&v.owner, &format!("{}/versions", v.secret_path("K")))
        .await;
    assert_eq!(history.versions.len(), 20);
    assert_eq!(
        history.versions.first().unwrap().version,
        2,
        "version 1 was pruned by the 21st write"
    );
}

#[tokio::test]
async fn delete_writes_a_signed_tombstone() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "OLD_KEY", b"v", Pre::Create).await;
    let path = v.secret_path("OLD_KEY");
    let tombstone = v.tombstone(RecordKind::Secret, "OLD_KEY", 2, h.now());
    let body = serde_json::to_vec(&tombstone.delete_request().unwrap()).unwrap();

    let r = h
        .send(h.req(&v.owner, "DELETE", &path, body, Pre::None))
        .await;
    assert_eq!(r.code(), "precondition_required");
    assert_eq!(
        h.delete(&v.owner, &tombstone, 9).await.code(),
        "precondition_failed"
    );
    let mut unsigned = tombstone.clone();
    unsigned.sig = Sig64([0; 64]);
    assert_eq!(
        h.delete(&v.owner, &unsigned, 1).await.code(),
        "bad_signature"
    );

    let r = h.delete(&v.owner, &tombstone, 1).await;
    assert_eq!(
        (r.status, r.body["version"].as_u64()),
        (StatusCode::OK, Some(2))
    );

    let r = h.get(&v.owner, &path).await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
    assert_eq!(
        r.headers["etag"], "\"2\"",
        "the 404 names the tombstone version"
    );
    let history: VersionList = h.fetch(&v.owner, &format!("{path}/versions")).await;
    let last = history.versions.last().unwrap();
    assert!(last.tombstone);
    verify_meta(
        &v.descriptor,
        RecordKind::Secret,
        &v.full.name_key.hmac("OLD_KEY"),
        last,
    )
    .unwrap();

    let again = v.tombstone(RecordKind::Secret, "OLD_KEY", 3, h.now());
    assert_eq!(h.delete(&v.owner, &again, 2).await.code(), "not_found");
}

#[tokio::test]
async fn scopes_bound_what_each_token_can_do_with_values() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "STRIPE_KEY", b"sk", Pre::Create).await;
    let meta = h.mint(&v, Scope::Meta).await;
    let append = h.mint(&v, Scope::Append).await;
    let read = h.mint(&v, Scope::Read).await;
    let path = v.secret_path("STRIPE_KEY");

    // Meta lists, verifies and decrypts the names with its own bundle, but
    // reads no value.
    let list: SecretList = h.fetch(&meta, "/v1/secrets").await;
    let (_, d, names) = h.token_bundle(&meta).await;
    let item = &list.items[0];
    verify_listed(&d, RecordKind::Secret, item).unwrap();
    assert_eq!(
        open_name(
            &d,
            names.name_key(),
            RecordKind::Secret,
            &item.name_hmac,
            &item.name_ct.0
        )
        .unwrap(),
        "STRIPE_KEY"
    );
    assert_eq!(h.get(&meta, &path).await.code(), "forbidden");

    // Append writes with the writer key from its own bundle, but cannot read back.
    let (_, d, bundle) = h.token_bundle(&append).await;
    let writer = Writer {
        descriptor: &d,
        name_key: bundle.name_key(),
        writer: bundle.secret_writer().unwrap(),
    };
    let rec = writer.secret("NEW", b"x", 1, h.now()).unwrap();
    assert_eq!(
        h.put(&append, &rec, Pre::Create).await.status,
        StatusCode::CREATED
    );
    assert_eq!(h.get(&append, &path).await.code(), "forbidden");

    // Read reads, but cannot write.
    let r = h
        .put(
            &read,
            &v.secret("STRIPE_KEY", b"y", 2, h.now()),
            Pre::Match(1),
        )
        .await;
    assert_eq!(r.code(), "forbidden");
    assert_eq!(h.get(&read, &path).await.status, StatusCode::OK);
}

/// A `config-write` token holds no secret writer key. It is refused by scope,
/// and a secret signed with the config writer key is refused by signature,
/// even when the owner sends it.
#[tokio::test]
async fn no_one_writes_a_secret_with_the_config_writer_key() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "AGENT_KEY", b"0xkey", Pre::Create).await;
    let config_write = h.mint(&v, Scope::ConfigWrite).await;
    let (_, _, bundle) = h.token_bundle(&config_write).await;
    assert!(bundle.secret_writer().is_none());

    let mut rec = v.secret("AGENT_KEY", b"stolen", 2, h.now());
    rec.sig = bundle.config_writer().unwrap().sign(&ctx_of(&v, &rec));
    let r = h.put(&config_write, &rec, Pre::Match(1)).await;
    assert_eq!((r.status, r.code()), (StatusCode::FORBIDDEN, "forbidden"));
    let r = h.put(&v.owner, &rec, Pre::Match(1)).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "bad_signature")
    );

    // A config record sent as a secret fails too: the kind is signed.
    let config = v.config("app", b"a = 1", 1, h.now());
    let body = serde_json::to_vec(&config.put_request().unwrap()).unwrap();
    let path = format!("/v1/secrets/{}", config.name_hmac.to_hex());
    let r = h
        .send(h.req(&v.owner, "PUT", &path, body, Pre::Create))
        .await;
    assert_eq!(r.code(), "bad_signature");

    let latest: SecretVersion = h.fetch(&v.owner, &v.secret_path("AGENT_KEY")).await;
    assert_eq!(latest.version, 1, "nothing was written");
}

#[tokio::test]
async fn the_read_allow_list_is_enforced_and_refusals_audited() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "DATABASE_URL", b"db", Pre::Create).await;
    h.write(&v, "STRIPE_KEY", b"sk", Pre::Create).await;
    let t = TokenKeys::generate(v.id());
    let mut request = Harness::registration(&v, &t, Scope::Read, 0);
    request.allow_list = Some(vec![v.full.name_key.hmac("DATABASE_URL")]);
    assert_eq!(
        h.register(&v.owner, &request).await.status,
        StatusCode::CREATED
    );

    assert_eq!(
        h.get(&t, &v.secret_path("DATABASE_URL")).await.status,
        StatusCode::OK
    );
    let refused = h.get(&t, &v.secret_path("STRIPE_KEY")).await;
    assert_eq!(
        (refused.status, refused.code()),
        (StatusCode::FORBIDDEN, "forbidden")
    );

    let audit: AuditPage = h.fetch(&v.owner, "/v1/audit").await;
    assert!(
        audit
            .rows
            .iter()
            .any(|r| r.action == AuditAction::SecretRead
                && r.result == AuditResult::Refused
                && r.name_hmac == Some(v.full.name_key.hmac("STRIPE_KEY")))
    );
}

#[tokio::test]
async fn listing_paginates_with_a_cursor() {
    let h = Harness::new();
    let v = h.create_vault().await;
    for i in 0..5 {
        h.write(&v, &format!("K{i}"), b"v", Pre::Create).await;
    }
    let mut seen = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let path = match &after {
            None => "/v1/secrets?limit=2".to_string(),
            Some(a) => format!("/v1/secrets?limit=2&after={a}"),
        };
        let page: SecretList = h.fetch(&v.owner, &path).await;
        seen.extend(page.items.iter().map(|i| i.name_hmac));
        match page.next_cursor {
            Some(c) => after = Some(c.to_hex()),
            None => break,
        }
    }
    seen.dedup();
    assert_eq!(seen.len(), 5);
}

#[tokio::test]
async fn malformed_paths_and_oversized_values_get_named_json_errors() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let r = h.get(&v.owner, "/v1/secrets/zz").await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::BAD_REQUEST, "invalid_request")
    );
    let path = format!("{}/versions/latest", v.secret_path("K"));
    assert_eq!(h.get(&v.owner, &path).await.code(), "invalid_request");
    let r = h.get(&v.owner, &v.secret_path("NOPE")).await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));

    let big = vec![b'x'; 20 * 1024];
    let r = h.write(&v, "BIG", &big, Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::PAYLOAD_TOO_LARGE, "value_too_large")
    );
}

#[tokio::test]
async fn every_scope_reads_and_verifies_the_audit_chain() {
    let h = Harness::new();
    let v = h.create_vault().await;
    for scope in Scope::ALL {
        let t = h.mint(&v, scope).await;
        let page: AuditPage = h.fetch(&t, "/v1/audit?after=0").await;
        assert_eq!(
            verify_chain(None, &page.rows).unwrap(),
            page.head,
            "{scope}"
        );
    }
}
