//! Config documents over the real router: a record kind of their own, with
//! their own writer key; the `config` and `config-write` scopes; quotas; and
//! rotation that must carry every config version.

#[path = "server_common/mod.rs"]
mod common;

use axum::http::StatusCode;
use common::{Harness, Pre};
use galata_vault::proto::api::{Scope, SecretList, SecretVersion};
use galata_vault::proto::record::RecordKind;
use galata_vault::seal::{ConfigFormat, Writer, build_rotation, open_config_record, open_secret};

#[tokio::test]
async fn one_name_can_be_a_secret_and_a_config() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let r = h.write(&v, "app", b"s", Pre::Create).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    let r = h.write_config(&v, "app", b"a = 1", Pre::Create).await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);

    for (path, index) in [
        ("/v1/secrets", v.full.name_key.hmac("app")),
        ("/v1/configs", v.full.name_key.config_hmac("app")),
    ] {
        let list: SecretList = h.fetch(&v.owner, path).await;
        assert_eq!(list.items.len(), 1, "{path} lists its own kind only");
        assert_eq!(list.items[0].name_hmac, index);
    }
    assert_eq!(h.status(&v.owner).await.config_count, 1);
}

#[tokio::test]
async fn the_config_scopes_read_configs_and_never_a_secret() {
    let h = Harness::new();
    let v = h.create_vault().await;
    h.write(&v, "AGENT_KEY", b"0xkey", Pre::Create).await;
    h.write_config(&v, "app", b"a = 1\r\n", Pre::Create).await;

    for scope in [Scope::Config, Scope::ConfigWrite] {
        let t = h.mint(&v, scope).await;
        // It verifies and decrypts the config with its own bundle.
        let rec: SecretVersion = h.fetch(&t, &v.config_path("app")).await;
        let (_, d, bundle) = h.token_bundle(&t).await;
        assert!(!bundle.holds_vault_secret(), "{scope}");
        let doc = open_config_record(&d, bundle.name_key(), bundle.config_secret().unwrap(), &rec)
            .unwrap();
        assert_eq!(
            doc.value.unwrap().as_slice(),
            b"a = 1\r\n",
            "the exact bytes"
        );

        // A secret value is refused, and so is every secret write.
        assert_eq!(
            h.get(&t, &v.secret_path("AGENT_KEY")).await.status,
            StatusCode::FORBIDDEN,
            "{scope}"
        );
        let r = h
            .put(&t, &v.secret("AGENT_KEY", b"x", 2, h.now()), Pre::Match(1))
            .await;
        assert_eq!(r.status, StatusCode::FORBIDDEN, "{scope}");
    }

    // `config` cannot write a config; `config-write` can, with the config
    // writer key from its own bundle, from the version it read.
    let config = h.mint(&v, Scope::Config).await;
    let r = h
        .put(
            &config,
            &v.config("app", b"a = 2", 2, h.now()),
            Pre::Match(1),
        )
        .await;
    assert_eq!(r.status, StatusCode::FORBIDDEN);
    let writer = h.mint(&v, Scope::ConfigWrite).await;
    let (_, d, bundle) = h.token_bundle(&writer).await;
    let w = Writer {
        descriptor: &d,
        name_key: bundle.name_key(),
        writer: bundle.config_writer().unwrap(),
    };
    let rec = w
        .config("app", ConfigFormat::Toml, b"a = 2", 2, h.now())
        .unwrap();
    let r = h.put(&writer, &rec, Pre::Match(1)).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["version"], 2);
    // A stale edit loses.
    let r = h.put(&writer, &rec, Pre::Match(1)).await;
    assert_eq!(r.status, StatusCode::PRECONDITION_FAILED);

    // `append` writes configs too, and still reads nothing.
    let append = h.mint(&v, Scope::Append).await;
    let r = h
        .put(
            &append,
            &v.config("from-ci", b"x = 1", 1, h.now()),
            Pre::Create,
        )
        .await;
    assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
    assert_eq!(
        h.get(&append, &v.config_path("app")).await.status,
        StatusCode::FORBIDDEN
    );

    // Every config read, write and refusal is in the chain, by index only.
    let r = h.get(&v.owner, "/v1/audit").await;
    let actions: Vec<(String, String)> = r.body["rows"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| {
            (
                row["action"].as_str().unwrap().to_owned(),
                row["result"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for want in [
        ("config_write", "ok"),
        ("config_read", "ok"),
        ("config_write", "refused"),
        ("config_read", "refused"),
    ] {
        assert!(
            actions.contains(&(want.0.to_owned(), want.1.to_owned())),
            "{want:?} in {actions:?}"
        );
    }
}

#[tokio::test]
async fn configs_follow_the_record_rules() {
    // age adds a random-length grease stanza to every header: leave room
    // above a small document's ciphertext.
    let h = Harness::with_config(|c| {
        c.limits.max_config_bytes = 1000;
        c.limits.max_configs = 2;
        c.limits.max_config_versions = 3;
    });
    let v = h.create_vault().await;
    let path = v.config_path("app");

    // Plaintext is refused, and a write needs a precondition.
    let mut plain = v.config("app", b"a = 1", 1, h.now());
    plain.value_ct = Some(b"a = 1".to_vec());
    let r = h.put(&v.owner, &plain, Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "not_age_ciphertext")
    );
    let r = h
        .put(&v.owner, &v.config("app", b"a", 1, h.now()), Pre::None)
        .await;
    assert_eq!(r.status, StatusCode::PRECONDITION_REQUIRED);

    // Too large, by the config quota.
    let r = h.write_config(&v, "app", &[b'x'; 1100], Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::PAYLOAD_TOO_LARGE, "config_too_large")
    );

    // Versions prune at the config limit.
    h.write_config(&v, "app", b"1", Pre::Create).await;
    for ver in 1..=3 {
        let r = h.write_config(&v, "app", b"n", Pre::Match(ver)).await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    }
    let r = h.get(&v.owner, &format!("{path}/versions")).await;
    let kept: Vec<u64> = r.body["versions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["version"].as_u64().unwrap())
        .collect();
    assert_eq!(kept, [2, 3, 4]);

    // The count quota.
    h.write_config(&v, "b", b"1", Pre::Create).await;
    let r = h.write_config(&v, "c", b"1", Pre::Create).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "config_quota_exceeded")
    );

    // Delete writes a signed tombstone; the latest is then a 404.
    let r = h
        .delete(
            &v.owner,
            &v.tombstone(RecordKind::Config, "app", 5, h.now()),
            4,
        )
        .await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(h.get(&v.owner, &path).await.status, StatusCode::NOT_FOUND);
}

/// A vault filled to its byte quota across secret and config versions can
/// still be rotated: the derived body limit fits the whole batch, which is
/// larger than the quota itself once the ciphertext is base64 in JSON.
#[tokio::test]
async fn a_full_vault_rotates_within_the_derived_body_limit() {
    let limits =
        galata_vault::proto::api::Limits::new(4, 16 * 1024, 3, 96 * 1024, 6, 2, 32 * 1024, 3);
    let h = Harness::with_config(|c| c.limits = limits);
    let mut v = h.create_vault().await;
    let pre = |ver: u64| match ver {
        1 => Pre::Create,
        _ => Pre::Match(ver - 1),
    };

    // Configs first, then secrets until the vault is full.
    let (config_names, secret_names) = (["app", "db"], ["A", "B", "C", "D"]);
    for name in config_names {
        for ver in 1..=3 {
            let r = h.write_config(&v, name, &[b'x'; 8 * 1024], pre(ver)).await;
            assert!(r.status.is_success(), "{:?}", r.body);
        }
    }
    let mut full_up = false;
    'fill: for name in secret_names {
        for ver in 1..=3 {
            let r = h.write(&v, name, &[0u8; 14 * 1024], pre(ver)).await;
            if r.code() == "vault_quota_exceeded" {
                full_up = true;
                break 'fill;
            }
            assert!(r.status.is_success(), "{:?}", r.body);
        }
    }
    assert!(full_up, "the vault reached its byte quota");
    let before = h.status(&v.owner).await;
    assert!(
        before.bytes_used > limits.max_vault_bytes - 16 * 1024,
        "within one value of the quota: {}",
        before.bytes_used
    );

    let read = h.mint(&v, Scope::Read).await;
    for scope in [Scope::Meta, Scope::Config, Scope::Admin] {
        h.mint(&v, scope).await;
    }
    let secrets = h.versions(&v, RecordKind::Secret).len();
    let configs = h.versions(&v, RecordKind::Config).len();
    let (r, rotation) = h.rotate(&v, &[read.id()]).await;
    let len = serde_json::to_vec(&rotation.request).unwrap().len();
    assert!(
        len as u64 > limits.max_vault_bytes,
        "a body limit equal to the quota could not carry this batch: {len} bytes"
    );
    assert!(len <= h.state.config().body_limit());
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);

    // Every retained version verifies and opens under the new generation.
    v.rotated(rotation);
    let after = h.versions(&v, RecordKind::Secret);
    assert_eq!(after.len(), secrets);
    for rec in &after {
        open_secret(&v.descriptor, &v.full.name_key, &v.full.vault_secret, rec).unwrap();
    }
    let after = h.versions(&v, RecordKind::Config);
    assert_eq!(after.len(), configs);
    for rec in &after {
        open_config_record(&v.descriptor, &v.full.name_key, &v.full.config_secret, rec).unwrap();
    }
}

#[tokio::test]
async fn a_rotation_must_carry_every_config() {
    let h = Harness::new();
    let mut v = h.create_vault().await;
    h.write_config(&v, "app", b"a = 1", Pre::Create).await;
    let config_token = h.mint(&v, Scope::Config).await;
    let status = h.status(&v.owner).await;
    let rotation = build_rotation(
        &v.owner,
        &status,
        &v.descriptor,
        &v.full,
        &h.versions(&v, RecordKind::Secret),
        &h.versions(&v, RecordKind::Config),
        &[],
        h.now(),
    )
    .unwrap();
    let submit = |body: Vec<u8>| h.send(h.signed(&v.owner, "POST", "/v1/vault/rotations", body));

    // Leaving the config out is refused, and changes nothing.
    let mut incomplete = rotation.request.clone();
    incomplete.configs.clear();
    let r = submit(serde_json::to_vec(&incomplete).unwrap()).await;
    assert_eq!(
        (r.status, r.code()),
        (StatusCode::UNPROCESSABLE_ENTITY, "incomplete_rotation")
    );
    assert_eq!(h.status(&v.owner).await.generation, 1);

    // The complete batch lands; the config reads under the new keys.
    let r = submit(serde_json::to_vec(&rotation.request).unwrap()).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    let old_config_secret = v.full.config_secret.clone();
    v.rotated(rotation);
    let rec: SecretVersion = h.fetch(&v.owner, &v.config_path("app")).await;
    let doc =
        open_config_record(&v.descriptor, &v.full.name_key, &v.full.config_secret, &rec).unwrap();
    assert_eq!(doc.value.unwrap().as_slice(), b"a = 1");
    assert_ne!(
        v.full.config_secret.as_bytes(),
        old_config_secret.as_bytes()
    );

    // The surviving config token was resealed with the new config key.
    let (_, d, bundle) = h.token_bundle(&config_token).await;
    assert_eq!(d.generation, 2);
    assert!(bundle.matches(&d));
    assert_eq!(
        bundle.config_secret().unwrap().as_bytes(),
        v.full.config_secret.as_bytes()
    );
}
