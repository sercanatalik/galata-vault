//! What this server is (`specs/abuse-controls`, `specs/server-core`): it
//! authenticates, enforces the quotas, and admits everything else. There is
//! one build, so this is not a default among two: no proof of work, no
//! expiry announced, no vault deleted for inactivity, and no metrics
//! endpoint. A configuration naming a removed setting is refused by name,
//! before anything is opened.

mod common;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use common::{DAY, Harness, Pre};
use galata_vault_keys::NodeKey;
use galata_vault_proto::api::{Limits, Scope};

#[tokio::test]
async fn the_capabilities_ask_for_nothing() {
    let h = Harness::new();
    let caps = h.capabilities().await;
    assert_eq!(caps.proof_of_work, None);
    assert_eq!(caps.idle_expiry_days, None);
    assert_eq!(caps.limits, Limits::default());

    // Unauthenticated, JSON with explicit nulls, and as unrenderable as
    // every other response. Both fields stay in the document, so a client
    // can tell this server from one that requires either.
    let r = h
        .send(
            Request::get("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert!(
        r.body["proof_of_work"].is_null() && r.body["idle_expiry_days"].is_null(),
        "{:?}",
        r.body
    );
    assert!(r.body.as_object().unwrap().contains_key("proof_of_work"));
    assert!(r.body.as_object().unwrap().contains_key("idle_expiry_days"));
    assert_eq!(r.headers["content-type"], "application/json");
    assert_eq!(r.headers["x-content-type-options"], "nosniff");
    let r = h
        .send(
            Request::post("/v1/capabilities")
                .body(Body::empty())
                .unwrap(),
        )
        .await;
    assert_eq!(r.code(), "invalid_request", "GET only");
}

#[tokio::test]
async fn creation_needs_no_challenge_and_there_is_none_to_ask_for() {
    let h = Harness::new();
    let (v, request) = h.creation(&NodeKey::generate()).await;
    assert!(request.challenge.is_none() && request.nonce.is_none());
    assert_eq!(
        h.submit(&v.owner, &request).await.status,
        StatusCode::CREATED
    );
    let r = h
        .send(
            Request::post("/v1/challenges")
                .body(Body::from(r#"{"purpose":"create_vault"}"#))
                .unwrap(),
        )
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
}

/// A challenge sent to a server that asks for none is not checked: the
/// endpoint that would have issued it does not exist.
/// (`api.rs::creation_refusals` covers what creation does refuse.)
#[tokio::test]
async fn a_challenge_this_server_never_issued_is_ignored() {
    let h = Harness::new();
    let (v, mut extra) = h.creation(&NodeKey::generate()).await;
    extra.challenge = Some("not-a-challenge".to_owned());
    extra.nonce = Some(1);
    assert_eq!(h.submit(&v.owner, &extra).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn nothing_announces_an_expiry() {
    let h = Harness::new();
    let v = h.create_vault().await;
    let meta = h.mint(&v, Scope::Meta).await;
    for r in [
        h.get(&v.owner, "/v1/vault").await,
        h.get(&meta, "/v1/vault").await,
        h.get(&v.owner, "/v1/secrets").await,
        h.get(&meta, "/v1/vault/children").await,
    ] {
        assert!(r.headers.get("x-gv-expires-at").is_none(), "{:?}", r.body);
    }
    assert_eq!(h.status(&v.owner).await.expires_at, None);
}

#[tokio::test]
async fn a_vault_idle_for_400_days_survives() {
    let h = Harness::new();
    let v = h.create_vault().await;
    assert_eq!(
        h.write(&v, "DATABASE_URL", b"postgres://", Pre::Create)
            .await
            .status,
        StatusCode::CREATED
    );
    h.advance(400 * DAY);
    let r = h.get(&v.owner, &v.secret_path("DATABASE_URL")).await;
    assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
    assert_eq!(r.body["version"], 1);
    let status = h.status(&v.owner).await;
    assert_eq!((status.vault_id, status.expires_at), (v.id(), None));
}

#[tokio::test]
async fn there_is_no_metrics_endpoint() {
    let h = Harness::new();
    let r = h
        .send(Request::get("/metrics").body(Body::empty()).unwrap())
        .await;
    assert_eq!((r.status, r.code()), (StatusCode::NOT_FOUND, "not_found"));
}

/// The library refuses what the binary refuses: `AppState::new` validates.
#[test]
fn a_removed_setting_is_refused_before_the_core_opens() {
    use std::sync::Arc;

    use galata_vault_server::journal::FileJournal;
    use galata_vault_server::{AppState, ServerConfig, SystemClock};
    use galata_vault_store::{SqliteStore, StoreConfig};

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("vault.db");
    let toml = format!(
        "database = {:?}\nidle_expiry_days = 90\n[journal]\nkind = \"file\"\ndir = {:?}\n",
        path.display().to_string(),
        dir.path().join("journal").display().to_string()
    );
    let config: ServerConfig = toml::from_str(&toml).unwrap();
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&path)).unwrap());
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let err = AppState::new(store, journal, config, Arc::new(SystemClock))
        .err()
        .expect("refused")
        .to_string();
    assert!(
        err.contains("idle_expiry_days") && err.contains("no longer supported"),
        "{err}"
    );
}

/// `gv-server --config` with a removed setting exits naming it, opens and
/// binds nothing, and names no Cargo feature: there is no build to ask for.
#[test]
fn the_server_exits_naming_the_removed_setting() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("server.toml");
    let s3 = "[journal]\nkind = \"s3\"\nendpoint = \"https://s3.example\"\nregion = \"fsn1\"\nbucket = \"gv-journal\"\n";
    let file_journal = format!(
        "[journal]\nkind = \"file\"\ndir = \"{}\"\n",
        dir.path().join("journal").display()
    );
    for (setting, line, journal) in [
        ("idle_expiry_days", "idle_expiry_days = 90", &file_journal),
        ("production", "production = true", &file_journal),
        ("pow_difficulty", "pow_difficulty = 24", &file_journal),
        (
            "[rate_limits]",
            "[rate_limits]\ncreations_per_ip_per_hour = 5",
            &file_journal,
        ),
        ("profile", "profile = \"hosted\"", &file_journal),
        ("S3 journal", "", &s3.to_owned()),
    ] {
        // A table has to come last in TOML: the journal goes after it.
        std::fs::write(
            &file,
            format!(
                "database = \"{}\"\nlisten = \"127.0.0.1:1\"\n{line}\n{journal}",
                dir.path().join("vault.db").display()
            ),
        )
        .unwrap();
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_gv-server"))
            .args(["--config", file.to_str().unwrap()])
            .output()
            .unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(!out.status.success(), "{setting}: {err}");
        assert!(
            err.contains(setting) && err.contains("no longer supported"),
            "{setting}: {err}"
        );
        assert!(!err.contains("feature"), "{setting}: {err}");
        assert!(!dir.path().join("vault.db").exists(), "nothing is opened");
    }
}
