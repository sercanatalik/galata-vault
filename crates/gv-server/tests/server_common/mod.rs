//! Shared test harness: the real router in-process, a clock the tests move,
//! and client helpers built on the real client crypto (the protocol: every
//! request signed, preconditions included; every record signed by its
//! generation's writer key).

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use galata_vault::backend::{SqliteStore, Store, StoreConfig, VersionRow};
use galata_vault::keys::{
    Bundle, FullBundle, NodeKey, OwnerKeys, TokenKeys, seal_for_scope, seal_owner_bundle,
};
use galata_vault::proto::api::{
    Capabilities, ChallengeResponse, CreateVaultRequest, RegisterTokenRequest, Scope,
    SecretVersion, TokenSelf, VaultStatus,
};
use galata_vault::proto::descriptor::Descriptor;
use galata_vault::proto::ids::{B64, Hash32, TokenId, VaultId};
use galata_vault::proto::pow;
use galata_vault::proto::record::RecordKind;
use galata_vault::proto::sig::SignedRequest;
use galata_vault::seal::{ConfigFormat, Rotation, Writer, WrittenRecord, build_rotation};
use galata_vault::server::journal::{FileJournal, Journal};
use galata_vault::server::{AppState, Clock, ServerConfig, router};
use http_body_util::BodyExt;
use serde::de::DeserializeOwned;
use serde_json::Value;
use tower::ServiceExt;

pub const T0: i64 = 1_757_500_000;
pub const DAY: i64 = 86_400;

pub struct TestClock(pub AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

pub struct Reply {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Value,
}

impl Reply {
    pub fn code(&self) -> &str {
        self.body["error"].as_str().unwrap_or("")
    }
}

/// Who signs a request.
#[derive(Clone, Copy)]
pub enum As<'a> {
    Owner(&'a OwnerKeys),
    Token(&'a TokenKeys),
}

impl<'a> From<&'a OwnerKeys> for As<'a> {
    fn from(owner: &'a OwnerKeys) -> As<'a> {
        As::Owner(owner)
    }
}

impl<'a> From<&'a TokenKeys> for As<'a> {
    fn from(token: &'a TokenKeys) -> As<'a> {
        As::Token(token)
    }
}

/// The precondition a request carries. It is part of what is signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pre {
    None,
    /// `If-None-Match: *`
    Create,
    /// `If-Match: "v"`
    Match(u64),
    /// Both headers, which the server refuses.
    Both(u64),
}

impl Pre {
    pub fn headers(self) -> (Option<String>, Option<&'static str>) {
        match self {
            Pre::None => (None, None),
            Pre::Create => (None, Some("*")),
            Pre::Match(v) => (Some(format!("\"{v}\"")), None),
            Pre::Both(v) => (Some(format!("\"{v}\"")), Some("*")),
        }
    }

    /// The version a write under this precondition creates.
    pub fn next(self) -> u64 {
        match self {
            Pre::None | Pre::Create => 1,
            Pre::Match(v) | Pre::Both(v) => v + 1,
        }
    }
}

/// What an owner holds for its vault's current generation.
pub struct Vault {
    pub owner: OwnerKeys,
    pub full: FullBundle,
    pub descriptor: Descriptor,
}

impl Vault {
    pub fn id(&self) -> VaultId {
        self.owner.vault_id()
    }

    pub fn writer(&self, kind: RecordKind) -> Writer<'_> {
        Writer {
            descriptor: &self.descriptor,
            name_key: &self.full.name_key,
            writer: match kind {
                RecordKind::Secret => &self.full.secret_writer,
                RecordKind::Config => &self.full.config_writer,
                _ => unreachable!("the tests write two record kinds"),
            },
        }
    }

    pub fn secret(&self, name: &str, value: &[u8], version: u64, at: i64) -> WrittenRecord {
        self.writer(RecordKind::Secret)
            .secret(name, value, version, at)
            .unwrap()
    }

    pub fn config(&self, name: &str, body: &[u8], version: u64, at: i64) -> WrittenRecord {
        self.writer(RecordKind::Config)
            .config(name, ConfigFormat::Toml, body, version, at)
            .unwrap()
    }

    pub fn tombstone(&self, kind: RecordKind, name: &str, version: u64, at: i64) -> WrittenRecord {
        self.writer(kind)
            .tombstone(kind, name, version, at)
            .unwrap()
    }

    pub fn secret_path(&self, name: &str) -> String {
        format!("/v1/secrets/{}", self.full.name_key.hmac(name).to_hex())
    }

    pub fn config_path(&self, name: &str) -> String {
        format!(
            "/v1/configs/{}",
            self.full.name_key.config_hmac(name).to_hex()
        )
    }

    /// Move to the generation an accepted rotation created.
    pub fn rotated(&mut self, rotation: Rotation) {
        self.full = rotation.new_bundle;
        self.descriptor = rotation.new_descriptor;
    }
}

pub fn record_path(rec: &WrittenRecord) -> String {
    format!("/v1/{}s/{}", rec.kind.as_str(), rec.name_hmac.to_hex())
}

/// Stored rows as the API serves them.
pub fn wire(rows: Vec<VersionRow>) -> Vec<SecretVersion> {
    rows.into_iter()
        .map(|r| {
            SecretVersion::new(
                r.name_hmac,
                r.version,
                B64(r.name_ct),
                r.value_ct.map(B64),
                r.generation,
                r.written_at,
                r.written_by,
                r.tombstone,
                r.sig,
            )
        })
        .collect()
}

pub struct Harness {
    pub dir: tempfile::TempDir,
    pub app: Router,
    pub clock: Arc<TestClock>,
    pub store: Arc<SqliteStore>,
    pub journal_dir: PathBuf,
    pub state: AppState,
}

pub const CLIENT_ADDR: SocketAddr =
    SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 77)), 40_000);

impl Harness {
    /// The server these tests were written against: the one build, which
    /// asks nothing of its callers beyond the protocol.
    pub fn new() -> Harness {
        Harness::build(|_| {}, None)
    }

    pub fn with_config(tweak: impl FnOnce(&mut ServerConfig)) -> Harness {
        Harness::build(tweak, None)
    }

    /// A harness whose journal is `journal` rather than a local directory.
    pub fn with_journal(journal: Arc<dyn Journal>) -> Harness {
        Harness::build(|_| {}, Some(journal))
    }

    fn build(tweak: impl FnOnce(&mut ServerConfig), journal: Option<Arc<dyn Journal>>) -> Harness {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.db");
        let journal_dir = dir.path().join("journal");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(&path)).unwrap());
        let mut config = ServerConfig::for_database(&path);
        tweak(&mut config);
        let journal = journal.unwrap_or_else(|| Arc::new(FileJournal::open(&journal_dir).unwrap()));
        let clock = Arc::new(TestClock(AtomicI64::new(T0)));
        let state = AppState::new(store.clone(), journal, config, clock.clone()).unwrap();
        // Every request arrives from one documentation address (RFC 5737), so
        // tests can assert it never reaches storage, logs or metrics.
        let app = router(state.clone()).layer(MockConnectInfo(CLIENT_ADDR));
        Harness {
            dir,
            app,
            clock,
            store,
            journal_dir,
            state,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.dir.path().join("vault.db")
    }

    pub fn now(&self) -> i64 {
        self.clock.now()
    }

    pub fn advance(&self, secs: i64) {
        self.clock.0.fetch_add(secs, Ordering::SeqCst);
    }

    pub async fn send(&self, req: Request<Body>) -> Reply {
        let response = self.app.clone().oneshot(req).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let body = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).into()))
        };
        Reply {
            status,
            headers,
            body,
        }
    }

    // ------------------------------------------------------------ requests

    /// A request signed at `ts`, preconditions included in the signature.
    pub fn req_at<'a>(
        &self,
        who: impl Into<As<'a>>,
        method: &str,
        path: &str,
        body: Vec<u8>,
        pre: Pre,
        ts: i64,
    ) -> Request<Body> {
        let (if_match, if_none_match) = pre.headers();
        let signed = SignedRequest {
            method,
            path_and_query: path,
            body: &body,
            if_match: if_match.as_deref(),
            if_none_match,
        };
        let params = match who.into() {
            As::Owner(o) => o.sign_request(&signed, ts),
            As::Token(t) => t.sign_request(&signed, ts),
        };
        let mut builder = Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", params.to_header_value())
            .header("content-type", "application/json");
        if let Some(v) = &if_match {
            builder = builder.header("if-match", v.as_str());
        }
        if let Some(v) = if_none_match {
            builder = builder.header("if-none-match", v);
        }
        builder.body(Body::from(body)).unwrap()
    }

    pub fn req<'a>(
        &self,
        who: impl Into<As<'a>>,
        method: &str,
        path: &str,
        body: Vec<u8>,
        pre: Pre,
    ) -> Request<Body> {
        self.req_at(who, method, path, body, pre, self.now())
    }

    /// A signed request with no precondition.
    pub fn signed<'a>(
        &self,
        who: impl Into<As<'a>>,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Request<Body> {
        self.req(who, method, path, body, Pre::None)
    }

    pub async fn get<'a>(&self, who: impl Into<As<'a>>, path: &str) -> Reply {
        self.send(self.signed(who, "GET", path, vec![])).await
    }

    /// `GET`, expecting 200, parsed.
    pub async fn fetch<'a, T: DeserializeOwned>(&self, who: impl Into<As<'a>>, path: &str) -> T {
        let r = self.get(who, path).await;
        assert_eq!(r.status, StatusCode::OK, "GET {path}: {:?}", r.body);
        serde_json::from_value(r.body).unwrap()
    }

    pub async fn status(&self, owner: &OwnerKeys) -> VaultStatus {
        self.fetch(owner, "/v1/vault").await
    }

    // ------------------------------------------------------------ records

    /// Send a signed write.
    pub async fn put<'a>(&self, who: impl Into<As<'a>>, rec: &WrittenRecord, pre: Pre) -> Reply {
        let body =
            serde_json::to_vec(&rec.put_request().expect("a write, not a tombstone")).unwrap();
        self.send(self.req(who, "PUT", &record_path(rec), body, pre))
            .await
    }

    /// Send a signed tombstone.
    pub async fn delete<'a>(
        &self,
        who: impl Into<As<'a>>,
        rec: &WrittenRecord,
        if_match: u64,
    ) -> Reply {
        let body = serde_json::to_vec(&rec.delete_request().expect("a tombstone")).unwrap();
        self.send(self.req(who, "DELETE", &record_path(rec), body, Pre::Match(if_match)))
            .await
    }

    /// The owner writes a secret, signing the version `pre` creates.
    pub async fn write(&self, v: &Vault, name: &str, value: &[u8], pre: Pre) -> Reply {
        let rec = v.secret(name, value, pre.next(), self.now());
        self.put(&v.owner, &rec, pre).await
    }

    /// The owner writes a config, signing the version `pre` creates.
    pub async fn write_config(&self, v: &Vault, name: &str, body: &[u8], pre: Pre) -> Reply {
        let rec = v.config(name, body, pre.next(), self.now());
        self.put(&v.owner, &rec, pre).await
    }

    /// Every retained version of a kind, as a rotating client fetches it.
    pub fn versions(&self, v: &Vault, kind: RecordKind) -> Vec<SecretVersion> {
        let kind = match kind {
            RecordKind::Secret => galata_vault::backend::RecordKind::Secret,
            RecordKind::Config => galata_vault::backend::RecordKind::Config,
            _ => unreachable!("the tests store two record kinds"),
        };
        wire(self.store.all_record_versions(self.pk(v), kind).unwrap())
    }

    /// Build a rotation from the vault's current state and submit it.
    pub async fn rotate(&self, v: &Vault, revoke: &[TokenId]) -> (Reply, Rotation) {
        let status = self.status(&v.owner).await;
        let secrets = self.versions(v, RecordKind::Secret);
        let configs = self.versions(v, RecordKind::Config);
        let rotation = build_rotation(
            &v.owner,
            &status,
            &v.descriptor,
            &v.full,
            &secrets,
            &configs,
            revoke,
            self.now(),
        )
        .unwrap();
        let body = serde_json::to_vec(&rotation.request).unwrap();
        let r = self
            .send(self.signed(&v.owner, "POST", "/v1/vault/rotations", body))
            .await;
        (r, rotation)
    }

    // ------------------------------------------------------------ vaults

    /// `GET /v1/capabilities`, unauthenticated.
    pub async fn capabilities(&self) -> Capabilities {
        let r = self
            .send(
                Request::get("/v1/capabilities")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        serde_json::from_value(r.body).unwrap()
    }

    pub async fn challenge(&self) -> ChallengeResponse {
        let r = self
            .send(
                Request::post("/v1/challenges")
                    .body(Body::from(r#"{"purpose":"create_vault"}"#))
                    .unwrap(),
            )
            .await;
        assert_eq!(r.status, StatusCode::OK, "{:?}", r.body);
        serde_json::from_value(r.body).unwrap()
    }

    /// A creation request for `node`'s vault: generation 1, owner-signed,
    /// with a solved challenge when the capabilities ask for one, as a
    /// client does it.
    pub async fn creation(&self, node: &NodeKey) -> (Vault, CreateVaultRequest) {
        let owner = node.owner();
        let full = FullBundle::generate(1);
        let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), self.now());
        let (challenge, nonce) = match self.capabilities().await.proof_of_work {
            Some(_) => {
                let c = self.challenge().await;
                let nonce = pow::solve(&c.challenge, c.difficulty).unwrap();
                (Some(c.challenge), Some(nonce))
            }
            None => (None, None),
        };
        let request = CreateVaultRequest::new(
            owner.vault_id(),
            owner.sign_pub(),
            owner.box_pub(),
            owner.sign_descriptor(&descriptor),
            seal_owner_bundle(&owner, &full).unwrap(),
        )
        .with_proof(challenge, nonce);
        (
            Vault {
                owner,
                full,
                descriptor,
            },
            request,
        )
    }

    pub async fn submit(&self, owner: &OwnerKeys, request: &CreateVaultRequest) -> Reply {
        let body = serde_json::to_vec(request).unwrap();
        self.send(self.signed(owner, "POST", "/v1/vaults", body))
            .await
    }

    pub async fn create_vault(&self) -> Vault {
        let (v, request) = self.creation(&NodeKey::generate()).await;
        let r = self.submit(&v.owner, &request).await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        v
    }

    pub fn pk(&self, v: &Vault) -> i64 {
        self.store.vault_by_id(&v.id()).unwrap().unwrap().pk
    }

    // ------------------------------------------------------------ tokens

    pub fn registration(
        v: &Vault,
        t: &TokenKeys,
        scope: Scope,
        ttl_secs: u64,
    ) -> RegisterTokenRequest {
        RegisterTokenRequest::new(
            t.id(),
            t.auth_pub(),
            t.box_pub(),
            scope,
            ttl_secs,
            None,
            v.full.generation,
            seal_for_scope(&v.owner, &t.box_pub(), &t.id(), scope, &v.full).unwrap(),
        )
    }

    pub async fn register<'a>(
        &self,
        who: impl Into<As<'a>>,
        request: &RegisterTokenRequest,
    ) -> Reply {
        let body = serde_json::to_vec(request).unwrap();
        self.send(self.signed(who, "POST", "/v1/tokens", body))
            .await
    }

    pub async fn mint_with(&self, v: &Vault, scope: Scope, ttl: u64) -> TokenKeys {
        let t = TokenKeys::generate(v.id());
        let r = self
            .register(&v.owner, &Self::registration(v, &t, scope, ttl))
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "{:?}", r.body);
        t
    }

    pub async fn mint(&self, v: &Vault, scope: Scope) -> TokenKeys {
        self.mint_with(v, scope, 0).await
    }

    /// What a holder does first: fetch its own view, verify the descriptor
    /// against the vault id in its token string, and open its bundle.
    pub async fn token_bundle(&self, t: &TokenKeys) -> (TokenSelf, Descriptor, Bundle) {
        let me: TokenSelf = self.fetch(t, "/v1/tokens/self").await;
        let d = me
            .descriptor
            .verify_for(&t.vault_id(), &me.owner_sign_pub)
            .unwrap();
        let bundle = t
            .open_bundle(
                &me.bundle,
                &me.owner_sign_pub,
                me.scope.get().unwrap(),
                d.generation,
            )
            .unwrap();
        (me, d, bundle)
    }
}

pub fn with_header(mut req: Request<Body>, name: &'static str, value: &str) -> Request<Body> {
    req.headers_mut().insert(
        HeaderName::from_static(name),
        HeaderValue::from_str(value).unwrap(),
    );
    req
}
