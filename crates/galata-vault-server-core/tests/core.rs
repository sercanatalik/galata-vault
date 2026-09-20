//! The core with no HTTP (`specs/server-core`): signed canonical requests
//! passed straight to `Core::call`, as the SDK's embedded transport passes
//! them.

use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};

use galata_vault_keys::{
    FullBundle, NodeKey, OwnerKeys, TokenKeys, seal_for_scope, seal_owner_bundle,
};
use galata_vault_proto::api::{
    Capabilities, CreateVaultRequest, ErrorBody, RegisterTokenRequest, Scope,
};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::Hash32;
use galata_vault_proto::sig::SignedRequest;
use galata_vault_seal::Writer;
use galata_vault_server_core::{
    CanonicalRequest, Clock, Core, CoreResponse, FileJournal, Journal, Policy,
};
use galata_vault_store::{JournalRecord, SqliteStore, StoreConfig};

const T0: i64 = 1_757_500_000;

struct Fixed(AtomicI64);

impl Clock for Fixed {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// A file journal whose writes can be made to fail.
struct Switch {
    inner: FileJournal,
    down: AtomicBool,
}

impl Journal for Switch {
    fn put(&self, record: &JournalRecord) -> Result<(), String> {
        if self.down.load(Ordering::SeqCst) {
            return Err("journal unreachable".into());
        }
        self.inner.put(record)
    }
    fn list_after(&self, after: u64) -> Result<Vec<JournalRecord>, String> {
        self.inner.list_after(after)
    }
    fn check(&self) -> Result<(), String> {
        self.inner.check()
    }
    fn describe(&self) -> String {
        "switchable".into()
    }
}

struct Node {
    owner: OwnerKeys,
    full: FullBundle,
    descriptor: Descriptor,
}

struct Fixture {
    core: Core,
    store: Arc<SqliteStore>,
    journal: Arc<Switch>,
}

fn open(dir: &Path) -> Fixture {
    let store = Arc::new(SqliteStore::open(StoreConfig::new(dir.join("vault.db"))).unwrap());
    let journal = Arc::new(Switch {
        inner: FileJournal::open(dir.join("journal-root")).unwrap(),
        down: AtomicBool::new(false),
    });
    let core = Core::open(
        store.clone(),
        journal.clone(),
        Policy::default(),
        Arc::new(Fixed(AtomicI64::new(T0))),
    )
    .unwrap();
    Fixture {
        core,
        store,
        journal,
    }
}

/// Who signs a request, if anyone.
#[derive(Clone, Copy)]
enum By<'a> {
    Nobody,
    Owner(&'a OwnerKeys),
    Token(&'a TokenKeys),
}

/// A request as a transport hands it over: signed over exactly these bytes.
fn call(
    core: &Core,
    by: By<'_>,
    method: &str,
    path: &str,
    body: &[u8],
    create: bool,
) -> CoreResponse {
    let if_none_match = create.then_some("*");
    let signed = SignedRequest {
        method,
        path_and_query: path,
        body,
        if_match: None,
        if_none_match,
    };
    let authorization = match by {
        By::Nobody => None,
        By::Owner(o) => Some(o.sign_request(&signed, T0).to_header_value()),
        By::Token(t) => Some(t.sign_request(&signed, T0).to_header_value()),
    };
    core.call(CanonicalRequest {
        method,
        path_and_query: path,
        authorization: authorization.as_deref(),
        if_match: None,
        if_none_match,
        body,
    })
}

fn code(response: &CoreResponse) -> String {
    let body: ErrorBody = serde_json::from_slice(&response.body).unwrap();
    serde_json::to_value(body.error)
        .unwrap()
        .as_str()
        .unwrap()
        .to_owned()
}

fn create(core: &Core) -> Node {
    let owner = NodeKey::generate().owner();
    let full = FullBundle::generate(1);
    let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), T0);
    let request = CreateVaultRequest::new(
        owner.vault_id(),
        owner.sign_pub(),
        owner.box_pub(),
        owner.sign_descriptor(&descriptor),
        seal_owner_bundle(&owner, &full).unwrap(),
    );
    let body = serde_json::to_vec(&request).unwrap();
    let r = call(core, By::Owner(&owner), "POST", "/v1/vaults", &body, false);
    assert_eq!(r.status, 201, "{r:?}");
    Node {
        owner,
        full,
        descriptor,
    }
}

fn registration(v: &Node, t: &TokenKeys, scope: Scope) -> Vec<u8> {
    serde_json::to_vec(&RegisterTokenRequest::new(
        t.id(),
        t.auth_pub(),
        t.box_pub(),
        scope,
        0,
        None,
        1,
        seal_for_scope(&v.owner, &t.box_pub(), &t.id(), scope, &v.full).unwrap(),
    ))
    .unwrap()
}

fn mint(core: &Core, v: &Node, scope: Scope) -> TokenKeys {
    let t = TokenKeys::generate(v.owner.vault_id());
    let body = registration(v, &t, scope);
    let r = call(
        core,
        By::Owner(&v.owner),
        "POST",
        "/v1/tokens",
        &body,
        false,
    );
    assert_eq!(r.status, 201, "{r:?}");
    t
}

#[test]
fn the_default_policy_asks_for_no_challenge_and_announces_no_expiry() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    let r = call(&f.core, By::Nobody, "GET", "/v1/capabilities", b"", false);
    let caps: Capabilities = serde_json::from_slice(&r.body).unwrap();
    assert_eq!((caps.proof_of_work, caps.idle_expiry_days), (None, None));

    let v = create(&f.core);
    let r = call(&f.core, By::Owner(&v.owner), "GET", "/v1/vault", b"", false);
    assert_eq!((r.status, r.expires_at), (200, None));

    let r = call(&f.core, By::Nobody, "POST", "/v1/challenges", b"{}", false);
    assert_eq!((r.status, code(&r)), (404, "not_found".into()));
}

#[test]
fn a_bad_signature_is_the_uniform_401_and_changes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    let v = create(&f.core);
    let t = TokenKeys::generate(v.owner.vault_id());
    let signed_for = registration(&v, &t, Scope::Meta);
    let sent = registration(&v, &t, Scope::Admin);
    let signed = SignedRequest::new("POST", "/v1/tokens", &signed_for);
    let authorization = v.owner.sign_request(&signed, T0).to_header_value();
    let r = f.core.call(CanonicalRequest {
        method: "POST",
        path_and_query: "/v1/tokens",
        authorization: Some(&authorization),
        if_match: None,
        if_none_match: None,
        body: &sent,
    });
    assert_eq!((r.status, code(&r)), (401, "unauthorized".into()));
    let r = call(&f.core, By::Token(&t), "GET", "/v1/tokens/self", b"", false);
    assert_eq!(r.status, 401, "no token was registered");
}

#[test]
fn a_replayed_request_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    let v = create(&f.core);
    let signed = SignedRequest::new("GET", "/v1/vault", b"");
    let authorization = v.owner.sign_request(&signed, T0).to_header_value();
    let request = CanonicalRequest {
        method: "GET",
        path_and_query: "/v1/vault",
        authorization: Some(&authorization),
        if_match: None,
        if_none_match: None,
        body: b"",
    };
    assert_eq!(f.core.call(request).status, 200);
    let again = f.core.call(request);
    assert_eq!((again.status, code(&again)), (401, "unauthorized".into()));
}

#[test]
fn a_journal_failure_is_unavailable_and_the_token_stays_valid() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    let v = create(&f.core);
    let t = mint(&f.core, &v, Scope::Read);
    f.journal.down.store(true, Ordering::SeqCst);
    let path = format!("/v1/tokens/{}", t.id().to_hex());
    let r = call(&f.core, By::Owner(&v.owner), "DELETE", &path, b"", false);
    assert_eq!((r.status, code(&r)), (503, "unavailable".into()));
    let r = call(&f.core, By::Token(&t), "GET", "/v1/tokens/self", b"", false);
    assert_eq!(r.status, 200, "the revocation was rolled back");
}

#[test]
fn an_older_database_is_caught_up_when_the_core_opens() {
    let dir = tempfile::tempdir().unwrap();
    let backup = dir.path().join("backup.db");
    let (v, t) = {
        let f = open(dir.path());
        let v = create(&f.core);
        let t = mint(&f.core, &v, Scope::Read);
        f.store.checkpoint().unwrap();
        std::fs::copy(dir.path().join("vault.db"), &backup).unwrap();
        let path = format!("/v1/tokens/{}", t.id().to_hex());
        let r = call(&f.core, By::Owner(&v.owner), "DELETE", &path, b"", false);
        assert_eq!(r.status, 200);
        (v, t)
    };
    for stale in ["vault.db-wal", "vault.db-shm"] {
        let _ = std::fs::remove_file(dir.path().join(stale));
    }
    std::fs::copy(&backup, dir.path().join("vault.db")).unwrap();

    let f = open(dir.path());
    assert_eq!(f.core.replayed(), 1, "the revocation, from the journal");
    let r = call(&f.core, By::Token(&t), "GET", "/v1/tokens/self", b"", false);
    assert_eq!(r.status, 401);
    let r = call(&f.core, By::Owner(&v.owner), "GET", "/v1/vault", b"", false);
    assert_eq!(r.status, 200);
}

#[test]
fn quotas_apply_under_the_default_policy() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    let v = create(&f.core);
    let writer = Writer {
        descriptor: &v.descriptor,
        name_key: &v.full.name_key,
        writer: &v.full.secret_writer,
    };
    let record = writer.secret("BIG", &[b'x'; 20 * 1024], 1, T0).unwrap();
    let body = serde_json::to_vec(&record.put_request().unwrap()).unwrap();
    let path = format!("/v1/secrets/{}", record.name_hmac.to_hex());
    let r = call(&f.core, By::Owner(&v.owner), "PUT", &path, &body, true);
    assert_eq!((r.status, code(&r)), (413, "value_too_large".into()));
    let r = call(&f.core, By::Owner(&v.owner), "GET", &path, b"", false);
    assert_eq!(r.status, 404, "nothing was stored");
}

#[test]
fn unknown_paths_and_methods_are_refused_as_the_router_refused_them() {
    let dir = tempfile::tempdir().unwrap();
    let f = open(dir.path());
    for (method, path, status, error) in [
        ("GET", "/v1/vault", 404, "not_found"),
        ("GET", "/v1/secrets/", 404, "not_found"),
        ("GET", "/v1/tokens", 400, "invalid_request"),
        ("DELETE", "/v1/tokens/self", 400, "invalid_request"),
        ("GET", "/v1/vault", 401, "unauthorized"),
    ] {
        let r = call(&f.core, By::Nobody, method, path, b"", false);
        assert_eq!(
            (r.status, code(&r)),
            (status, error.into()),
            "{method} {path}"
        );
    }
}
