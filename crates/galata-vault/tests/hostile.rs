//! Whatever a server sends, the client returns an error and never panics
//! and every code the Python suite asserts is produced unchanged for the
//! same failure.
//!
//! The hostile answers come from transports that never open a socket (or
//! that pass only the token's own view through to a real server), so every
//! `galata_vault::client::Api` operation and the SDK paths on top meet malformed JSON,
//! unknown statuses, truncated bodies and unknown error codes.

use std::net::SocketAddr;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use galata_vault::backend::{SqliteStore, StoreConfig};
use galata_vault::client::{
    Api, ApiError, Auth, HttpTransport, Pre, RecordingTransport, Request, Response, Transport,
    TransportError,
};
use galata_vault::keys::{
    FullBundle, NodeKey, OwnerKeys, TokenKeys, seal_for_scope, seal_owner_bundle,
};
use galata_vault::owner::Owner;
use galata_vault::proto::api::{
    ChallengePurpose, CreateVaultRequest, DeleteRecordRequest, PutSecretRequest,
    RegisterTokenRequest, ReportTokenRequest, RotationRequest,
};
use galata_vault::proto::children::ChildrenRecord;
use galata_vault::proto::ids::{B64, Hash32, NameHmac, Sig64};
use galata_vault::proto::record::RecordKind;
use galata_vault::server::journal::FileJournal;
use galata_vault::server::{AppState, ServerConfig, SystemClock, router};
use galata_vault::state::MemoryStateStore;
use galata_vault::store::MemoryKeyStore;
use galata_vault::testing::RawVault;
use galata_vault::{
    ChainHead, ClientBuilder, ConfigFormat, Error, ErrorKind, NewConfig, Scope, Vault, code,
    kind_of,
};

fn start() -> String {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let config = ServerConfig::for_database(&db);
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let state = AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap();
    let app = router(state);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        let _dir = dir;
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(listener).unwrap();
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
    });
    format!("http://{addr}")
}

/// What a hostile or broken server might answer.
fn hostile() -> Vec<(&'static str, Response)> {
    vec![
        ("malformed json", Response::new(200, b"{not json".to_vec())),
        (
            "an unknown 2xx",
            Response::new(299, b"\xff\xfe\x00".to_vec()),
        ),
        ("an unknown 5xx", Response::new(599, Vec::new())),
        ("an unknown 1xx", Response::new(103, b"{}".to_vec())),
        (
            "a redirect",
            Response::new(307, Vec::new()).with_expires_at("soon"),
        ),
        (
            "a truncated body",
            Response::new(200, br#"{"vault_id":"abab","generation":"#.to_vec())
                .with_expires_at("99999999999999999999999"),
        ),
        (
            "an unknown error code",
            Response::new(409, br#"{"error":"brand_new_code","message":"x"}"#.to_vec()),
        ),
        (
            "an error body of the wrong shape",
            Response::new(401, br#"{"error":7,"message":null}"#.to_vec()),
        ),
        ("an empty 200", Response::new(200, Vec::new())),
        ("the wrong shape", Response::new(200, b"[1,2,3]".to_vec())),
    ]
}

fn canned(response: Response) -> Api {
    Api::new(RecordingTransport::responding(
        move |_| Ok(response.clone()),
    ))
}

/// The inputs every operation needs, built for real so only the server's
/// answer is hostile.
struct Inputs {
    owner: OwnerKeys,
    token: TokenKeys,
    create: CreateVaultRequest,
    rotation: RotationRequest,
    register: RegisterTokenRequest,
    put: PutSecretRequest,
    delete: DeleteRecordRequest,
    report: ReportTokenRequest,
}

fn inputs() -> Inputs {
    let owner = NodeKey::generate().owner();
    let token = TokenKeys::generate(owner.vault_id());
    let full = FullBundle::generate(1);
    let descriptor = owner.sign_descriptor(&full.descriptor(owner.vault_id(), Hash32([0; 32]), 1));
    let create = CreateVaultRequest::new(
        owner.vault_id(),
        owner.sign_pub(),
        owner.box_pub(),
        descriptor.clone(),
        seal_owner_bundle(&owner, &full).unwrap(),
    )
    .with_proof(Some("c".into()), Some(0));
    let rotation = RotationRequest::new(
        1,
        0,
        descriptor,
        seal_owner_bundle(&owner, &full).unwrap(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
    );
    let register = RegisterTokenRequest::new(
        token.id(),
        token.auth_pub(),
        token.box_pub(),
        Scope::Read,
        0,
        None,
        1,
        seal_for_scope(&owner, &token.box_pub(), &token.id(), Scope::Read, &full).unwrap(),
    );
    let put = PutSecretRequest::new(B64(vec![1]), B64(vec![2]), 1, 1, 0, Sig64([0; 64]));
    let delete = DeleteRecordRequest::new(B64(vec![1]), 1, 2, 0, Sig64([0; 64]));
    let report = ReportTokenRequest::new(token.id(), 1, token.sign_report(1));
    Inputs {
        owner,
        token,
        create,
        rotation,
        register,
        put,
        delete,
        report,
    }
}

type Op = Box<dyn Fn(&Api, &Inputs) -> Result<(), ApiError>>;

/// Every public `Api` operation. The flag says whether it decodes its body
/// (the others ignore it, so a 2xx with any body is a success).
fn operations() -> Vec<(&'static str, bool, Op)> {
    let index = NameHmac([3; 32]);
    let mut ops: Vec<(&'static str, bool, Op)> = Vec::new();
    ops.push((
        "status",
        true,
        Box::new(|a, i| a.status(Auth::Owner(&i.owner)).map(drop)),
    ));
    ops.push((
        "token_self",
        true,
        Box::new(|a, i| a.token_self(&i.token).map(drop)),
    ));
    ops.push((
        "challenge",
        true,
        Box::new(|a, _| a.challenge(ChallengePurpose::CreateVault).map(drop)),
    ));
    ops.push((
        "create_vault",
        true,
        Box::new(|a, i| a.create_vault(&i.owner, &i.create).map(drop)),
    ));
    ops.push((
        "delete_vault",
        false,
        Box::new(|a, i| a.delete_vault(&i.owner).map(drop)),
    ));
    ops.push((
        "descriptors",
        true,
        Box::new(|a, i| a.descriptors(Auth::Token(&i.token), 0).map(drop)),
    ));
    ops.push((
        "rotate",
        true,
        Box::new(|a, i| a.rotate(&i.owner, &i.rotation).map(drop)),
    ));
    ops.push((
        "children_get",
        true,
        Box::new(|a, i| a.children_get(&i.owner).map(drop)),
    ));
    ops.push((
        "children_put",
        false,
        Box::new(|a, i| {
            let blob = i.owner.seal_children(1, &ChildrenRecord::new()).unwrap();
            a.children_put(&i.owner, &blob, Pre::Create).map(drop)
        }),
    ));
    ops.push((
        "list",
        true,
        Box::new(move |a, i| {
            a.list(Auth::Token(&i.token), RecordKind::Secret, Some(&index))
                .map(drop)
        }),
    ));
    ops.push((
        "versions",
        true,
        Box::new(move |a, i| {
            a.versions(Auth::Token(&i.token), RecordKind::Config, &index)
                .map(drop)
        }),
    ));
    ops.push((
        "record",
        true,
        Box::new(move |a, i| {
            a.record(Auth::Token(&i.token), RecordKind::Secret, &index, Some(2))
                .map(drop)
        }),
    ));
    ops.push((
        "put",
        true,
        Box::new(move |a, i| {
            a.put(
                Auth::Token(&i.token),
                RecordKind::Secret,
                &index,
                &i.put,
                Pre::Create,
            )
            .map(drop)
        }),
    ));
    ops.push((
        "delete",
        true,
        Box::new(move |a, i| {
            a.delete(
                Auth::Owner(&i.owner),
                RecordKind::Config,
                &index,
                &i.delete,
                Pre::Update(1),
            )
            .map(drop)
        }),
    ));
    ops.push((
        "audit",
        true,
        Box::new(|a, i| a.audit(Auth::Token(&i.token), 7).map(drop)),
    ));
    ops.push((
        "register_token",
        true,
        Box::new(|a, i| a.register_token(&i.owner, &i.register).map(drop)),
    ));
    ops.push((
        "revoke",
        true,
        Box::new(|a, i| a.revoke(Auth::Owner(&i.owner), &i.token.id()).map(drop)),
    ));
    ops.push((
        "report_token",
        true,
        Box::new(|a, i| a.report_token(&i.report).map(drop)),
    ));
    ops
}

#[test]
fn every_api_operation_errs_and_never_panics_on_a_hostile_answer() {
    let inputs = inputs();
    for (what, response) in hostile() {
        let success = (200..300).contains(&response.status);
        let api = canned(response);
        for (op, decodes, call) in operations() {
            let result = catch_unwind(AssertUnwindSafe(|| call(&api, &inputs)))
                .unwrap_or_else(|_| panic!("{op} panicked on {what}"));
            if decodes || !success {
                let e = result.expect_err(&format!("{op} accepted {what}"));
                // Every refusal still has a stable code.
                assert!(!e.stable_code().is_empty(), "{op} on {what}");
            }
        }
    }
    // A failure to get an answer at all.
    let api = Api::new(RecordingTransport::responding(|_| {
        Err(TransportError::new("https://vault.example", "reset"))
    }));
    for (op, _, call) in operations() {
        let e = call(&api, &inputs).expect_err(op);
        assert_eq!(e.stable_code(), "unreachable", "{op}");
    }
}

/// The token's own view comes from a real server; every other answer is
/// hostile. So the SDK gets past opening the vault and meets the hostile
/// answer on each operation.
struct HalfHostile {
    real: HttpTransport,
    bad: Response,
}

impl Transport for HalfHostile {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        if request.path_and_query.starts_with("/v1/tokens/self")
            || request.path_and_query == "/v1/capabilities"
        {
            self.real.send(request)
        } else {
            Ok(self.bad.clone())
        }
    }
}

/// A vault with a secret and a config, and an admin token for it.
fn world(url: &str) -> (RawVault, String) {
    let api = ClientBuilder::new(url).build().unwrap();
    let key = NodeKey::generate();
    assert!(RawVault::create(&api, &key, "acme/dev").unwrap());
    let owner = RawVault::open_owner(&api, &key, "acme/dev").unwrap();
    let pre = owner.current("S").unwrap();
    owner.put("S", b"v", pre).unwrap();
    let pre = owner.config_current("app").unwrap();
    owner
        .put_config("app", ConfigFormat::Toml, b"a = 1\n", pre)
        .unwrap();
    let token = owner.mint(Scope::Admin, 0, None).unwrap().0;
    (owner, token.token_string().to_string())
}

#[test]
fn every_sdk_path_errs_and_never_panics_on_a_hostile_answer() {
    let url = start();
    let (_owner, token) = world(&url);
    let real = ClientBuilder::new(&url).build_transport().unwrap();
    for (what, response) in hostile() {
        // Opening itself meets the hostile answer.
        let api = canned(response.clone());
        let opened = catch_unwind(AssertUnwindSafe(|| Vault::with_api(&token, &api)))
            .unwrap_or_else(|_| panic!("opening panicked on {what}"));
        assert!(opened.is_err(), "opened on {what}");

        let api = Api::new(HalfHostile {
            real: real.clone(),
            bad: response,
        });
        let vault = Vault::with_api(&token, &api).unwrap();
        type Call<'a> = (&'static str, Box<dyn Fn() -> Result<(), Error> + 'a>);
        let calls: Vec<Call> = vec![
            ("secret", Box::new(|| vault.secret("S").map(drop))),
            (
                "secret_version",
                Box::new(|| vault.secret_version("S", 1).map(drop)),
            ),
            ("secrets", Box::new(|| vault.secrets(&["S"]).map(drop))),
            ("readable", Box::new(|| vault.readable(None).map(drop))),
            ("list", Box::new(|| vault.list().map(drop))),
            ("list_all", Box::new(|| vault.list_all().map(drop))),
            ("history", Box::new(|| vault.history("S").map(drop))),
            (
                "set_secret",
                Box::new(|| vault.set_secret("S", b"x").map(drop)),
            ),
            (
                "delete_secret",
                Box::new(|| vault.delete_secret("S", None).map(drop)),
            ),
            ("config", Box::new(|| vault.config("app").map(drop))),
            ("list_configs", Box::new(|| vault.list_configs().map(drop))),
            (
                "set_config",
                Box::new(|| {
                    vault
                        .set_config("app", NewConfig::toml("a = 2\n"))
                        .map(drop)
                }),
            ),
            (
                "delete_config",
                Box::new(|| vault.delete_config("app", None).map(drop)),
            ),
            (
                "verify_audit",
                Box::new(|| vault.verify_audit(None).map(drop)),
            ),
            ("status", Box::new(|| vault.status().map(drop))),
            (
                "audit",
                Box::new(|| vault.audit(&MemoryStateStore::new()).map(drop)),
            ),
        ];
        for (op, call) in calls {
            let result = catch_unwind(AssertUnwindSafe(&call))
                .unwrap_or_else(|_| panic!("{op} panicked on {what}"));
            assert!(result.is_err(), "{op} accepted {what}");
        }
    }
}

#[test]
fn owner_operations_err_and_never_panic_on_a_hostile_answer() {
    let url = start();
    for (what, response) in hostile() {
        let keys = Arc::new(MemoryKeyStore::new());
        let state = Arc::new(MemoryStateStore::new());
        let mut owner = Owner::open(keys.clone(), state.clone()).unwrap();
        owner
            .begin_init("acme", &url)
            .unwrap()
            .confirm_kit_stored()
            .unwrap();
        owner.env_add(&"acme/dev".parse().unwrap()).unwrap();
        let mut owner = owner.with_connector(move |_| Ok(canned(response.clone())));
        let dev = "acme/dev".parse().unwrap();
        let acme = "acme".parse().unwrap();
        let results = catch_unwind(AssertUnwindSafe(|| {
            [
                ("environment", owner.environment(&dev).map(drop)),
                ("env_add", owner.env_add(&"acme/qa".parse().unwrap())),
                ("env_repair", owner.env_repair(&dev).map(drop)),
                ("env_remove", owner.env_remove(&dev, true).map(drop)),
                ("refresh", owner.refresh(&acme)),
                ("discover", owner.discover(&acme).map(drop)),
            ]
        }))
        .unwrap_or_else(|_| panic!("an owner operation panicked on {what}"));
        for (op, result) in results {
            assert!(result.is_err(), "{op} accepted {what}");
        }
    }
}

/// Every code the Python suite asserts, produced for the same failure as
/// before, with the same kind.
#[test]
fn every_code_the_python_suite_asserts_is_unchanged() {
    let url = start();
    let (owner, admin) = world(&url);
    let admin = Vault::new(&admin, &url).unwrap();
    let mint = |scope| owner.mint(scope, 0, None).unwrap().0;
    let mut seen: Vec<(Error, &str, ErrorKind)> = Vec::new();

    // unauthorized: a revoked token.
    let revoked = mint(Scope::Read);
    owner.revoke(&revoked.id()).unwrap();
    let e = Vault::new(&revoked.token_string(), &url).unwrap_err();
    seen.push((e, "unauthorized", ErrorKind::Auth));
    // token_expired: the server's refusal, kept verbatim.
    let expired = canned(Response::new(
        401,
        br#"{"error":"token_expired","message":"expired"}"#.to_vec(),
    ));
    let e = Vault::with_api(&mint(Scope::Read).token_string(), &expired).unwrap_err();
    seen.push((e, "token_expired", ErrorKind::Auth));
    // not_found, forbidden, conflict.
    seen.push((
        admin.secret("MISSING").unwrap_err(),
        "not_found",
        ErrorKind::NotFound,
    ));
    let config = Vault::new(&mint(Scope::Config).token_string(), &url).unwrap();
    seen.push((
        config.secret("S").unwrap_err(),
        "forbidden",
        ErrorKind::Forbidden,
    ));
    admin.set_config("app", NewConfig::toml("a = 2\n")).unwrap();
    seen.push((
        admin
            .set_config("app", NewConfig::toml("a = 3\n").expect_version(1))
            .unwrap_err(),
        "conflict",
        ErrorKind::Conflict,
    ));
    // unreachable.
    let token = mint(Scope::Read).token_string().to_string();
    seen.push((
        Vault::new(&token, "http://127.0.0.1:1").unwrap_err(),
        "unreachable",
        ErrorKind::Transport,
    ));
    // Refused locally, before any request.
    seen.push((
        admin.set_secret("gv:children", b"x").unwrap_err(),
        "invalid_name",
        ErrorKind::Invalid,
    ));
    admin.set_config("k8s", NewConfig::yaml("a: 1\n")).unwrap();
    seen.push((
        admin
            .config("k8s")
            .unwrap()
            .deserialize::<serde_json::Value>()
            .unwrap_err(),
        "unsupported_format",
        ErrorKind::Invalid,
    ));
    let pre = owner.config_current("raw").unwrap();
    owner
        .put_config("raw", ConfigFormat::Text, b"\xff\xfe", pre)
        .unwrap();
    seen.push((
        admin.config("raw").unwrap().text().unwrap_err(),
        "not_text",
        ErrorKind::Invalid,
    ));
    seen.push((
        Vault::new("gvt1_nonsense", &url).unwrap_err(),
        "invalid_token",
        ErrorKind::Auth,
    ));
    seen.push((
        Vault::new(&token, "http://vault.example").unwrap_err(),
        "invalid_server",
        ErrorKind::Invalid,
    ));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("token");
        std::fs::write(&file, &token).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).unwrap();
        seen.push((
            Vault::from_token_file(&file, &url).unwrap_err(),
            "invalid_token_file",
            ErrorKind::Invalid,
        ));
    }
    seen.push((
        admin
            .set_config(
                "k",
                NewConfig::toml("k = \"\"\"\n-----BEGIN EC PRIVATE KEY-----\n\"\"\"\n"),
            )
            .unwrap_err(),
        "credential_literal",
        ErrorKind::Invalid,
    ));
    seen.push((
        admin
            .set_config("bad", NewConfig::toml("a = = 1\n"))
            .unwrap_err(),
        "invalid_config",
        ErrorKind::Invalid,
    ));
    // Integrity: a forged descriptor, a rolled-back version, a forked audit
    // head, a v1 token.
    let forged = Api::new(Tamper(ClientBuilder::new(&url).build_transport().unwrap()));
    seen.push((
        Vault::with_api(&token, &forged).unwrap_err(),
        "bad_signature",
        ErrorKind::Integrity,
    ));
    let reader = Vault::new(&token, &url).unwrap();
    reader.secret("S").unwrap();
    let mut ahead = reader.pins();
    for v in ahead.secrets.values_mut() {
        *v += 5;
    }
    let behind = Vault::new(&token, &url).unwrap();
    behind.set_pins(ahead).unwrap();
    seen.push((
        behind.secret("S").unwrap_err(),
        "version_rollback",
        ErrorKind::Integrity,
    ));
    let head = reader.verify_audit(None).unwrap().head.unwrap();
    let fork = ChainHead::new(head.seq, Hash32([0; 32]));
    seen.push((
        reader.verify_audit(Some(fork)).unwrap_err(),
        "audit_mismatch",
        ErrorKind::Integrity,
    ));

    for (e, want, kind) in &seen {
        assert_eq!((e.code(), e.kind()), (*want, *kind), "{e}");
        assert_eq!(kind_of(want), *kind, "{want}");
        assert!(!e.message().contains(&token[5..]), "{e}");
    }
    // Asserted by Python, produced by the environment and the Python layer
    // (sdk.rs runs from_env in a child process): the table is unchanged.
    for (c, kind) in [
        (code::MISSING_SERVER, ErrorKind::Invalid),
        (code::INVALID_ENVIRONMENT, ErrorKind::Invalid),
        (code::INVALID_AUDIT_HEAD, ErrorKind::Invalid),
    ] {
        assert_eq!(kind_of(c), kind, "{c}");
    }
}

/// Passes everything through, flipping one byte of the descriptor the token's
/// view carries.
struct Tamper(HttpTransport);

impl Transport for Tamper {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let mut response = self.0.send(request)?;
        if request.path_and_query.starts_with("/v1/tokens/self")
            && let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&response.body)
        {
            let mut d: B64 = serde_json::from_value(v["descriptor"]["descriptor"].clone()).unwrap();
            d.0[30] ^= 0x5a;
            v["descriptor"]["descriptor"] = serde_json::to_value(d).unwrap();
            response.body = serde_json::to_vec(&v).unwrap();
        }
        Ok(response)
    }
}
