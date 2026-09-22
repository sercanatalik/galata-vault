//! The SDK against a real server, in-process on loopback: what an application
//! sees. The owner's setup (vault creation, minting, owner writes) goes
//! through the shared core, as `gv` does it.
//!
//! A test-only layer in front of the router can forge responses, to show the
//! SDK refuses what does not verify.
//!
//! Two tests re-run this binary as a child process: one to set the
//! environment `from_env` reads (the workspace forbids the `unsafe` that
//! `set_var` needs), one to prove the library writes nothing to stdout or
//! stderr.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::process::{Command, Output};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

use axum::body::Body;
use axum::extract::Request;
use axum::middleware::Next;
use axum::response::Response;
use galata_vault::ClientBuilder;
use galata_vault::backend::{SqliteStore, StoreConfig};
use galata_vault::client::{
    Api, HttpTransport, RecordingTransport, Request as WireRequest, Response as WireResponse,
    Transport, TransportError,
};
use galata_vault::keys::NodeKey;
use galata_vault::proto::api::{ChallengeResponse, CreateVaultRequest, ErrorCode};
use galata_vault::proto::ids::{B64, Hash32};
use galata_vault::proto::pow::{self, CHALLENGE_TTL_SECS, Challenge};
use galata_vault::server::journal::FileJournal;
use galata_vault::server::{
    AppState, Core as ServerCore, Policy, ServerConfig, SystemClock, router,
};
use galata_vault::server_core::{Admission, Admitted, CoreError};
use galata_vault::testing::RawVault as Core;
use galata_vault::{ChainHead, ConfigFormat, ErrorKind, NewConfig, Scope, Vault, code};

struct Server {
    url: String,
    /// While set, the latest version of any secret is served with one
    /// ciphertext byte flipped: what a malicious server might do.
    forge: Arc<AtomicBool>,
    _dir: tempfile::TempDir,
}

fn is_latest_secret(path: &str) -> bool {
    path.strip_prefix("/v1/secrets/")
        .is_some_and(|rest| !rest.is_empty() && !rest.contains('/'))
}

async fn flip_value(response: Response) -> Response {
    let (mut parts, body) = response.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX).await.unwrap();
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return Response::from_parts(parts, Body::from(bytes));
    };
    if let Some(ct) = v.get("value_ct").and_then(|c| c.as_str()) {
        let mut raw = B64::decode_str(ct).unwrap();
        let last = raw.len() - 1;
        raw[last] ^= 1;
        v["value_ct"] = serde_json::Value::String(B64::encode_str(&raw));
    }
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    Response::from_parts(parts, Body::from(serde_json::to_vec(&v).unwrap()))
}

/// An expiring server, with the public service's 90-day window, as these
/// tests were written against. `start_with(Policy::default())` is the
/// default server, which asks for nothing and announces nothing.
fn start() -> Server {
    start_with(Policy {
        idle_expiry_days: Some(90),
        ..Policy::default()
    })
}

fn start_with(policy: Policy) -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let config = ServerConfig::for_database(&db);
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let core = ServerCore::open(store, journal, policy, Arc::new(SystemClock)).unwrap();
    let state = AppState::from_core(core, config);
    let forge = Arc::new(AtomicBool::new(false));
    let flag = forge.clone();
    let app = router(state).layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let flag = flag.clone();
            async move {
                let tamper = flag.load(Ordering::SeqCst)
                    && req.method() == axum::http::Method::GET
                    && is_latest_secret(req.uri().path());
                let response = next.run(req).await;
                if tamper {
                    flip_value(response).await
                } else {
                    response
                }
            }
        },
    ));
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
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
    Server {
        url: format!("http://{addr}"),
        forge,
        _dir: dir,
    }
}

/// A server with one vault, and its owner.
struct Env {
    server: Server,
    owner: Core,
}

fn env() -> Env {
    env_on(start())
}

fn env_on(server: Server) -> Env {
    let client = ClientBuilder::new(&server.url).build().unwrap();
    let key = NodeKey::generate();
    assert!(Core::create(&client, &key, "acme/dev").unwrap());
    let owner = Core::open_owner(&client, &key, "acme/dev").unwrap();
    Env { server, owner }
}

impl Env {
    fn token(&self, scope: Scope) -> String {
        let (token, _) = self.owner.mint(scope, 0, None).unwrap();
        token.token_string().as_str().to_owned()
    }

    fn open(&self, scope: Scope) -> Vault {
        Vault::new(&self.token(scope), &self.server.url).unwrap()
    }

    fn put(&self, name: &str, value: &[u8]) {
        let pre = self.owner.current(name).unwrap();
        self.owner.put(name, value, pre).unwrap();
    }
}

#[test]
fn secrets_and_configs_come_back_exactly_as_written() {
    let env = env();
    env.put("DATABASE_URL", b"postgres://db/acme\n");

    let admin = env.open(Scope::Admin);
    // CRLF, trailing blanks, a blank line and no final newline: all kept.
    let body = b"[app]\r\nname = \"acme\"  \r\nworkers = 4\n\n# no final newline";
    assert_eq!(
        admin
            .set_config("app", NewConfig::toml(body.to_vec()))
            .unwrap(),
        1
    );
    let text = "line one\r\n\tline two \u{a0}".as_bytes();
    admin.set_config("motd", NewConfig::text(text)).unwrap();

    let config = env.open(Scope::Config);
    assert_eq!(config.scope(), Scope::Config);
    let app = config.config("app").unwrap();
    assert_eq!(app.expose(), body);
    assert_eq!((app.version(), app.format()), (1, ConfigFormat::Toml));
    assert_eq!(config.config("motd").unwrap().expose(), text);

    #[derive(serde::Deserialize)]
    struct App {
        app: Inner,
    }
    #[derive(serde::Deserialize)]
    struct Inner {
        name: String,
        workers: u32,
    }
    let parsed: App = app.deserialize().unwrap();
    assert_eq!((parsed.app.name.as_str(), parsed.app.workers), ("acme", 4));

    let names: Vec<_> = config
        .list_configs()
        .unwrap()
        .into_iter()
        .map(|e| e.name)
        .collect();
    assert_eq!(names, ["app", "motd"]);

    admin
        .set_config("app", NewConfig::toml(b"[app]\nname = \"b\"\n".to_vec()))
        .unwrap();
    assert_eq!(config.config_version("app", 1).unwrap().expose(), body);
    assert_eq!(config.config("app").unwrap().version(), 2);

    let read = env.open(Scope::Read);
    let db = read.secret("DATABASE_URL").unwrap();
    assert_eq!(db.expose(), b"postgres://db/acme\n");
    let debug = format!("{db:?} {app:?}");
    assert!(
        !debug.contains("postgres") && !debug.contains("acme"),
        "{debug}"
    );

    let names: Vec<_> = read.list().unwrap().into_iter().map(|e| e.name).collect();
    assert_eq!(names, ["DATABASE_URL"]);

    let e = read.secrets(&["DATABASE_URL", "MISSING"]).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::NotFound);
    assert!(e.message().contains("MISSING"), "{e}");
    assert_eq!(read.secrets(&["DATABASE_URL"]).unwrap().len(), 1);

    assert_eq!(admin.set_secret("API_KEY", b"k1").unwrap(), 1);
    assert_eq!(admin.set_secret("API_KEY", b"k2").unwrap(), 2);
    assert_eq!(read.secret_version("API_KEY", 1).unwrap().expose(), b"k1");
    assert!(read.expiry().token_expires_at.is_some());
}

#[test]
fn a_config_token_never_reaches_a_secret() {
    let env = env();
    env.put("SIGNING_KEY", b"0xdead");
    env.open(Scope::Admin)
        .set_config("app", NewConfig::toml(b"a = 1\n".to_vec()))
        .unwrap();

    let config = env.open(Scope::Config);
    for e in [
        config.secret("SIGNING_KEY").unwrap_err(),
        config.set_secret("OTHER", b"x").unwrap_err(),
        config
            .set_config("app", NewConfig::toml(b"a = 2\n".to_vec()))
            .unwrap_err(),
    ] {
        assert_eq!(e.kind(), ErrorKind::Forbidden, "{e}");
    }

    let writer = env.open(Scope::ConfigWrite);
    assert_eq!(
        writer
            .set_config("app", NewConfig::toml(b"a = 2\n".to_vec()))
            .unwrap(),
        2
    );
    // A config-write token holds no secret key and no secret writer key.
    assert_eq!(
        writer.secret("SIGNING_KEY").unwrap_err().kind(),
        ErrorKind::Forbidden
    );
    assert_eq!(
        writer.set_secret("OTHER", b"x").unwrap_err().kind(),
        ErrorKind::Forbidden
    );

    // A meta token can list configs but holds no key to open one.
    let meta = env.open(Scope::Meta);
    assert_eq!(meta.list_configs().unwrap().len(), 1);
    assert_eq!(meta.config("app").unwrap_err().kind(), ErrorKind::Forbidden);
}

#[test]
fn a_stale_config_edit_conflicts_and_overwrites_nothing() {
    let env = env();
    let mine = env.open(Scope::ConfigWrite);
    let theirs = env.open(Scope::ConfigWrite);
    mine.set_config("app", NewConfig::toml(b"v = 1\n".to_vec()))
        .unwrap();
    let read = mine.config("app").unwrap();

    theirs
        .set_config("app", NewConfig::toml(b"v = 2\n".to_vec()))
        .unwrap();
    let e = mine
        .set_config(
            "app",
            NewConfig::toml(b"v = 3\n".to_vec()).expect_version(read.version()),
        )
        .unwrap_err();
    assert_eq!((e.code(), e.kind()), (code::CONFLICT, ErrorKind::Conflict));
    assert!(
        e.message().contains('1') && e.message().contains('2'),
        "{e}"
    );
    assert_eq!(mine.config("app").unwrap().expose(), b"v = 2\n");

    let e = mine
        .set_config("app", NewConfig::toml(b"v = 4\n".to_vec()).expect_absent())
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Conflict);
    assert_eq!(
        mine.set_config("new", NewConfig::toml(b"v = 1\n".to_vec()).expect_absent())
            .unwrap(),
        1
    );
}

#[test]
fn config_writes_are_checked_on_this_side() {
    let env = env();
    let writer = env.open(Scope::ConfigWrite);

    let e = writer
        .set_config("app", NewConfig::toml(b"a = 1\nb = = 2\n".to_vec()))
        .unwrap_err();
    assert_eq!(e.code(), code::INVALID_CONFIG);
    assert!(e.message().starts_with("line 2"), "{e}");

    let key = format!("[producer]\nagent_key = \"0x{}\"\n", "ab".repeat(32));
    let e = writer
        .set_config("app", NewConfig::toml(key.clone()))
        .unwrap_err();
    assert_eq!(e.code(), code::CREDENTIAL_LITERAL);
    assert!(!e.message().contains(&"ab".repeat(32)));
    assert!(writer.list_configs().unwrap().is_empty(), "nothing written");
    writer
        .set_config("app", NewConfig::toml(key).allow_literals())
        .unwrap();

    let e = writer
        .set_config("gv:children", NewConfig::text("x"))
        .unwrap_err();
    assert_eq!(e.code(), code::INVALID_NAME);
    assert_eq!(
        writer.set_secret("gv:x", b"x").unwrap_err().code(),
        code::INVALID_NAME
    );

    writer.set_config("k8s", NewConfig::yaml("a: 1\n")).unwrap();
    let e = writer
        .config("k8s")
        .unwrap()
        .deserialize::<serde_json::Value>()
        .unwrap_err();
    assert_eq!(e.code(), code::UNSUPPORTED_FORMAT);
}

#[test]
fn an_append_token_writes_what_the_owner_reads() {
    let env = env();
    let append = env.open(Scope::Append);
    assert_eq!(append.set_secret("FROM_CI", b"v1").unwrap(), 1);
    let (_, opened) = env.owner.get("FROM_CI", None).unwrap();
    assert_eq!(&opened.value[..], b"v1");
    assert_eq!(
        append.secret("FROM_CI").unwrap_err().kind(),
        ErrorKind::Forbidden
    );
}

#[test]
fn a_deleted_secret_is_revived_as_the_next_version() {
    let env = env();
    env.put("GONE", b"v1");
    env.owner.delete("GONE", 1).unwrap();
    let admin = env.open(Scope::Admin);
    assert_eq!(
        admin.secret("GONE").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(admin.set_secret("GONE", b"v3").unwrap(), 3);
    assert_eq!(admin.secret("GONE").unwrap().expose(), b"v3");
}

#[test]
fn a_revoked_token_fails_with_a_stable_code() {
    let env = env();
    env.put("S", b"v");
    let (keys, _) = env.owner.mint(Scope::Read, 0, None).unwrap();
    let token = keys.token_string().as_str().to_owned();
    let id = keys.id();
    let vault = Vault::new(&token, &env.server.url).unwrap();
    env.owner.revoke(&id).unwrap();
    let e = vault.secret("S").unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Auth, "{} {e}", e.code());
    assert_eq!(e.code(), "unauthorized");
    assert!(!e.message().contains(&token));

    let e = Vault::new(&token, &env.server.url).unwrap_err();
    assert_eq!(e.code(), "unauthorized");
}

#[test]
fn a_forged_value_is_an_integrity_error() {
    let env = env();
    env.put("S", b"genuine");
    let read = env.open(Scope::Read);
    assert_eq!(read.secret("S").unwrap().expose(), b"genuine");
    env.server.forge.store(true, Ordering::SeqCst);
    let e = read.secret("S").unwrap_err();
    assert_eq!(
        (e.kind(), e.code()),
        (ErrorKind::Integrity, code::BAD_SIGNATURE),
        "{e}"
    );
    assert!(!e.message().contains("genuine"), "{e}");
    env.server.forge.store(false, Ordering::SeqCst);
    assert_eq!(read.secret("S").unwrap().expose(), b"genuine");
}

#[test]
fn audit_heads_carry_across_handles() {
    let env = env();
    env.put("A", b"1");
    let first = env.open(Scope::Read).verify_audit(None).unwrap();
    let head = first.head.expect("the vault has audit rows");
    env.put("B", b"2");
    // Another handle, of another scope, continues from the kept head.
    let second = env.open(Scope::Meta).verify_audit(Some(head)).unwrap();
    assert!(second.head.unwrap().seq > head.seq);
    assert!(second.new_rows > 0);

    let forged = ChainHead::new(head.seq, Hash32([0; 32]));
    let e = env
        .open(Scope::Read)
        .verify_audit(Some(forged))
        .unwrap_err();
    assert_eq!(
        (e.kind(), e.code()),
        (ErrorKind::Integrity, code::AUDIT_MISMATCH),
        "{e}"
    );
}

#[test]
fn pins_refuse_version_and_generation_rollback() {
    let env = env();
    env.put("S", b"v1");
    env.put("S", b"v2");
    let first = env.open(Scope::Read);
    assert_eq!(first.secret("S").unwrap().version(), 2);
    let pins = first.pins();
    assert_eq!(pins.secrets.values().copied().collect::<Vec<_>>(), [2]);

    // A later handle given the pins accepts the same state...
    let second = env.open(Scope::Read);
    second.set_pins(pins.clone()).unwrap();
    assert_eq!(second.secret("S").unwrap().version(), 2);

    // ...and refuses a latest version older than one it saw.
    let mut ahead = pins.clone();
    for v in ahead.secrets.values_mut() {
        *v += 5;
    }
    let third = env.open(Scope::Read);
    third.set_pins(ahead).unwrap();
    let e = third.secret("S").unwrap_err();
    assert_eq!(
        (e.kind(), e.code()),
        (ErrorKind::Integrity, code::VERSION_ROLLBACK),
        "{e}"
    );

    // A descriptor pin that names a different generation-1 descriptor.
    let mut forked = pins;
    forked.descriptor.as_mut().unwrap().hash = Hash32([1; 32]);
    let e = env.open(Scope::Read).set_pins(forked).unwrap_err();
    assert_eq!(e.code(), code::GENERATION_ROLLBACK, "{e}");
}

#[test]
fn a_token_of_another_version_is_refused_locally() {
    let env = env();
    let other = galata_vault::proto::codec::encode_checked("gvt2_", &[7u8; 48]);
    let e = Vault::new(&other, &env.server.url).unwrap_err();
    assert_eq!((e.code(), e.kind()), (code::INVALID_TOKEN, ErrorKind::Auth));
    assert!(e.message().contains("version 2"), "{e}");
}

#[test]
fn expiry_is_data_for_the_caller() {
    let env = env();
    env.put("S", b"v");
    let read = env.open(Scope::Read);
    read.secret("S").unwrap();
    let expiry = read.expiry();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        expiry.vault_expires_at.is_some_and(|at| at > now),
        "{expiry:?}"
    );
    assert!(
        expiry.token_expires_at.is_some_and(|at| at > now),
        "{expiry:?}"
    );

    // One altered character fails the checksum before any request.
    let token = env.token(Scope::Read);
    let mut altered = token.clone().into_bytes();
    let last = altered.len() - 1;
    altered[last] = if altered[last] == b'a' { b'b' } else { b'a' };
    let altered = String::from_utf8(altered).unwrap();
    let e = Vault::new(&altered, &env.server.url).unwrap_err();
    assert_eq!(e.code(), code::INVALID_TOKEN);
    assert!(!e.message().contains(&altered));
}

#[test]
fn one_handle_serves_eight_threads() {
    let env = env();
    for i in 0..8 {
        env.put(&format!("S{i}"), format!("value-{i}").as_bytes());
    }
    let vault = env.open(Scope::Read);
    std::thread::scope(|s| {
        for i in 0..8 {
            let vault = &vault;
            s.spawn(move || {
                for _ in 0..10 {
                    let v = vault.secret(&format!("S{i}")).unwrap();
                    assert_eq!(v.expose(), format!("value-{i}").as_bytes());
                }
                assert_eq!(vault.list().unwrap().len(), 8);
            });
        }
    });
}

#[test]
fn a_token_file_is_checked_before_it_is_read() {
    let env = env();
    let token = env.token(Scope::Read);
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("token");
    let chmod = |mode| std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode));

    std::fs::write(&path, format!("{token}\n")).unwrap();
    chmod(0o644).unwrap();
    let e = Vault::from_token_file(&path, &env.server.url).unwrap_err();
    assert_eq!(e.code(), code::INVALID_TOKEN_FILE);
    assert!(e.message().contains("0644"), "{e}");
    // Unreadable, yet refused for its mode: the mode is checked first.
    chmod(0o000).unwrap();
    let e = Vault::from_token_file(&path, &env.server.url).unwrap_err();
    assert!(e.message().contains("0000"), "{e}");

    chmod(0o600).unwrap();
    Vault::from_token_file(&path, &env.server.url).unwrap();
    chmod(0o400).unwrap();
    Vault::from_token_file(&path, &env.server.url).unwrap();

    chmod(0o600).unwrap();
    std::fs::write(&path, format!("{token}\n{token}\n")).unwrap();
    let e = Vault::from_token_file(&path, &env.server.url).unwrap_err();
    assert_eq!(e.code(), code::INVALID_TOKEN_FILE);
    assert!(!e.message().contains(&token));

    let e = Vault::from_token_file(dir.path().join("missing"), &env.server.url).unwrap_err();
    assert_eq!(e.code(), code::INVALID_TOKEN_FILE);
}

// ------------------------------------------------------------ child runs

const CHILD: &str = "GV_SDK_CHILD";

fn is_child(role: &str) -> bool {
    std::env::var(CHILD).is_ok_and(|r| r == role)
}

fn run_child(test: &str, envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(std::env::current_exe().unwrap());
    cmd.args(["--exact", test, "--test-threads=1", "--nocapture"]);
    for var in ["GV_SERVER", "GV_TOKEN", "GV_TOKEN_FILE", "RUST_LOG"] {
        cmd.env_remove(var);
    }
    cmd.envs(envs.iter().copied());
    let out = cmd.output().unwrap();
    assert!(
        out.status.success(),
        "{test} {envs:?}\n{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out
}

#[test]
fn child_from_env() {
    if !is_child("from_env") {
        return;
    }
    let expect = std::env::var("GV_SDK_EXPECT").unwrap();
    match Vault::from_env() {
        Ok(v) => assert_eq!(expect, "ok", "opened {v:?}"),
        Err(e) => assert_eq!(e.code(), expect, "{e}"),
    }
}

#[test]
fn from_env_takes_exactly_one_token_source() {
    let env = env();
    let token = env.token(Scope::Read);
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("token");
    std::fs::write(&file, &token).unwrap();
    std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    let file = file.to_str().unwrap();
    let server = env.server.url.as_str();

    let cases: [(&str, &[(&str, &str)]); 5] = [
        ("ok", &[("GV_SERVER", server), ("GV_TOKEN", &token)]),
        ("ok", &[("GV_SERVER", server), ("GV_TOKEN_FILE", file)]),
        (
            code::INVALID_ENVIRONMENT,
            &[
                ("GV_SERVER", server),
                ("GV_TOKEN", &token),
                ("GV_TOKEN_FILE", file),
            ],
        ),
        (code::MISSING_SERVER, &[("GV_TOKEN", &token)]),
        (code::INVALID_TOKEN, &[("GV_SERVER", server)]),
    ];
    for (expect, vars) in cases {
        let mut vars = vars.to_vec();
        vars.extend([(CHILD, "from_env"), ("GV_SDK_EXPECT", expect)]);
        run_child("child_from_env", &vars);
    }
}

#[test]
fn child_quiet() {
    if !is_child("quiet") {
        return;
    }
    let core_limit = rlimit::getrlimit(rlimit::Resource::CORE).unwrap();
    let env = env();
    env.put("S", b"v");
    let admin = env.open(Scope::Admin);
    admin.secret("S").unwrap();
    admin.set_config("app", NewConfig::json("{}")).unwrap();
    // Failures are values too, never output.
    let _ = admin.secret("MISSING");
    let _ = admin.set_config("app", NewConfig::json("{}").expect_absent());
    let _ = admin.set_config("bad", NewConfig::json("{"));
    let _ = env.open(Scope::Config).secret("S");
    let _ = Vault::new("gvt1_x", &env.server.url);
    let _ = admin.verify_audit(None);
    assert_eq!(
        rlimit::getrlimit(rlimit::Resource::CORE).unwrap(),
        core_limit,
        "the library must not change its host's core-dump limit"
    );
}

#[test]
fn the_library_writes_nothing_to_stdout_or_stderr() {
    let out = run_child("child_quiet", &[(CHILD, "quiet")]);
    assert!(
        out.stderr.is_empty(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    // Only the test harness's own lines.
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        assert!(
            line.is_empty() || line.starts_with("running ") || line.starts_with("test "),
            "unexpected output: {line:?}"
        );
    }
}

/// A server that announces no expiry: the SDK reports none, and printed
/// nothing about it either (`the_library_writes_nothing_to_stdout_or_stderr`).
#[test]
fn no_expiry_is_reported_that_the_server_did_not_announce() {
    let env = env_on(start_with(Policy::default()));
    env.put("S", b"v");
    let read = env.open(Scope::Read);
    read.secret("S").unwrap();
    let expiry = read.expiry();
    assert_eq!(expiry.vault_expires_at, None, "{expiry:?}");
    assert!(expiry.token_expires_at.is_some(), "{expiry:?}");
}

/// Proof of work as a hosted server asks for it, in a core built here: the
/// SDK must ask for a challenge exactly when the capabilities say so.
#[derive(Default)]
struct ProofOfWork {
    issued: AtomicU8,
}

const POW_KEY: [u8; 32] = [7; 32];

impl Admission for ProofOfWork {
    fn proof_of_work(&self) -> Option<u8> {
        Some(4)
    }

    fn challenge(&self, now: i64) -> Result<ChallengeResponse, CoreError> {
        let n = self.issued.fetch_add(1, Ordering::SeqCst);
        let expires_at = now + CHALLENGE_TTL_SECS;
        let challenge = Challenge {
            id: [n; 16],
            expires_at,
            difficulty: 4,
        }
        .issue(&POW_KEY);
        Ok(ChallengeResponse::new(challenge, 4, expires_at))
    }

    fn admit_creation(
        &self,
        request: &CreateVaultRequest,
        now: i64,
    ) -> Result<Option<Admitted>, CoreError> {
        let refused = || CoreError::new(ErrorCode::InvalidProofOfWork, "no solved challenge");
        let token = request.challenge.as_deref().ok_or_else(refused)?;
        let c = Challenge::open(token, &POW_KEY, now).map_err(|_| refused())?;
        if !request
            .nonce
            .is_some_and(|n| pow::verify(token, c.difficulty, n))
        {
            return Err(refused());
        }
        Ok(Some(Admitted {
            challenge_id: c.id,
            expires_at: c.expires_at,
        }))
    }
}

#[test]
fn a_challenge_is_asked_for_only_when_the_server_wants_one() {
    // Two creations through one handle; every request the SDK sent.
    let requests = |server: &Server| {
        let http = ClientBuilder::new(&server.url).build_transport().unwrap();
        let recorder = Arc::new(RecordingTransport::forwarding(Arc::new(http)));
        let api = Api::shared(recorder.clone());
        for label in ["acme", "acme/dev"] {
            assert!(Core::create(&api, &NodeKey::generate(), label).unwrap());
        }
        recorder
            .requests()
            .into_iter()
            .map(|r| r.path_and_query)
            .collect::<Vec<_>>()
    };
    let count = |paths: &[String], path: &str| paths.iter().filter(|p| *p == path).count();

    let plain = requests(&start_with(Policy::default()));
    assert_eq!(
        count(&plain, "/v1/capabilities"),
        1,
        "once per handle: {plain:?}"
    );
    assert_eq!(count(&plain, "/v1/challenges"), 0, "{plain:?}");

    let pow = Arc::new(ProofOfWork::default());
    let hosted = requests(&start_with(Policy {
        admission: pow.clone(),
        ..Policy::default()
    }));
    assert_eq!(count(&hosted, "/v1/capabilities"), 1, "{hosted:?}");
    assert_eq!(count(&hosted, "/v1/challenges"), 2, "{hosted:?}");
    assert_eq!(pow.issued.load(Ordering::SeqCst), 2);
}

/// A server from before the capabilities document: the endpoint is missing,
/// so the SDK must ask for a challenge as it always did.
struct OlderServer {
    http: HttpTransport,
    challenges: AtomicUsize,
}

impl Transport for OlderServer {
    fn send(&self, request: WireRequest<'_>) -> Result<WireResponse, TransportError> {
        match request.path_and_query {
            "/v1/capabilities" => Ok(WireResponse::new(
                404,
                &br#"{"error":"not_found","message":"no such endpoint"}"#[..],
            )),
            "/v1/challenges" => {
                self.challenges.fetch_add(1, Ordering::SeqCst);
                self.http.send(request)
            }
            _ => self.http.send(request),
        }
    }
}

#[test]
fn a_server_without_capabilities_is_asked_for_a_challenge() {
    let pow = Arc::new(ProofOfWork::default());
    let server = start_with(Policy {
        admission: pow.clone(),
        ..Policy::default()
    });
    let older = Arc::new(OlderServer {
        http: ClientBuilder::new(&server.url).build_transport().unwrap(),
        challenges: AtomicUsize::new(0),
    });
    let api = Api::shared(older.clone());
    assert!(Core::create(&api, &NodeKey::generate(), "acme").unwrap());
    assert_eq!(older.challenges.load(Ordering::SeqCst), 1);
    assert_eq!(pow.issued.load(Ordering::SeqCst), 1);
}
