//! The embedded transport (`specs/embedded-backend`, `specs/server-core`):
//! the server's rules in this process, over a data directory a server can
//! also serve. The shared conformance list runs over it and over HTTP, and
//! must come out the same on both.
//!
//! One test re-runs this binary as a child process, to show that opening a
//! directory and using it writes nothing to stdout or stderr and holds no
//! socket.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use galata_vault::client::{Api, Auth, Method, Pre};
use galata_vault::owner::Owner;
use galata_vault::state::MemoryStateStore;
use galata_vault::store::MemoryKeyStore;
use galata_vault::testing::RawVault;
use galata_vault::{ClientBuilder, ConfigFormat, EnvPath, Error, Scope, Vault, code, embedded};
use galata_vault_keys::NodeKey;
use galata_vault_proto::audit::{Actor, AuditAction, AuditResult};
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_server_core::data_dir::{DATABASE, DataDir, JOURNAL_ROOT};
use galata_vault_store::{SqliteStore, StoreConfig};

/// Serve the data directory `dir` over HTTP on loopback, as `gv-server
/// local` serves one: `vault.db`, and the file journal under `journal-root/`.
fn serve(dir: &Path) -> String {
    std::fs::create_dir_all(dir).unwrap();
    let db = dir.join(DATABASE);
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let journal = Arc::new(FileJournal::open(dir.join(JOURNAL_ROOT)).unwrap());
    let config = ServerConfig::for_database(&db);
    let state = AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap();
    let app = router(state);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap()
            .block_on(async move {
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

// ------------------------------------------------------------ conformance

/// What must come out the same over every transport: the version (or
/// count, or status) a step produced, or the code it was refused with.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Outcome {
    Done(u64),
    Refused(String),
}

fn done<T>(result: Result<T, Error>, value: impl FnOnce(T) -> u64) -> Outcome {
    match result {
        Ok(v) => Outcome::Done(value(v)),
        Err(e) => Outcome::Refused(e.code().to_owned()),
    }
}

fn refused(code: &str) -> Outcome {
    Outcome::Refused(code.to_owned())
}

/// One request exactly as the protocol sends it: its status, or the status
/// and code it was refused with.
fn raw(api: &Api, method: Method, path: &str, auth: Auth<'_>, pre: Option<Pre>) -> Outcome {
    let body = (method == Method::Put).then_some(&b"{}"[..]);
    match api.call(method, path, body, auth, pre) {
        Ok(reply) => Outcome::Done(u64::from(reply.status)),
        Err(e) => Outcome::Refused(format!("{} {}", e.status().unwrap_or(0), e.stable_code())),
    }
}

/// An audit row, as far as it can be compared across runs with fresh keys.
type AuditLine = (u64, &'static str, AuditAction, AuditResult, u64);

fn audit(api: &Api, key: &NodeKey) -> Vec<AuditLine> {
    let page = api.audit(Auth::Owner(&key.owner()), 0).unwrap().value;
    page.rows
        .into_iter()
        .map(|r| {
            let actor = match r.actor {
                Actor::Owner => "owner",
                Actor::Token(_) => "token",
                _ => "another kind",
            };
            (r.seq, actor, r.action, r.result, r.version)
        })
        .collect()
}

/// The shared conformance list: creation, token mint, scoped reads and
/// writes, preconditions, refusals, rotation, revocation, a rekey's
/// create-migrate-retire sequence, deletion, and each vault's audit rows.
fn conformance(api: &Api) -> (Vec<(&'static str, Outcome)>, Vec<AuditLine>) {
    let mut steps = Vec::new();
    let mut step = |label, outcome| steps.push((label, outcome));
    let label = "acme/dev";
    let old = NodeKey::generate();
    let secret_path = format!("/v1/secrets/{}", "00".repeat(32));

    step(
        "the capabilities",
        raw(api, Method::Get, "/v1/capabilities", Auth::None, None),
    );
    step(
        "create the vault",
        done(RawVault::create(api, &old, label), u64::from),
    );
    step(
        "create it again",
        done(RawVault::create(api, &old, label), u64::from),
    );
    let owner = RawVault::open_owner(api, &old, label).unwrap();
    let (read, _) = owner.mint(Scope::Read, 0, None).unwrap();
    let (config, _) = owner.mint(Scope::Config, 0, None).unwrap();
    let (admin, _) = owner.mint(Scope::Admin, 0, None).unwrap();
    let (config_id, admin_id) = (config.id(), admin.id());

    step("write A", done(owner.put("A", b"one", Pre::Create), |v| v));
    step(
        "create A again",
        done(owner.put("A", b"x", Pre::Create), |v| v),
    );
    step(
        "update A from version 1",
        done(owner.put("A", b"two", Pre::Update(1)), |v| v),
    );
    step(
        "a lost update from version 1",
        done(owner.put("A", b"x", Pre::Update(1)), |v| v),
    );
    step(
        "write config app",
        done(
            owner.put_config("app", ConfigFormat::Toml, b"k = 1\n", Pre::Create),
            |v| v,
        ),
    );
    step(
        "a read token writes",
        raw(
            api,
            Method::Put,
            &secret_path,
            Auth::Token(&read),
            Some(Pre::Create),
        ),
    );
    step(
        "an unsigned status",
        raw(api, Method::Get, "/v1/vault", Auth::None, None),
    );

    // The SDK refuses this itself; sent anyway, the core refuses and audits it.
    step(
        "a config token reads a secret",
        raw(api, Method::Get, &secret_path, Auth::Token(&config), None),
    );

    let reader = RawVault::open_token(api, read, label).unwrap();
    let configurer = RawVault::open_token(api, config, label).unwrap();
    step(
        "the read token reads A",
        done(reader.get("A", None), |r| r.0),
    );
    step(
        "the config token reads A",
        done(configurer.get("A", None), |r| r.0),
    );
    step(
        "the config token reads app",
        done(configurer.get_config("app", None), |r| r.0),
    );
    step(
        "rotate, revoking the config token",
        done(owner.rotate(&[config_id]), u64::from),
    );
    step(
        "the revoked config token reads app",
        done(configurer.get_config("app", None), |r| r.0),
    );
    reader.refresh().unwrap();
    step(
        "the read token reads A in generation 2",
        done(reader.get("A", None), |r| r.0),
    );
    step(
        "revoke the admin token",
        done(owner.revoke(&admin_id), |r| r.revoked.len() as u64),
    );
    let mut rows = audit(api, &old);

    // A rekey: a new vault, the records moved, the old vault retired.
    let new = NodeKey::generate();
    step(
        "create the new vault",
        done(RawVault::create(api, &new, label), u64::from),
    );
    let new_owner = RawVault::open_owner(api, &new, label).unwrap();
    step(
        "move A",
        done(new_owner.put("A", b"two", Pre::Create), |v| v),
    );
    step(
        "retire the old vault",
        raw(
            api,
            Method::Delete,
            "/v1/vault",
            Auth::Owner(&old.owner()),
            None,
        ),
    );
    step(
        "the old vault's read token after it",
        done(reader.get("A", None), |r| r.0),
    );
    step(
        "the new vault reads A",
        done(new_owner.get("A", None), |r| r.0),
    );
    rows.extend(audit(api, &new));
    (steps, rows)
}

#[test]
fn the_conformance_list_comes_out_the_same_over_http_and_embedded() {
    let http_dir = tempfile::tempdir().unwrap();
    let over_http = conformance(&ClientBuilder::new(&serve(http_dir.path())).build().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let over_embedded = conformance(&Api::new(embedded::open(dir.path().join("data")).unwrap()));

    assert_eq!(over_http.0, over_embedded.0, "the same outcomes");
    assert_eq!(over_http.1, over_embedded.1, "the same audit rows");

    // And they are what the rules say.
    let expected = [
        ("the capabilities", Outcome::Done(200)),
        ("create the vault", Outcome::Done(1)),
        ("create it again", Outcome::Done(0)),
        ("write A", Outcome::Done(1)),
        ("create A again", refused(code::CONFLICT)),
        ("update A from version 1", Outcome::Done(2)),
        ("a lost update from version 1", refused(code::CONFLICT)),
        ("write config app", Outcome::Done(1)),
        ("a read token writes", refused("403 forbidden")),
        ("an unsigned status", refused("401 unauthorized")),
        ("a config token reads a secret", refused("403 forbidden")),
        ("the read token reads A", Outcome::Done(2)),
        ("the config token reads A", refused(code::FORBIDDEN)),
        ("the config token reads app", Outcome::Done(1)),
        ("rotate, revoking the config token", Outcome::Done(2)),
        (
            "the revoked config token reads app",
            refused("unauthorized"),
        ),
        ("the read token reads A in generation 2", Outcome::Done(2)),
        ("revoke the admin token", Outcome::Done(1)),
        ("create the new vault", Outcome::Done(1)),
        ("move A", Outcome::Done(1)),
        ("retire the old vault", Outcome::Done(200)),
        (
            "the old vault's read token after it",
            refused("unauthorized"),
        ),
        ("the new vault reads A", Outcome::Done(1)),
    ];
    let got: Vec<_> = over_embedded
        .0
        .iter()
        .map(|(l, o)| (*l, o.clone()))
        .collect();
    assert_eq!(got, expected);

    // A refusal in-process is audited as it is over HTTP: the config token's
    // read, and the read token's write and both lost preconditions.
    let refusals = |action| {
        over_embedded
            .1
            .iter()
            .filter(|row| row.2 == action && row.3 == AuditResult::Refused)
            .count()
    };
    assert_eq!(
        refusals(AuditAction::SecretRead),
        1,
        "{:?}",
        over_embedded.1
    );
    assert_eq!(refusals(AuditAction::SecretPut), 3, "{:?}", over_embedded.1);
}

// ------------------------------------------------------------ the directory

/// Every file under `dir`, with its bytes.
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(d) = pending.pop() {
        for entry in std::fs::read_dir(&d).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else {
                let bytes = std::fs::read(&path).unwrap();
                files.push((path, bytes));
            }
        }
    }
    files.sort();
    files
}

#[test]
fn a_second_opener_is_refused_and_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let first = Api::new(embedded::open(&dir).unwrap());
    assert!(RawVault::create(&first, &NodeKey::generate(), "acme/dev").unwrap());
    let before = snapshot(&dir);

    let e = embedded::open(&dir).unwrap_err();
    assert_eq!(e.code(), code::DATA_DIR_IN_USE, "{e}");
    assert!(e.to_string().contains("gv-server local"), "{e}");
    // What `gv-server local` takes first: the same lock, refused the same way.
    let e = DataDir::open(&dir).unwrap_err();
    assert_eq!(e.code(), "data_dir_in_use");
    assert_eq!(snapshot(&dir), before, "nothing was changed");

    drop(first);
    embedded::open(&dir).expect("free once the first opener is gone");
}

#[test]
fn a_permissive_directory_is_refused() {
    use std::os::unix::fs::PermissionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("open");
    std::fs::create_dir(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = embedded::open(&dir).unwrap_err();
    assert_eq!(e.code(), code::INVALID_DATA_DIR, "{e}");
    assert!(
        e.to_string().contains("0755") && e.to_string().contains("0700"),
        "{e}"
    );
}

/// Written in-process, closed, and then served over HTTP from the same
/// directory, as `gv-server local` serves it: the secret reads back.
#[test]
fn switching_from_embedded_to_a_server_keeps_the_data() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let token = {
        let api = Api::new(embedded::open(&dir).unwrap());
        let key = NodeKey::generate();
        assert!(RawVault::create(&api, &key, "acme/dev").unwrap());
        let owner = RawVault::open_owner(&api, &key, "acme/dev").unwrap();
        owner
            .put("DATABASE_URL", b"postgres://db", Pre::Create)
            .unwrap();
        let (token, _) = owner.mint(Scope::Read, 0, None).unwrap();
        token.token_string().as_str().to_owned()
    };
    DataDir::open(&dir).expect("closed with its last handle");

    let url = serve(&dir);
    let vault = Vault::new(&token, &url).unwrap();
    assert_eq!(
        vault.secret("DATABASE_URL").unwrap().expose(),
        b"postgres://db"
    );
}

/// A `vault.db` put back from before an acknowledged revocation: opening
/// the directory replays the journal first, and the token stays revoked.
#[test]
fn an_older_copy_of_the_database_is_caught_up_when_opened() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let backup = tmp.path().join("backup.db");
    let key = NodeKey::generate();
    let (token, id) = {
        let api = Api::new(embedded::open(&dir).unwrap());
        assert!(RawVault::create(&api, &key, "acme/dev").unwrap());
        let owner = RawVault::open_owner(&api, &key, "acme/dev").unwrap();
        let (token, _) = owner.mint(Scope::Read, 0, None).unwrap();
        (token.token_string().as_str().to_owned(), token.id())
    };
    // Closed, so the database is one checkpointed file.
    std::fs::copy(dir.join(DATABASE), &backup).unwrap();
    {
        let api = Api::new(embedded::open(&dir).unwrap());
        Vault::with_api(&token, &api).expect("valid before the revocation");
        let owner = RawVault::open_owner(&api, &key, "acme/dev").unwrap();
        assert_eq!(owner.revoke(&id).unwrap().revoked, [id]);
    }
    std::fs::copy(&backup, dir.join(DATABASE)).unwrap();

    let api = Api::new(embedded::open(&dir).unwrap());
    let e = Vault::with_api(&token, &api).unwrap_err();
    assert_eq!(e.code(), "unauthorized", "{e}");
}

/// The owner API, with the embedded transport as its connector: a project
/// and an environment, a secret written and read back, and no server.
#[test]
fn a_project_with_no_server() {
    let tmp = tempfile::tempdir().unwrap();
    let api = Api::new(embedded::open(tmp.path().join("data")).unwrap());
    let connect = api.clone();
    let mut owner = Owner::open(
        Arc::new(MemoryKeyStore::new()),
        Arc::new(MemoryStateStore::new()),
    )
    .unwrap()
    .with_connector(move |_server| Ok(connect.clone()));
    owner
        .begin_init("acme", "http://127.0.0.1:8750")
        .unwrap()
        .confirm_kit_stored()
        .unwrap();
    let path: EnvPath = "acme/dev".parse().unwrap();
    owner.env_add(&path).unwrap();
    let env = owner.environment(&path).unwrap();
    env.set_secret("S", b"v").unwrap();
    let token = env.mint(Scope::Read, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let vault = Vault::with_api(token.expose(), &api).unwrap();
    assert_eq!(vault.secret("S").unwrap().expose(), b"v");
    assert_eq!(vault.expiry().vault_expires_at, None, "nothing expires");
}

// ------------------------------------------------------------ a child

const CHILD: &str = "GV_EMBEDDED_CHILD";

/// This process holds no socket. On Linux its descriptors are read from
/// `/proc`; on macOS `lsof` lists them. Elsewhere there is nothing to ask.
fn assert_no_socket() {
    #[cfg(target_os = "linux")]
    for entry in std::fs::read_dir("/proc/self/fd").unwrap() {
        if let Ok(target) = std::fs::read_link(entry.unwrap().path()) {
            let target = target.to_string_lossy();
            assert!(!target.starts_with("socket:"), "an open socket: {target}");
        }
    }
    #[cfg(target_os = "macos")]
    for kind in ["-i", "-U"] {
        let pid = std::process::id().to_string();
        let Ok(out) = Command::new("lsof").args(["-a", "-p", &pid, kind]).output() else {
            return;
        };
        assert!(
            out.stdout.is_empty(),
            "an open socket:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
    }
}

#[test]
fn child_uses_a_directory() {
    let Ok(dir) = std::env::var(CHILD) else {
        return;
    };
    let api = Api::new(embedded::open(&dir).unwrap());
    let key = NodeKey::generate();
    assert!(RawVault::create(&api, &key, "acme/dev").unwrap());
    let owner = RawVault::open_owner(&api, &key, "acme/dev").unwrap();
    owner.put("S", b"v", Pre::Create).unwrap();
    assert_eq!(owner.get("S", None).unwrap().0, 1);
    assert_no_socket();
}

#[test]
fn a_child_using_a_directory_is_silent_and_holds_no_socket() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("data");
    let out = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_uses_a_directory",
            "--test-threads=1",
            "--nocapture",
        ])
        .env(CHILD, &dir)
        .env_remove("RUST_LOG")
        .output()
        .unwrap();
    let (stdout, stderr) = (
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    assert!(out.status.success(), "{stdout}{stderr}");
    assert!(stderr.is_empty(), "stderr: {stderr}");
    // Only the test harness's own lines.
    for line in stdout.lines() {
        assert!(
            line.is_empty() || line.starts_with("running ") || line.starts_with("test "),
            "unexpected output: {line:?}"
        );
    }
    assert!(dir.join(DATABASE).exists(), "the child did its work");
}
