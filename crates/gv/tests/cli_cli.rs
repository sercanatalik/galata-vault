//! The real `gv` binary against a real server, in-process on loopback.
//!
//! Every run uses a temporary GV_HOME and GV_CREDENTIAL_STORE=file, with the
//! environment cleared: these tests never touch the OS keychain, the user's
//! configuration, or a proxy. A spy layer in front of the router records
//! every request and can let another writer win a race.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use galata_vault::backend::{
    Ctx, Precondition, RecordKind, RecordWrite, SqliteStore, Store, StoreConfig,
};
use galata_vault::keys::{NodeKey, TokenKeys};
use galata_vault::proto::api::Limits;
use galata_vault::proto::audit::Actor;
use galata_vault::proto::children::ChildMode;
use galata_vault::proto::ids::VaultId;
use galata_vault::proto::path::Segment;
use galata_vault::server::journal::FileJournal;
use galata_vault::server::{AppState, Core, Policy, ServerConfig, SystemClock, router};

#[path = "cli_common/mod.rs"]
mod common;

#[derive(Debug, Clone)]
struct Seen {
    method: String,
    path: String,
    /// The vault a GV-Sig request was signed for.
    vault: Option<String>,
}

/// Runs just before the next conditional secret update reaches the server.
type Hook = Box<dyn FnOnce() + Send>;

#[derive(Clone)]
struct Spy {
    seen: Arc<Mutex<Vec<Seen>>>,
    /// Let another writer win the next conditional secret update.
    race: Arc<Mutex<Option<Hook>>>,
    store: Arc<SqliteStore>,
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

async fn spy(State(spy): State<Spy>, req: Request, next: Next) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let vault = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .filter(|v| v.starts_with("GV-Sig "))
        .and_then(|v| {
            v.split(',')
                .find_map(|p| p.trim().strip_prefix("vault=").map(str::to_owned))
        });
    spy.seen.lock().unwrap().push(Seen {
        method: method.clone(),
        path: path.clone(),
        vault,
    });

    if method == "PUT" && path.starts_with("/v1/secrets/") && req.headers().contains_key("if-match")
    {
        let hook = spy.race.lock().unwrap().take();
        if let Some(hook) = hook {
            // Another writer updates the same secret first.
            tokio::task::spawn_blocking(hook).await.unwrap();
        }
    }
    next.run(req).await
}

struct Server {
    url: String,
    spy: Spy,
    /// The server's database, WAL and journal.
    dir: tempfile::TempDir,
}

impl Server {
    fn start() -> Server {
        Server::start_with(|_| {})
    }

    /// A server whose core runs the default policy, tweaked: an expiring
    /// server, say, which no default-build configuration can ask for.
    fn start_with(tweak: impl FnOnce(&mut Policy)) -> Server {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
        let config = ServerConfig::for_database(&db);
        let mut policy = Policy::default();
        tweak(&mut policy);
        let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
        let core = Core::open(store.clone(), journal, policy, Arc::new(SystemClock)).unwrap();
        let state = AppState::from_core(core, config);
        let spy_state = Spy {
            seen: Arc::default(),
            race: Arc::default(),
            store,
        };
        let app = router(state).layer(middleware::from_fn_with_state(spy_state.clone(), spy));
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
            spy: spy_state,
            dir,
        }
    }

    fn data_dir(&self) -> &Path {
        self.dir.path()
    }

    fn clear_seen(&self) {
        self.spy.seen.lock().unwrap().clear();
    }

    fn seen(&self) -> Vec<Seen> {
        self.spy.seen.lock().unwrap().clone()
    }

    fn store(&self) -> &SqliteStore {
        &self.spy.store
    }
}

/// One user's machine: a home directory and a working directory.
struct Gv {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    server: String,
}

impl Gv {
    fn new(server: &Server) -> Gv {
        Gv {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
            server: server.url.clone(),
        }
    }

    fn run_with(&self, args: &[&str], stdin: &[u8], envs: &[(&str, &str)]) -> Output {
        common::gv(self.home.path(), self.work.path(), args, stdin, envs)
    }

    fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
        self.run_with(args, stdin, &[])
    }

    fn ok(&self, args: &[&str], stdin: &[u8]) -> String {
        let out = self.run(args, stdin);
        assert!(
            out.status.success(),
            "gv {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Run, expect failure, return stderr.
    fn fail(&self, args: &[&str], stdin: &[u8]) -> String {
        let out = self.run(args, stdin);
        assert!(
            !out.status.success(),
            "gv {args:?} should have failed:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8(out.stderr).unwrap()
    }

    fn init(&self, project: &str) {
        self.ok(&["init", project, "--server", &self.server], b"saved\n");
    }

    fn set(&self, env: &str, name: &str, value: &str) {
        self.ok(&["set", name, "--env", env], value.as_bytes());
    }

    fn get(&self, env: &str, name: &str) -> String {
        self.ok(&["get", name, "--env", env], b"")
    }

    fn file(&self, name: &str) -> PathBuf {
        self.work.path().join(name)
    }

    fn home_file(&self, name: &str) -> PathBuf {
        self.home.path().join(name)
    }

    fn credential_names(&self) -> Vec<String> {
        let text = std::fs::read_to_string(self.home_file("credentials.toml")).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        table["credentials"]
            .as_table()
            .unwrap()
            .keys()
            .cloned()
            .collect()
    }

    /// The key this machine holds for `path`.
    fn held_key(&self, path: &str) -> NodeKey {
        let text = std::fs::read_to_string(self.home_file("credentials.toml")).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        NodeKey::parse(
            table["credentials"][&format!("node:{path}")]
                .as_str()
                .unwrap(),
        )
        .unwrap()
    }

    fn state(&self) -> String {
        std::fs::read_to_string(self.home_file("state.toml")).unwrap()
    }

    fn vault_id(&self, path: &str) -> VaultId {
        let text = std::fs::read_to_string(self.home_file("config.toml")).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        let project = path.split('/').next().unwrap();
        let id = table["projects"][project]["tree"][path]["vault_id"]
            .as_str()
            .unwrap();
        VaultId::from_hex(id).unwrap()
    }
}

/// `GET /v1/tokens/self`, signed with the token, as its holder could.
fn token_self(server: &Server, keys: &TokenKeys) -> galata_vault::proto::api::TokenSelf {
    let pq = "/v1/tokens/self";
    let auth = keys
        .sign_request(
            &galata_vault::proto::sig::SignedRequest::new("GET", pq, b""),
            now(),
        )
        .to_header_value();
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = agent
        .get(format!("{}{pq}", server.url))
        .header("authorization", auth)
        .call()
        .unwrap();
    serde_json::from_slice(&resp.body_mut().read_to_vec().unwrap()).unwrap()
}

fn mode(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().permissions().mode() & 0o777
}

/// A project with `dev` and `prod`, and one secret in each.
fn project(server: &Server) -> Gv {
    let gv = Gv::new(server);
    gv.init("acme");
    gv.ok(&["env", "add", "acme/dev"], b"");
    gv.ok(&["env", "add", "acme/prod"], b"");
    gv.set("acme/dev", "DEV_ONLY", "d1");
    gv.set("acme/prod", "PROD_ONLY", "p1");
    gv
}

#[test]
fn init_writes_a_private_kit_and_keeps_only_the_project_key() {
    let server = Server::start();
    let gv = project(&server);

    let kit = gv.file("acme-recovery.gvkit");
    assert_eq!(mode(&kit), 0o600);
    assert!(std::fs::read_to_string(&kit).unwrap().contains("gvk1_"));
    let config = std::fs::read_to_string(gv.home_file("config.toml")).unwrap();
    assert!(!config.contains("gvk1_"), "configuration holds no secret");
    assert!(config.contains(&server.url), "the server is pinned");

    // Worked in several environments: still only the project key is stored.
    gv.ok(&["env", "add", "acme/staging"], b"");
    gv.ok(&["env", "add", "acme/prod/eu"], b"");
    gv.set("acme/prod/eu", "X", "1");
    gv.set("acme/staging", "X", "1");
    assert_eq!(gv.credential_names(), ["node:acme"]);

    let tree = gv.ok(&["env", "ls", "acme"], b"");
    for p in [
        "acme",
        "acme/dev",
        "acme/prod",
        "acme/prod/eu",
        "acme/staging",
    ] {
        assert!(
            tree.lines().any(|l| l.split_whitespace().next() == Some(p)),
            "{tree}"
        );
    }
}

#[test]
fn init_without_confirmation_creates_nothing() {
    let server = Server::start();
    let gv = Gv::new(&server);
    let err = gv.fail(&["init", "acme", "--server", &server.url], b"no\n");
    assert!(err.contains("not confirmed"), "{err}");
    assert!(!gv.file("acme-recovery.gvkit").exists());
    assert!(server.seen().is_empty(), "no request before confirmation");
}

#[test]
fn set_get_ls_history_rm() {
    let server = Server::start();
    let gv = project(&server);
    gv.set("acme/dev", "API_KEY", "s3cret");
    assert_eq!(gv.get("acme/dev", "API_KEY"), "s3cret");
    gv.set("acme/dev", "API_KEY", "v2\nwith newline\n");
    assert_eq!(gv.get("acme/dev", "API_KEY"), "v2\nwith newline\n");
    assert_eq!(
        gv.ok(
            &["get", "API_KEY", "--version", "1", "--env", "acme/dev"],
            b""
        ),
        "s3cret"
    );

    let ls = gv.ok(&["ls", "--env", "acme/dev"], b"");
    assert!(ls.contains("API_KEY") && ls.contains("DEV_ONLY"), "{ls}");
    assert!(!ls.contains("gv:children"), "system records are hidden");
    let history = gv.ok(&["history", "API_KEY", "--env", "acme/dev"], b"");
    assert!(
        history.starts_with("v1") && history.contains("\nv2"),
        "{history}"
    );

    gv.ok(&["rm", "API_KEY", "--env", "acme/dev"], b"");
    gv.fail(&["get", "API_KEY", "--env", "acme/dev"], b"");
    assert!(!gv.ok(&["ls", "--env", "acme/dev"], b"").contains("API_KEY"));
    assert!(
        gv.ok(&["ls", "--all", "--env", "acme/dev"], b"")
            .contains("(deleted)")
    );
    // A deleted name can be set again.
    gv.set("acme/dev", "API_KEY", "back");
    assert_eq!(gv.get("acme/dev", "API_KEY"), "back");

    let err = gv.fail(&["set", "EMPTY", "--env", "acme/dev"], b"");
    assert!(err.contains("empty"), "{err}");
}

#[test]
fn reserved_names_and_lost_races_are_refused() {
    let server = Server::start();
    let gv = project(&server);
    for cmd in ["set", "rm"] {
        let err = gv.fail(&[cmd, "gv:children", "--env", "acme/dev"], b"x");
        assert!(err.contains("\"gv:\""), "{err}");
    }

    gv.set("acme/dev", "RACED", "mine-1");
    let (home, work) = (gv.home.path().to_owned(), gv.work.path().to_owned());
    *server.spy.race.lock().unwrap() = Some(Box::new(move || {
        let out = common::gv(
            &home,
            &work,
            &["set", "RACED", "--env", "acme/dev"],
            b"theirs",
            &[],
        );
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }));
    let err = gv.fail(&["set", "RACED", "--env", "acme/dev"], b"mine-2");
    assert!(
        err.contains("changed") && err.contains("version 1") && err.contains("version 2"),
        "{err}"
    );
    assert_eq!(
        gv.get("acme/dev", "RACED"),
        "theirs",
        "nothing was overwritten"
    );
}

#[test]
fn run_injects_and_preserves_exit_status_and_export_is_private() {
    let server = Server::start();
    let gv = project(&server);
    gv.set("acme/dev", "SPACED", "x y");
    let out = gv.run(
        &[
            "run",
            "--env",
            "acme/dev",
            "--",
            "sh",
            "-c",
            "test \"$DEV_ONLY\" = d1 && test \"$SPACED\" = 'x y' && test -z \"$PROD_ONLY\" && exit 3",
        ],
        b"",
    );
    assert_eq!(
        out.status.code(),
        Some(3),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = gv.run(
        &[
            "run",
            "--only",
            "SPACED",
            "--env",
            "acme/dev",
            "--",
            "sh",
            "-c",
            "test -z \"$DEV_ONLY\"",
        ],
        b"",
    );
    assert!(out.status.success());

    gv.ok(
        &[
            "export", "--format", "dotenv", "--out", ".env", "--env", "acme/dev",
        ],
        b"",
    );
    let env_file = gv.file(".env");
    assert_eq!(mode(&env_file), 0o600);
    let text = std::fs::read_to_string(&env_file).unwrap();
    assert!(
        text.contains("DEV_ONLY=\"d1\"") && text.contains("SPACED=\"x y\""),
        "{text}"
    );
    gv.fail(
        &[
            "export", "--format", "dotenv", "--out", ".env", "--env", "acme/dev",
        ],
        b"",
    );
    gv.ok(
        &[
            "export", "--format", "dotenv", "--out", ".env", "--force", "--env", "acme/dev",
        ],
        b"",
    );

    let json: serde_json::Value =
        serde_json::from_str(&gv.ok(&["export", "--format", "json", "--env", "acme/dev"], b""))
            .unwrap();
    assert_eq!(json["SPACED"], "x y");
    assert!(json.get("gv:children").is_none());
    let yaml = gv.ok(&["export", "--format", "yaml", "--env", "acme/dev"], b"");
    assert!(yaml.contains("\"SPACED\": \"x y\""), "{yaml}");
}

#[test]
fn typos_are_refused_before_any_request() {
    let server = Server::start();
    let gv = project(&server);
    server.clear_seen();
    let err = gv.fail(&["get", "DEV_ONLY", "--env", "acme/prdo"], b"");
    assert!(
        err.contains("acme/prod"),
        "suggests the closest path: {err}"
    );
    let err = gv.fail(&["get", "DEV_ONLY", "--env", "acmee/dev"], b"");
    assert!(err.contains("unknown project"), "{err}");
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

#[test]
fn environment_selection_and_dir_files() {
    let server = Server::start();
    let gv = project(&server);
    std::fs::write(gv.file(".gv.toml"), "env = \"acme/dev\"\n").unwrap();
    std::fs::create_dir(gv.file("sub")).unwrap();
    assert_eq!(gv.ok(&["get", "DEV_ONLY"], b""), "d1");

    // GV_ENV beats the file; --env beats GV_ENV.
    let prod = gv.run_with(&["get", "PROD_ONLY"], b"", &[("GV_ENV", "acme/prod")]);
    assert_eq!(String::from_utf8_lossy(&prod.stdout), "p1");
    let dev = gv.run_with(
        &["get", "DEV_ONLY", "--env", "acme/dev"],
        b"",
        &[("GV_ENV", "acme/prod")],
    );
    assert_eq!(String::from_utf8_lossy(&dev.stdout), "d1");

    std::fs::write(
        gv.file(".gv.toml"),
        "env = \"acme/dev\"\nserver = \"https://evil.example\"\n",
    )
    .unwrap();
    server.clear_seen();
    let err = gv.fail(&["get", "DEV_ONLY"], b"");
    assert!(err.contains("`server`"), "{err}");
    assert!(server.seen().is_empty());
}

#[test]
fn tokens_are_scoped_and_token_mode_needs_no_config() {
    let server = Server::start();
    let gv = project(&server);
    let token = gv
        .ok(
            &["token", "mint", "--scope", "read", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();
    assert!(token.starts_with("gvt1_"));

    // A machine with no configuration at all.
    let ci = Gv::new(&server);
    let tm = [
        ("GV_TOKEN", token.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];
    let out = ci.run_with(&["get", "PROD_ONLY"], b"", &tm);
    assert_eq!(
        String::from_utf8_lossy(&out.stdout),
        "p1",
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let out = ci.run_with(&["get", "DEV_ONLY"], b"", &tm);
    assert!(!out.status.success(), "the token reads only acme/prod");
    let out = ci.run_with(
        &["run", "--", "sh", "-c", "test \"$PROD_ONLY\" = p1"],
        b"",
        &tm,
    );
    assert!(out.status.success());
    let out = ci.run_with(&["set", "X"], b"v", &tm);
    assert!(!out.status.success(), "a read token cannot write");
    for stream in [&out.stdout, &out.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(&token),
            "the token is never printed"
        );
    }

    // One changed checksum character: always a different string.
    let swap = if token.ends_with('x') { 'y' } else { 'x' };
    let bad = format!("{}{swap}", &token[..token.len() - 1]);
    let out = ci.run_with(
        &["get", "PROD_ONLY"],
        b"",
        &[("GV_TOKEN", &bad), ("GV_SERVER", &server.url)],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("checksum") && !err.contains(&bad[5..20]),
        "{err}"
    );

    // An append token writes but cannot read.
    let append = gv
        .ok(
            &["token", "mint", "--scope", "append", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();
    let am = [
        ("GV_TOKEN", append.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];
    assert!(
        ci.run_with(&["set", "FROM_CI"], b"c1", &am)
            .status
            .success()
    );
    assert!(!ci.run_with(&["get", "FROM_CI"], b"", &am).status.success());
    assert_eq!(gv.get("acme/prod", "FROM_CI"), "c1");

    // Revoke without --rotate: confirmed, with the forward-only warning.
    let listed = gv.ok(&["token", "ls", "--env", "acme/prod"], b"");
    let read_id = listed
        .lines()
        .find(|l| l.contains("read"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned();
    let out = gv.run(&["token", "revoke", &read_id, "--env", "acme/prod"], b"");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        out.status.success() && err.contains("forward-only") && err.contains("rotate"),
        "{err}"
    );
    assert!(
        !ci.run_with(&["get", "PROD_ONLY"], b"", &tm)
            .status
            .success()
    );

    // Revoke with --rotate: one step, and the owner still reads everything.
    let second = gv
        .ok(
            &["token", "mint", "--scope", "read", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();
    let second_id = gv
        .ok(&["token", "ls", "--env", "acme/prod"], b"")
        .lines()
        .find(|l| l.contains("read"))
        .and_then(|l| l.split_whitespace().next())
        .unwrap()
        .to_owned();
    let out = gv.run(
        &[
            "token",
            "revoke",
            &second_id,
            "--rotate",
            "--env",
            "acme/prod",
        ],
        b"",
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("generation 2"));
    let sm = [
        ("GV_TOKEN", second.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];
    assert!(
        !ci.run_with(&["get", "PROD_ONLY"], b"", &sm)
            .status
            .success()
    );
    assert_eq!(gv.get("acme/prod", "PROD_ONLY"), "p1");
    assert_eq!(gv.get("acme/prod", "FROM_CI"), "c1");
    // The surviving append token still works after the rotation.
    assert!(
        ci.run_with(&["set", "FROM_CI"], b"c2", &am)
            .status
            .success()
    );
    assert_eq!(gv.get("acme/prod", "FROM_CI"), "c2");
}

#[test]
fn delegation_and_recovery_rediscover_from_a_key_alone() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/dev/eu"], b"");
    gv.set("acme/dev/eu", "EU", "e1");

    let out = gv.run(
        &["key", "export", "acme/dev", "--yes", "--out", "dev.gvkit"],
        b"",
    );
    assert!(out.status.success());
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("OWN acme/dev and everything beneath it")
    );
    let kit = gv.file("dev.gvkit");
    assert_eq!(mode(&kit), 0o600);

    // A delegate: dev and below, nothing above.
    let delegate = Gv::new(&server);
    delegate.ok(&["key", "import", kit.to_str().unwrap()], b"");
    assert_eq!(delegate.get("acme/dev", "DEV_ONLY"), "d1");
    assert_eq!(delegate.get("acme/dev/eu", "EU"), "e1");
    let err = delegate.fail(&["get", "PROD_ONLY", "--env", "acme/prod"], b"");
    assert!(err.contains("unknown environment"), "{err}");

    // A new machine with only the recovery kit.
    let fresh = Gv::new(&server);
    let recovery = gv.file("acme-recovery.gvkit");
    fresh.ok(&["recover", recovery.to_str().unwrap()], b"");
    let tree = fresh.ok(&["env", "ls"], b"");
    for p in ["acme/dev", "acme/dev/eu", "acme/prod"] {
        assert!(tree.contains(p), "{tree}");
    }
    assert_eq!(fresh.get("acme/prod", "PROD_ONLY"), "p1");
    let err = fresh.fail(&["recover", kit.to_str().unwrap()], b"");
    assert!(err.contains("delegation kit"), "{err}");
}

/// `gv rekey` re-roots: a fresh random key, fresh vaults holding
/// copies of every record, and the old vaults deleted with every token in
/// them. Nothing held before reaches the new subtree.
#[test]
fn a_rekey_leaves_the_old_subtree_unreachable() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/dev/eu"], b"");
    gv.set("acme/dev/eu", "EU", "e1");
    gv.set("acme/dev", "DEV_ONLY", "d2");
    let token = gv
        .ok(
            &["token", "mint", "--scope", "read", "--env", "acme/dev"],
            b"",
        )
        .trim()
        .to_owned();
    let token_id = TokenKeys::parse(&token).unwrap().id();
    let (old_dev, old_eu) = (gv.vault_id("acme/dev"), gv.vault_id("acme/dev/eu"));

    let out = gv.run(&["rekey", "acme/dev", "--kit", "dev-new.gvkit"], b"");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{err}");
    assert!(
        err.contains(&token_id.to_hex()) && err.contains("mint replacements"),
        "the tokens that died are listed: {err}"
    );
    assert_eq!(mode(&gv.file("dev-new.gvkit")), 0o600);
    let (new_dev, new_eu) = (gv.vault_id("acme/dev"), gv.vault_id("acme/dev/eu"));
    assert!(new_dev != old_dev && new_eu != old_eu);
    assert!(!gv.state().contains("[rekey]"), "the plan is done");

    // The old vaults are gone, and every token with them.
    for old in [old_dev, old_eu] {
        assert!(server.store().vault_by_id(&old).unwrap().is_none());
    }
    assert!(server.store().token_by_id(&token_id).unwrap().is_none());
    let out = Gv::new(&server).run_with(
        &["get", "DEV_ONLY"],
        b"",
        &[("GV_TOKEN", &token), ("GV_SERVER", &server.url)],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        !out.status.success() && err.contains("not accepted"),
        "{err}"
    );

    // The project key derives only the old subtree: the new key is random.
    let dev = gv.held_key("acme").child(&Segment::new("dev").unwrap());
    assert_eq!(dev.owner().vault_id(), old_dev);
    assert_eq!(
        dev.child(&Segment::new("eu").unwrap()).owner().vault_id(),
        old_eu
    );

    // Every record came along, history included.
    assert_eq!(gv.get("acme/dev", "DEV_ONLY"), "d2");
    assert_eq!(
        gv.ok(
            &["get", "DEV_ONLY", "--version", "1", "--env", "acme/dev"],
            b""
        ),
        "d1"
    );
    assert_eq!(gv.get("acme/dev/eu", "EU"), "e1");
    assert_eq!(
        gv.credential_names(),
        ["node:acme", "node:acme/dev"],
        "a re-rooted key is random, not derived, so the rekeying machine keeps it"
    );
    assert!(
        gv.ok(&["env", "ls", "acme"], b"")
            .contains("acme/dev  (key held, rekeyed)")
    );

    // The project key still reaches the subtree, through acme's owner-only
    // children record.
    let fresh = Gv::new(&server);
    fresh.ok(
        &["recover", gv.file("acme-recovery.gvkit").to_str().unwrap()],
        b"",
    );
    assert_eq!(fresh.get("acme/dev", "DEV_ONLY"), "d2");
    assert_eq!(fresh.get("acme/dev/eu", "EU"), "e1");

    // A delegate who rekeys detaches the subtree from its parent's owner,
    // and the old delegation kit opens nothing any more.
    let delegate = Gv::new(&server);
    gv.ok(
        &["key", "export", "acme/prod", "--yes", "--out", "prod.gvkit"],
        b"",
    );
    let prod_kit = gv.file("prod.gvkit");
    delegate.ok(&["key", "import", prod_kit.to_str().unwrap()], b"");
    let out = delegate.run(&["rekey", "acme/prod", "--kit", "mine.gvkit"], b"");
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("detached"),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(delegate.get("acme/prod", "PROD_ONLY"), "p1");
    gv.fail(&["get", "PROD_ONLY", "--env", "acme/prod"], b"");
    Gv::new(&server).fail(&["key", "import", prod_kit.to_str().unwrap()], b"");
}

/// Every step of a rekey is recorded before the next: an interrupted one is
/// finished by `--resume`, or undone by `--abort` until its parent points at
/// the new key.
#[test]
fn an_interrupted_rekey_resumes_or_aborts() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/dev/eu"], b"");
    gv.set("acme/dev/eu", "EU", "e1");
    let old = gv.vault_id("acme/dev");
    let interrupt = |step: &str, kit: &str| {
        let out = gv.run_with(
            &["rekey", "acme/dev", "--kit", kit],
            b"",
            &[("GV_TEST_REKEY_INTERRUPT", step)],
        );
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(!out.status.success() && err.contains("--resume"), "{err}");
    };
    let planned = || -> Vec<VaultId> {
        let state: toml::Table = toml::from_str(&gv.state()).unwrap();
        state["rekey"]["new_ids"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| VaultId::from_hex(v.as_str().unwrap()).unwrap())
            .collect()
    };

    // Stopped once the new vaults exist: --abort deletes them and the kit.
    interrupt("created", "a.gvkit");
    assert!(gv.file("a.gvkit").exists());
    let new = planned();
    assert_eq!(new.len(), 2);
    for id in &new {
        assert!(server.store().vault_by_id(id).unwrap().is_some());
    }
    let err = gv.fail(&["rekey", "acme/prod"], b"");
    assert!(err.contains("in progress"), "{err}");
    gv.ok(&["rekey", "--abort"], b"");
    assert!(!gv.file("a.gvkit").exists());
    for id in &new {
        assert!(server.store().vault_by_id(id).unwrap().is_none());
    }
    assert_eq!(gv.vault_id("acme/dev"), old);
    assert_eq!(gv.get("acme/dev/eu", "EU"), "e1");
    assert_eq!(gv.credential_names(), ["node:acme"]);

    // Stopped once the parent points at the new key: only forward.
    interrupt("linked", "b.gvkit");
    let new = planned();
    let err = gv.fail(&["rekey", "--abort"], b"");
    assert!(err.contains("gv rekey --resume"), "{err}");
    gv.ok(&["rekey", "--resume"], b"");
    assert_eq!(gv.vault_id("acme/dev"), new[0]);
    assert!(server.store().vault_by_id(&old).unwrap().is_none());
    assert_eq!(gv.get("acme/dev", "DEV_ONLY"), "d1");
    assert_eq!(gv.get("acme/dev/eu", "EU"), "e1");
    let err = gv.fail(&["rekey", "--resume"], b"");
    assert!(err.contains("no rekey is in progress"), "{err}");
}

#[test]
fn removing_a_non_empty_environment_needs_recursive() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/prod/eu"], b"");
    let err = gv.fail(&["env", "rm", "acme/prod"], b"");
    assert!(
        err.contains("--recursive") && err.contains("acme/prod/eu"),
        "{err}"
    );
    let prod_id = gv.vault_id("acme/prod");
    gv.ok(&["env", "rm", "acme/prod", "--recursive"], b"");
    assert!(server.store().vault_by_id(&prod_id).unwrap().is_none());
    let tree = gv.ok(&["env", "ls", "acme"], b"");
    assert!(!tree.contains("acme/prod"), "{tree}");
    assert!(tree.contains("acme/dev"));
}

#[test]
fn an_expired_root_is_repaired_at_the_same_vault_id() {
    let server = Server::start();
    let gv = project(&server);
    let root = gv.vault_id("acme");
    let pk = server.store().vault_by_id(&root).unwrap().unwrap().pk;
    // What the expiry sweep does to an idle vault.
    server
        .store()
        .delete_vault(pk, now(), &mut |_| Ok(()))
        .unwrap();

    // Environments stay usable: their keys are derived locally.
    assert_eq!(gv.get("acme/dev", "DEV_ONLY"), "d1");
    let err = gv.fail(&["env", "rm", "acme"], b"");
    assert!(err.contains("gv env repair acme"), "{err}");

    gv.ok(&["env", "repair", "acme"], b"");
    assert!(server.store().vault_by_id(&root).unwrap().is_some());
    let fresh = Gv::new(&server);
    fresh.ok(
        &["recover", gv.file("acme-recovery.gvkit").to_str().unwrap()],
        b"",
    );
    assert_eq!(fresh.get("acme/prod", "PROD_ONLY"), "p1");
}

#[test]
fn ancestors_are_kept_alive_at_most_daily() {
    // Only a server that expires vaults gets keep-alives.
    let server = Server::start_with(|p| p.idle_expiry_days = Some(90));
    let gv = project(&server);
    let root = gv.vault_id("acme").to_hex();
    let root_touches = |seen: Vec<Seen>| {
        seen.iter()
            .filter(|s| {
                s.method == "GET"
                    && s.path == "/v1/vault"
                    && s.vault.as_deref() == Some(root.as_str())
            })
            .count()
    };

    // A day since the last touch (state forgotten): acme is touched.
    std::fs::remove_file(gv.home_file("state.toml")).unwrap();
    server.clear_seen();
    gv.ok(&["ls", "--env", "acme/dev"], b"");
    assert_eq!(root_touches(server.seen()), 1);

    server.clear_seen();
    gv.ok(&["ls", "--env", "acme/dev"], b"");
    gv.ok(&["ls", "--env", "acme/prod"], b"");
    assert_eq!(root_touches(server.seen()), 0, "not again within 24 hours");
}

#[test]
fn no_keep_alive_on_a_server_that_announces_no_expiry() {
    let server = Server::start_with(|p| p.idle_expiry_days = None);
    let gv = project(&server);
    let root = gv.vault_id("acme").to_hex();
    let root_touches = |seen: Vec<Seen>| {
        seen.iter()
            .filter(|s| {
                s.method == "GET"
                    && s.path == "/v1/vault"
                    && s.vault.as_deref() == Some(root.as_str())
            })
            .count()
    };

    // Forget when acme was last touched, as a day passing would.
    let state_path = gv.home_file("state.toml");
    let mut state: toml::Table =
        toml::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
    state.remove("touched");
    std::fs::write(&state_path, toml::to_string(&state).unwrap()).unwrap();
    server.clear_seen();
    gv.ok(&["ls", "--env", "acme/dev"], b"");
    gv.ok(&["ls", "--env", "acme/prod"], b"");
    assert_eq!(root_touches(server.seen()), 0, "acme cannot expire");

    // With every record forgotten, the environment's own status says so.
    std::fs::remove_file(&state_path).unwrap();
    server.clear_seen();
    gv.ok(&["ls", "--env", "acme/dev"], b"");
    assert_eq!(root_touches(server.seen()), 0);
    let out = gv.ok(&["status", "--env", "acme/dev"], b"");
    assert!(out.contains("expires      never"), "{out}");
}

#[test]
fn an_expiry_within_two_weeks_is_warned_about_by_path() {
    let server = Server::start_with(|p| p.idle_expiry_days = Some(10));
    let gv = project(&server);
    let out = gv.run(&["ls", "--env", "acme/dev"], b"");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("warning: acme/dev expires"), "{err}");
}

#[test]
fn audit_verifies_and_detects_a_rollback() {
    let server = Server::start();
    let gv = project(&server);
    gv.set("acme/dev", "API_KEY", "a");
    let out = gv.run(&["audit", "--env", "acme/dev"], b"");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rows = String::from_utf8_lossy(&out.stdout);
    assert!(
        rows.contains("vault_create") && rows.contains("secret_put") && rows.contains("API_KEY"),
        "{rows}"
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("verified"));
    let state = std::fs::read_to_string(gv.home_file("state.toml")).unwrap();
    assert!(state.contains("[audit"), "{state}");
    gv.ok(&["audit", "--env", "acme/dev"], b"");

    // This client verified further than the server now claims.
    let rolled = regex_free_bump_seq(&std::fs::read_to_string(gv.home_file("state.toml")).unwrap());
    std::fs::write(gv.home_file("state.toml"), rolled).unwrap();
    let err = gv.fail(&["audit", "--env", "acme/dev"], b"");
    assert!(err.contains("FAILED") && err.contains("rollback"), "{err}");
}

/// Set every stored audit seq to 100000.
fn regex_free_bump_seq(state: &str) -> String {
    state
        .lines()
        .map(|l| {
            if l.trim_start().starts_with("seq =") {
                "seq = 100000".to_owned()
            } else if let Some(i) = l.find("seq = ") {
                let rest = &l[i + 6..];
                let end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                format!("{}seq = 100000{}", &l[..i], &rest[end..])
            } else {
                l.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn a_permissive_credentials_file_is_refused() {
    let server = Server::start();
    let gv = project(&server);
    let creds = gv.home_file("credentials.toml");
    std::fs::set_permissions(&creds, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = gv.fail(&["get", "DEV_ONLY", "--env", "acme/dev"], b"");
    assert!(
        err.contains("credentials.toml") && err.contains("0600"),
        "{err}"
    );
}

#[test]
fn a_tampered_record_names_path_version_and_kind_only() {
    let server = Server::start();
    let gv = project(&server);
    gv.set("acme/dev", "API_KEY", "super-secret-value");
    let pk = server
        .store()
        .vault_by_id(&gv.vault_id("acme/dev"))
        .unwrap()
        .unwrap()
        .pk;
    // A server that swaps in garbage: every head gets a bogus next version,
    // under a signature made for another one.
    for head in server
        .store()
        .list_records(pk, RecordKind::Secret, None, 100)
        .unwrap()
    {
        let row = server
            .store()
            .latest_record(pk, RecordKind::Secret, &head.name_hmac)
            .unwrap()
            .unwrap();
        server
            .store()
            .put_record(
                pk,
                RecordKind::Secret,
                &head.name_hmac,
                Precondition::IfMatch(row.version),
                &RecordWrite {
                    name_ct: row.name_ct,
                    value_ct: Some(
                        b"age-encryption.org/v1\n-> X25519 AAAA\nBBBB\n--- CCCC\n".to_vec(),
                    ),
                    generation: row.generation,
                    version: row.version + 1,
                    written_at: now(),
                    sig: row.sig,
                },
                Ctx {
                    actor: Actor::Owner,
                    now: now(),
                },
                &Limits::default(),
            )
            .unwrap();
    }
    let err = gv.fail(&["get", "API_KEY", "--env", "acme/dev"], b"");
    assert!(
        err.contains("acme/dev")
            && err.contains("version 2 of secret")
            && err.contains("does not verify"),
        "{err}"
    );
    assert!(!err.contains("super-secret-value") && !err.contains("API_KEY"));
    let key = gv.held_key("acme").encode();
    assert!(!err.contains(&key[5..]), "no key bytes in the error");
}

#[test]
fn mcp_setup_maps_every_environment_to_its_own_meta_token() {
    use galata_vault::proto::api::Scope;
    use galata_vault::proto::mcp::McpConfig;

    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/staging"], b"");
    let read = |gv: &Gv| -> Vec<(String, TokenKeys)> {
        let file = gv.home_file("mcp.toml");
        assert_eq!(mode(&file), 0o600);
        let config: McpConfig = toml::from_str(&std::fs::read_to_string(&file).unwrap()).unwrap();
        config
            .env
            .iter()
            .map(|e| (e.path.to_string(), TokenKeys::parse(&e.token).unwrap()))
            .collect()
    };

    let out = gv.run(&["mcp", "setup", "acme"], b"");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    for stream in [&out.stdout, &out.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains("gvt1_"),
            "tokens go only to the file"
        );
    }
    let first = read(&gv);
    let paths: Vec<&str> = first.iter().map(|(p, _)| p.as_str()).collect();
    assert_eq!(paths, ["acme", "acme/dev", "acme/prod", "acme/staging"]);
    let ids: std::collections::BTreeSet<_> = first.iter().map(|(_, t)| t.id()).collect();
    assert_eq!(ids.len(), 4, "four distinct tokens");
    for (path, t) in &first {
        let row = server.store().token_by_id(&t.id()).unwrap().unwrap();
        assert_eq!(row.scope, Scope::Meta, "{path}");
    }
    assert!(
        !std::fs::read_to_string(gv.home_file("mcp.toml"))
            .unwrap()
            .contains("gvk1_")
    );

    // Running it again replaces the tokens and revokes the old ones.
    gv.ok(&["mcp", "setup", "acme"], b"");
    let second = read(&gv);
    assert_eq!(second.len(), 4);
    for (_, old) in &first {
        assert!(server.store().token_by_id(&old.id()).unwrap().is_none());
    }
}

/// A restore can roll back the parent's link to a rekeyed node, which is an
/// ordinary write in another vault. The rekeying machine still reaches the
/// whole subtree, relinks it on its next rediscovery, and from then on the
/// recovery kit alone reaches everything again.
#[test]
fn a_parent_link_rolled_back_after_a_rekey_is_relinked() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(&["env", "add", "acme/dev/eu"], b"");
    gv.set("acme/dev/eu", "EU", "e1");
    gv.ok(&["rekey", "acme/dev", "--kit", "dev-new.gvkit"], b"");

    // What a restore to just before the link write leaves: acme's children
    // record naming dev by its old, derived key (written here with the
    // project key, as the owner's earlier record was).
    let owner = gv.held_key("acme").owner();
    let acme = server
        .store()
        .vault_by_id(&owner.vault_id())
        .unwrap()
        .unwrap();
    let blob = server.store().children(acme.pk).unwrap().unwrap();
    let mut record = owner.open_children(&blob).unwrap();
    record
        .set_mode(&Segment::new("dev").unwrap(), ChildMode::Derived)
        .unwrap();
    server
        .store()
        .put_children(
            acme.pk,
            Precondition::IfMatch(blob.version),
            &owner.seal_children(blob.version + 1, &record).unwrap(),
            Ctx {
                actor: Actor::Owner,
                now: now(),
            },
            &Limits::default(),
        )
        .unwrap();
    let kit = gv.file("acme-recovery.gvkit");
    let before = Gv::new(&server);
    before.ok(&["recover", kit.to_str().unwrap()], b"");
    before.fail(&["get", "EU", "--env", "acme/dev/eu"], b"");

    // The rekeying machine still reaches the subtree, and relinks it.
    assert_eq!(gv.get("acme/dev/eu", "EU"), "e1");
    let out = gv.run(&["env", "ls", "acme"], b"");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("relinked acme/dev"), "{err}");

    let after = Gv::new(&server);
    after.ok(&["recover", kit.to_str().unwrap()], b"");
    assert_eq!(after.get("acme/dev/eu", "EU"), "e1");
}

/// Task 13.1's last step: a holder who copied a read token's vault key
/// before `revoke --rotate` can open nothing stored afterwards.
/// A holder who copied a read token's vault key before `revoke --rotate` can
/// open nothing stored afterwards.
#[test]
fn a_copied_read_key_opens_nothing_after_revoke_rotate() {
    use galata_vault::seal::{EnvelopeContext, SealError, open_value};

    let server = Server::start();
    let gv = project(&server);
    let token = gv
        .ok(
            &["token", "mint", "--scope", "read", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();

    // While the token is valid, its holder opens the bundle and keeps the key.
    let keys = TokenKeys::parse(&token).unwrap();
    let me = token_self(&server, &keys);
    let descriptor = me
        .descriptor
        .verify_for(&keys.vault_id(), &me.owner_sign_pub)
        .unwrap();
    let bundle = keys
        .open_bundle(
            &me.bundle,
            &me.owner_sign_pub,
            me.scope.get().unwrap(),
            descriptor.generation,
        )
        .unwrap();
    let copied = bundle.vault_secret().expect("a read token holds the key");
    let pk = server
        .store()
        .vault_by_id(&gv.vault_id("acme/prod"))
        .unwrap()
        .unwrap()
        .pk;
    // Any context will do: the question is whether age decrypts.
    let ctx = EnvelopeContext {
        vault_id: keys.vault_id(),
        generation: 0,
        version: 0,
        written_at: 0,
    };
    let decrypts =
        |ct: &[u8]| !matches!(open_value(copied, &ctx, "?", ct), Err(SealError::Decrypt));
    let before = server
        .store()
        .all_record_versions(pk, RecordKind::Secret)
        .unwrap();
    assert!(
        before
            .iter()
            .filter_map(|v| v.value_ct.as_deref())
            .any(decrypts),
        "the copied key works before the rotation"
    );

    gv.ok(
        &[
            "token",
            "revoke",
            &me.token_id.to_hex(),
            "--rotate",
            "--env",
            "acme/prod",
        ],
        b"",
    );
    gv.set("acme/prod", "AFTER_ROTATE", "new-value");
    let after = server
        .store()
        .all_record_versions(pk, RecordKind::Secret)
        .unwrap();
    assert!(after.iter().any(|v| v.value_ct.is_some()));
    for ct in after.iter().filter_map(|v| v.value_ct.as_deref()) {
        assert!(
            !decrypts(ct),
            "the copied key opens nothing after the rotation"
        );
    }
    assert_eq!(gv.get("acme/prod", "AFTER_ROTATE"), "new-value");
    assert_eq!(gv.get("acme/prod", "PROD_ONLY"), "p1");
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap().flatten() {
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, out);
        } else {
            out.push(p);
        }
    }
}

/// Task 13.4: after a full workflow, nothing the server keeps (database, WAL
/// and journal) holds a plaintext name or value, a project or path name, a
/// node key, a vault private key or a token secret.
#[test]
fn a_dump_of_every_server_artifact_holds_no_plaintext_paths_or_keys() {
    use galata_vault::proto::codec::{TokenString, decode_node_key};

    let server = Server::start();
    let gv = Gv::new(&server);
    // Distinctive strings, so a match cannot be a coincidence.
    gv.ok(&["init", "zqxproject", "--server", &server.url], b"saved\n");
    gv.ok(&["env", "add", "zqxproject/kqvenv"], b"");
    gv.set("zqxproject/kqvenv", "CANARY_NAME_QZX", "canary-value-xqz");
    gv.set("zqxproject", "ROOT_CANARY_QZX", "root-value-xqz");
    let token = gv
        .ok(
            &[
                "token",
                "mint",
                "--scope",
                "read",
                "--env",
                "zqxproject/kqvenv",
            ],
            b"",
        )
        .trim()
        .to_owned();
    let token_id = TokenKeys::parse(&token).unwrap().id().to_hex();
    gv.ok(
        &[
            "token",
            "revoke",
            &token_id,
            "--rotate",
            "--env",
            "zqxproject/kqvenv",
        ],
        b"",
    );
    gv.ok(&["rekey", "zqxproject/kqvenv", "--kit", "env.gvkit"], b"");
    gv.ok(&["env", "add", "zqxproject/gonezqx"], b"");
    gv.ok(&["env", "rm", "zqxproject/gonezqx"], b"");

    let project_key = gv.held_key("zqxproject");
    let old_env_key = project_key.child(&Segment::new("kqvenv").unwrap());
    let kit = std::fs::read_to_string(gv.file("env.gvkit")).unwrap();
    let new_env_key =
        NodeKey::parse(kit.split('"').find(|s| s.starts_with("gvk1_")).unwrap()).unwrap();
    assert_eq!(
        new_env_key.encode().as_str(),
        gv.held_key("zqxproject/kqvenv").encode().as_str()
    );

    let mut needles: Vec<(String, Vec<u8>)> = Vec::new();
    for (label, key) in [
        ("project key", &project_key),
        ("old environment key", &old_env_key),
        ("new environment key", &new_env_key),
    ] {
        needles.push((
            label.into(),
            decode_node_key(&key.encode()).unwrap().to_vec(),
        ));
        needles.push((format!("{label} (text)"), key.encode().as_bytes().to_vec()));
    }
    for key in [&project_key, &new_env_key] {
        let owner = key.owner();
        let row = server
            .store()
            .vault_by_id(&owner.vault_id())
            .unwrap()
            .unwrap();
        let full = owner
            .open_own_bundle(&row.owner_bundle, row.generation)
            .unwrap();
        needles.push((
            "a vault private key".into(),
            full.vault_secret.as_bytes().to_vec(),
        ));
        needles.push((
            "a config private key".into(),
            full.config_secret.as_bytes().to_vec(),
        ));
    }
    needles.push((
        "the token secret".into(),
        TokenString::parse(&token).unwrap().secret.to_vec(),
    ));
    needles.push(("the token".into(), token.as_bytes().to_vec()));
    for plain in [
        "CANARY_NAME_QZX",
        "canary-value-xqz",
        "ROOT_CANARY_QZX",
        "root-value-xqz",
        "zqxproject",
        "kqvenv",
        "gonezqx",
    ] {
        needles.push((format!("{plain:?}"), plain.as_bytes().to_vec()));
    }

    server.store().checkpoint().unwrap();
    let mut files = Vec::new();
    collect_files(server.data_dir(), &mut files);
    let has = |pred: &dyn Fn(&str) -> bool| files.iter().any(|p| pred(&p.to_string_lossy()));
    assert!(has(&|p| p.ends_with("vault.db")), "{files:?}");
    assert!(
        has(&|p| p.contains("/journal/")),
        "critical operations were journaled"
    );

    for file in &files {
        let bytes = std::fs::read(file).unwrap();
        for (label, needle) in &needles {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_slice()),
                "{} contains {label}",
                file.display()
            );
        }
    }
}

// ------------------------------------------------------------ configs

/// CRLF, trailing blanks, a blank line and no final newline: all kept.
const APP_TOML: &[u8] = b"[app]\r\nname = \"acme\"  \r\nworkers = 4\n\n# no final newline";

#[test]
fn config_set_get_ls_history_rm() {
    let server = Server::start();
    let gv = project(&server);
    let dev = ["--env", "acme/dev"];
    let run = |args: &[&str], stdin: &[u8]| gv.ok(&[&["config"], args, &dev].concat(), stdin);

    run(&["set", "app", "--format", "toml"], APP_TOML);
    assert_eq!(run(&["get", "app"], b"").as_bytes(), APP_TOML);

    let file = gv.file("app.json");
    std::fs::write(&file, b"{\"a\": 1}\n").unwrap();
    run(
        &[
            "set",
            "app",
            "--format",
            "json",
            "--file",
            file.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(run(&["get", "app"], b""), "{\"a\": 1}\n");
    assert_eq!(
        run(&["get", "app", "--version", "1"], b"").as_bytes(),
        APP_TOML
    );

    let ls = run(&["ls"], b"");
    assert!(ls.contains("app") && !ls.contains("DEV_ONLY"), "{ls}");
    assert!(!gv.ok(&["ls", "--env", "acme/dev"], b"").contains("app"));
    let history = run(&["history", "app"], b"");
    assert!(
        history.starts_with("v1") && history.contains("\nv2"),
        "{history}"
    );

    run(&["rm", "app"], b"");
    gv.fail(&["config", "get", "app", "--env", "acme/dev"], b"");
    assert!(!run(&["ls"], b"").contains("app"));
    assert!(run(&["ls", "--all"], b"").contains("(deleted)"));
    let status = gv.ok(&["status", "--env", "acme/dev"], b"");
    assert!(status.contains("generation   1"), "{status}");
    assert!(status.contains("configs      0 live"), "{status}");
    // An address is 40 hex digits, not a key.
    let wallet = format!("addr = \"0x{}\"\n", "cd".repeat(20));
    run(&["set", "wallet", "--format", "toml"], wallet.as_bytes());
}

#[test]
fn a_config_is_checked_before_any_request() {
    let server = Server::start();
    let gv = project(&server);
    let set = |name: &str, extra: &[&str], body: &[u8]| {
        gv.run(
            &[
                &[
                    "config", "set", name, "--format", "toml", "--env", "acme/dev",
                ],
                extra,
            ]
            .concat(),
            body,
        )
    };
    let stderr = |out: &Output| String::from_utf8_lossy(&out.stderr).into_owned();

    server.clear_seen();
    let out = set("bad", &[], b"a = 1\nb = = 2\nsecret = \"zqx\"\n");
    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(err.contains("line 2") && err.contains("toml"), "{err}");
    assert!(!err.contains("zqx"), "never the body: {err}");

    let hex = "ab".repeat(32);
    let key = format!("[producer]\nagent_key = \"0x{hex}\"\n");
    let out = set("signer", &[], key.as_bytes());
    let err = stderr(&out);
    assert!(!out.status.success());
    assert!(
        err.contains("line 2")
            && err.contains("hex private key")
            && err.contains("--allow-literals"),
        "{err}"
    );
    assert!(!err.contains(&hex));

    let out = set("gv:children", &[], b"a = 1\n");
    assert!(stderr(&out).contains("\"gv:\""), "{}", stderr(&out));
    assert!(
        server.seen().is_empty(),
        "every refusal came before a request"
    );

    assert!(
        set("signer", &["--allow-literals"], key.as_bytes())
            .status
            .success()
    );
    // No format, no write.
    gv.fail(&["config", "set", "app", "--env", "acme/dev"], b"a = 1\n");
}

#[test]
fn config_tokens_read_configs_and_never_a_secret() {
    let server = Server::start();
    let gv = project(&server);
    gv.ok(
        &[
            "config",
            "set",
            "app",
            "--format",
            "toml",
            "--env",
            "acme/prod",
        ],
        b"a = 1\n",
    );
    let mint = |scope: &str| {
        gv.ok(
            &["token", "mint", "--scope", scope, "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned()
    };
    let (config, writer) = (mint("config"), mint("config-write"));

    // A machine with no configuration at all, only a token.
    let ci = Gv::new(&server);
    let run = |token: &str, args: &[&str], stdin: &[u8]| {
        ci.run_with(
            args,
            stdin,
            &[("GV_TOKEN", token), ("GV_SERVER", server.url.as_str())],
        )
    };

    let out = run(&config, &["config", "get", "app"], b"");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(out.stdout, b"a = 1\n");
    for (token, args, stdin) in [
        (&config, &["get", "PROD_ONLY"][..], &b""[..]),
        (
            &config,
            &["config", "set", "app", "--format", "toml"],
            b"a = 2\n",
        ),
        (&writer, &["get", "PROD_ONLY"], b""),
        (&writer, &["set", "NEW"], b"x"),
    ] {
        let out = run(token, args, stdin);
        assert!(!out.status.success(), "{args:?} should be refused");
        assert!(!String::from_utf8_lossy(&out.stdout).contains("p1"));
    }

    let out = run(
        &writer,
        &["config", "set", "app", "--format", "toml"],
        b"a = 2\n",
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(
        gv.ok(&["config", "get", "app", "--env", "acme/prod"], b""),
        "a = 2\n"
    );
}

/// A config token's bundle holds the name key and the config key only, and a
/// holder who copied that config key before `revoke --rotate` can open no
/// config stored afterwards.
#[test]
fn a_copied_config_key_opens_nothing_after_revoke_rotate() {
    use galata_vault::backend::RecordKind;
    use galata_vault::seal::{EnvelopeContext, SealError, open_config};

    let server = Server::start();
    let gv = project(&server);
    gv.ok(
        &[
            "config",
            "set",
            "app",
            "--format",
            "toml",
            "--env",
            "acme/prod",
        ],
        b"a = 1\n",
    );
    let token = gv
        .ok(
            &["token", "mint", "--scope", "config", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();

    let keys = TokenKeys::parse(&token).unwrap();
    let me = token_self(&server, &keys);
    let descriptor = me
        .descriptor
        .verify_for(&keys.vault_id(), &me.owner_sign_pub)
        .unwrap();
    let open = || {
        keys.open_bundle(
            &me.bundle,
            &me.owner_sign_pub,
            me.scope.get().unwrap(),
            descriptor.generation,
        )
        .unwrap()
    };
    assert!(
        open().into_full().is_err(),
        "a config token holds no vault key"
    );
    let bundle = open();
    let copied = bundle
        .config_secret()
        .expect("a config token holds the config key");

    let pk = server
        .store()
        .vault_by_id(&gv.vault_id("acme/prod"))
        .unwrap()
        .unwrap()
        .pk;
    let ctx = EnvelopeContext {
        vault_id: keys.vault_id(),
        generation: 0,
        version: 0,
        written_at: 0,
    };
    let decrypts =
        |ct: &[u8]| !matches!(open_config(copied, &ctx, "?", ct), Err(SealError::Decrypt));
    let before = server
        .store()
        .all_record_versions(pk, RecordKind::Config)
        .unwrap();
    assert!(
        before
            .iter()
            .filter_map(|v| v.value_ct.as_deref())
            .any(decrypts),
        "the copied key works before the rotation"
    );

    gv.ok(
        &[
            "token",
            "revoke",
            &me.token_id.to_hex(),
            "--rotate",
            "--env",
            "acme/prod",
        ],
        b"",
    );
    gv.ok(
        &[
            "config",
            "set",
            "after",
            "--format",
            "text",
            "--env",
            "acme/prod",
        ],
        b"new",
    );
    let after = server
        .store()
        .all_record_versions(pk, RecordKind::Config)
        .unwrap();
    assert!(after.iter().filter(|v| v.value_ct.is_some()).count() >= 2);
    for ct in after.iter().filter_map(|v| v.value_ct.as_deref()) {
        assert!(
            !decrypts(ct),
            "the copied key opens nothing after the rotation"
        );
    }
    assert_eq!(
        gv.ok(&["config", "get", "app", "--env", "acme/prod"], b""),
        "a = 1\n"
    );
}

/// Design D10 across runs: the versions this machine saw are kept in
/// state.toml, so a server that later shows an older one is caught.
#[test]
fn a_record_rolled_back_between_runs_is_caught() {
    let server = Server::start();
    let gv = project(&server);
    gv.set("acme/dev", "ROLLED", "a");
    gv.set("acme/dev", "ROLLED", "b");
    assert!(gv.state().contains("[pins."), "{}", gv.state());

    // What restoring an older backup does: ROLLED back at version 1.
    let pk = server
        .store()
        .vault_by_id(&gv.vault_id("acme/dev"))
        .unwrap()
        .unwrap()
        .pk;
    let db = rusqlite::Connection::open(server.data_dir().join("vault.db")).unwrap();
    db.busy_timeout(Duration::from_secs(5)).unwrap();
    let deleted = db
        .execute(
            "DELETE FROM secrets WHERE vault_pk = ?1 AND version = 2",
            [pk],
        )
        .unwrap();
    assert_eq!(deleted, 1);
    let rewound = db
        .execute(
            "UPDATE heads SET current_version = 1 WHERE vault_pk = ?1 AND current_version = 2",
            [pk],
        )
        .unwrap();
    assert_eq!(rewound, 1);

    let err = gv.fail(&["get", "ROLLED", "--env", "acme/dev"], b"");
    assert!(
        err.contains("acme/dev") && err.contains("rollback"),
        "{err}"
    );
    // A machine that never saw version 2 cannot tell.
    let fresh = Gv::new(&server);
    fresh.ok(
        &["recover", gv.file("acme-recovery.gvkit").to_str().unwrap()],
        b"",
    );
    assert_eq!(fresh.get("acme/dev", "ROLLED"), "a");
}

/// A leaked token is revoked by whoever holds it: the string
/// comes from a file or stdin, never an argument, and is never sent.
#[test]
fn a_leaked_token_is_reported_from_a_file_or_stdin() {
    let server = Server::start();
    let gv = project(&server);
    let mint = || {
        gv.ok(
            &["token", "mint", "--scope", "read", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned()
    };
    let works = |token: &str| {
        Gv::new(&server)
            .run_with(
                &["get", "PROD_ONLY"],
                b"",
                &[("GV_TOKEN", token), ("GV_SERVER", &server.url)],
            )
            .status
            .success()
    };

    // Whoever found it, on a machine with no configuration: from a file.
    let leaked = mint();
    assert!(works(&leaked));
    let finder = Gv::new(&server);
    std::fs::write(finder.file("found.txt"), format!("{leaked}\n")).unwrap();
    let out = finder.run(
        &[
            "token",
            "report",
            "--file",
            "found.txt",
            "--server",
            &server.url,
        ],
        b"",
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && err.contains("revoked it"), "{err}");
    assert!(!works(&leaked));

    // From stdin, the server found from this machine's configuration.
    let second = mint();
    let out = gv.run(&["token", "report"], second.as_bytes());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success() && err.contains("revoked it"), "{err}");
    assert!(!works(&second));
    for stream in [&out.stdout, &out.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(&second[5..]),
            "the token is never printed"
        );
    }

    // Anything else is refused before any request.
    server.clear_seen();
    let err = finder.fail(
        &["token", "report", "--server", &server.url],
        b"gvt1_not-a-token",
    );
    assert!(err.contains("not a valid gvt1_ token"), "{err}");
    assert!(server.seen().is_empty(), "{:?}", server.seen());
}

/// Minting and rotating are the owner's alone, whatever a
/// token's scope.
#[test]
fn minting_and_rotating_need_the_owner_key() {
    let server = Server::start();
    let gv = project(&server);
    let admin = gv
        .ok(
            &["token", "mint", "--scope", "admin", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();
    let ci = Gv::new(&server);
    let tm = [
        ("GV_TOKEN", admin.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];
    for args in [
        &["token", "mint", "--scope", "read"][..],
        &["token", "mint", "--scope", "admin"],
        &["rotate"],
    ] {
        let out = ci.run_with(args, b"", &tm);
        let err = String::from_utf8_lossy(&out.stderr);
        assert!(
            !out.status.success() && err.contains("owner key"),
            "{args:?}: {err}"
        );
    }
    assert_eq!(
        gv.ok(&["token", "ls", "--env", "acme/prod"], b"")
            .lines()
            .count(),
        1,
        "nothing was minted"
    );
    assert!(
        gv.ok(&["status", "--env", "acme/prod"], b"")
            .contains("generation   1")
    );

    // The admin token still reads and writes.
    assert!(
        ci.run_with(&["set", "FROM_ADMIN"], b"a1", &tm)
            .status
            .success()
    );
    assert_eq!(gv.get("acme/prod", "FROM_ADMIN"), "a1");
}

/// Protocol v1 kits and tokens are refused by name, and never reach the
/// server.
#[test]
fn kits_and_tokens_of_another_version_are_refused() {
    let server = Server::start();
    let gv = Gv::new(&server);
    let v1_key = galata_vault::proto::codec::encode_checked("gvk2_", &[5u8; 32]);
    let kit = gv.file("old-recovery.gvkit");
    std::fs::write(
        &kit,
        format!(
            "v = 1\nkind = \"recovery\"\npath = \"acme\"\nserver = \"{}\"\nkey = \"{}\"\n",
            server.url,
            v1_key.as_str()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&kit, std::fs::Permissions::from_mode(0o600)).unwrap();
    let kit = kit.to_str().unwrap();
    for args in [&["recover", kit][..], &["key", "import", kit]] {
        let err = gv.fail(args, b"");
        assert!(err.contains("version 2"), "{args:?}: {err}");
        assert!(!err.contains(&v1_key[5..]), "never the key: {err}");
    }

    let v1_token = galata_vault::proto::codec::encode_checked("gvt2_", &[3u8; 48]);
    let out = gv.run_with(
        &["get", "X"],
        b"",
        &[("GV_TOKEN", &v1_token), ("GV_SERVER", &server.url)],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success() && err.contains("version 2"), "{err}");
    assert!(server.seen().is_empty(), "{:?}", server.seen());
    assert!(!gv.home_file("config.toml").exists());
}

/// Listing and revoking are the owner's *and* an `admin` token's, as
/// `docs/spec/http-api.md#2` says. Rotating alongside a revocation is still
/// the owner's alone, and is refused on its own terms rather than by
/// refusing the whole command.
#[test]
fn an_admin_token_lists_and_revokes_from_the_command_line() {
    let server = Server::start();
    let gv = project(&server);
    let admin = gv
        .ok(
            &["token", "mint", "--scope", "admin", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();
    let meta = gv
        .ok(
            &["token", "mint", "--scope", "meta", "--env", "acme/prod"],
            b"",
        )
        .trim()
        .to_owned();

    let ci = Gv::new(&server);
    let as_admin = [
        ("GV_TOKEN", admin.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];

    // The admin token sees both tokens, without the owner key anywhere.
    let out = ci.run_with(&["token", "ls"], b"", &as_admin);
    let listed = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(listed.lines().count(), 2, "{listed}");

    // Rotating is still the owner's, and says so about the rotation rather
    // than about the command.
    let meta_id = listed
        .lines()
        .find(|l| l.contains("meta"))
        .and_then(|l| l.split_whitespace().next())
        .expect("the meta token is listed")
        .to_owned();
    let out = ci.run_with(&["token", "revoke", &meta_id, "--rotate"], b"", &as_admin);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "--rotate must need the owner key");
    assert!(
        err.contains("owner key") && err.contains("admin token"),
        "{err}"
    );

    // Without --rotate it goes through, and the token really is gone.
    // A lesser scope is refused by naming the scope it lacks, not the owner key.
    let as_meta = [
        ("GV_TOKEN", meta.as_str()),
        ("GV_SERVER", server.url.as_str()),
    ];
    let out = ci.run_with(&["token", "ls"], b"", &as_meta);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a meta token may not list");
    assert!(err.contains("admin"), "{err}");

    let out = ci.run_with(&["token", "revoke", &meta_id], b"", &as_admin);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let listed = ci.run_with(&["token", "ls"], b"", &as_admin);
    assert_eq!(String::from_utf8_lossy(&listed.stdout).lines().count(), 1);

    // And the revoked token really is refused by the server now.
    let out = ci.run_with(&["token", "ls"], b"", &as_meta);
    assert!(!out.status.success(), "a revoked token opens nothing");
}
