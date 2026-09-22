//! The owner API against a real server, in-process on loopback: the
//! `owner-sdk` scenarios. Keys live in an in-memory key store, local state in
//! an in-memory state store, and every notice goes to a recording observer:
//! nothing here touches a keychain, a terminal or stdout.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::Request;
use axum::middleware::Next;
use galata_vault::backend::{SqliteStore, Store, StoreConfig};
use galata_vault::owner::{GrantsSubtreeOwnership, Kit, KitKind, Owner, RetiresAllTokens};
use galata_vault::server::journal::FileJournal;
use galata_vault::server::{AppState, Core, Policy, ServerConfig, SystemClock, router};
use galata_vault::state::MemoryStateStore;
use galata_vault::store::MemoryKeyStore;
use galata_vault::{
    Actor, AuditReport, ClientBuilder, EnvPath, Error, ErrorKind, Events, FileStateStore, Progress,
    Scope, StateStore, Vault, Warning, code,
};
use gv_adversary::{Adversary, Matcher};

struct Server {
    url: String,
    store: Arc<SqliteStore>,
    /// Every request the server received.
    requests: Arc<AtomicUsize>,
    _dir: tempfile::TempDir,
}

impl Server {
    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

fn start() -> Server {
    start_with(|_| {})
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
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = requests.clone();
    let app = router(state).layer(axum::middleware::from_fn(
        move |req: Request, next: Next| {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                next.run(req).await
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
        store,
        requests,
        _dir: dir,
    }
}

/// Every notice, in order.
#[derive(Default)]
struct Recorder {
    progress: Mutex<Vec<Progress>>,
    warnings: Mutex<Vec<Warning>>,
    expiry: Mutex<Vec<(String, i64)>>,
}

impl Events for Recorder {
    fn progress(&self, event: &Progress) {
        self.progress.lock().unwrap().push(event.clone());
    }

    fn expiry(&self, label: &str, expires_at: i64) {
        self.expiry
            .lock()
            .unwrap()
            .push((label.to_owned(), expires_at));
    }

    fn warning(&self, warning: &Warning) {
        self.warnings.lock().unwrap().push(warning.clone());
    }
}

/// One owner's machine: its key store, state store and observer.
struct Machine {
    keys: Arc<MemoryKeyStore>,
    state: Arc<MemoryStateStore>,
    events: Arc<Recorder>,
}

impl Machine {
    fn new() -> Machine {
        Machine {
            keys: Arc::new(MemoryKeyStore::new()),
            state: Arc::new(MemoryStateStore::new()),
            events: Arc::new(Recorder::default()),
        }
    }

    fn owner(&self) -> Owner {
        Owner::open(self.keys.clone(), self.state.clone())
            .unwrap()
            .with_events(self.events.clone())
    }
}

fn p(s: &str) -> EnvPath {
    s.parse().unwrap()
}

/// An owner of project `acme` on `url`, with `envs` added.
fn project(url: &str, envs: &[&str]) -> (Machine, Owner) {
    let m = Machine::new();
    let mut owner = m.owner();
    owner
        .begin_init("acme", url)
        .unwrap()
        .confirm_kit_stored()
        .unwrap();
    for e in envs {
        owner.env_add(&p(e)).unwrap();
    }
    (m, owner)
}

#[test]
fn init_without_acknowledgement_leaves_nothing() {
    let server = start();
    let m = Machine::new();
    let mut owner = m.owner();
    let before = server.requests();
    {
        let pending = owner.begin_init("acme", &server.url).unwrap();
        let kit = pending.recovery_kit().render().unwrap();
        assert!(kit.contains("gvk1_"));
        assert_eq!(pending.recovery_kit().kind(), KitKind::Recovery);
        // Dropped: the kit was never acknowledged.
    }
    assert!(m.keys.names().is_empty(), "no key was stored");
    assert!(owner.state().projects.is_empty());
    assert!(m.state.load().unwrap().projects.is_empty());
    assert_eq!(
        server.requests(),
        before,
        "no request before acknowledgement"
    );

    // Acknowledged, the project exists.
    let info = owner
        .begin_init("acme", &server.url)
        .unwrap()
        .confirm_kit_stored()
        .unwrap();
    assert_eq!(info.path, p("acme"));
    assert_eq!(m.keys.names(), ["node:acme"]);
    let e = owner.begin_init("acme", &server.url).unwrap_err();
    assert_eq!(e.code(), code::PROJECT_EXISTS);
}

#[test]
fn only_held_keys_are_stored_and_a_token_is_shown_once() {
    let server = start();
    let (m, mut owner) = project(
        &server.url,
        &[
            "acme/dev",
            "acme/prod",
            "acme/prod/eu",
            "acme/qa",
            "acme/stage",
            "acme/test",
        ],
    );
    assert_eq!(m.keys.names(), ["node:acme"], "derived keys are not stored");

    let env = owner.environment(&p("acme/prod")).unwrap();
    assert_eq!(env.set_secret("DB", b"postgres://prod").unwrap(), 1);
    let token = env.mint(Scope::Read, 0, &[]).unwrap();
    owner.close(env).unwrap();
    assert_eq!(m.keys.names(), ["node:acme"]);

    let debug = format!("{token:?}");
    assert!(debug.contains(&format!("{:?}", token.id())), "{debug}");
    assert!(debug.contains("Read"), "{debug}");
    assert!(!debug.contains(&token.expose()[5..]), "{debug}");

    let reader = Vault::new(token.expose(), &server.url).unwrap();
    assert_eq!(reader.secret("DB").unwrap().expose(), b"postgres://prod");

    // Revoked without rotating: forward-only, and said so.
    let env = owner.environment(&p("acme/prod")).unwrap();
    let listed = env.tokens().unwrap();
    assert!(
        listed
            .iter()
            .any(|t| t.id == token.id() && t.scope == Scope::Read)
    );
    let revoked = env.revoke(&token.id(), false).unwrap();
    assert!(revoked.forward_only());
    assert!(revoked.held_keys().contains("the secret key"));
    let warned = m.events.warnings.lock().unwrap().clone();
    assert!(
        warned.iter().any(|w| matches!(
            w,
            Warning::ForwardOnlyRevocation { path, scope, .. } if path == "acme/prod" && scope == "read"
        )),
        "{warned:?}"
    );
    let second = env.mint(Scope::Read, 0, &[]).unwrap();
    owner.close(env).unwrap();
    assert_eq!(
        Vault::new(token.expose(), &server.url).unwrap_err().code(),
        "unauthorized"
    );

    // Revoked with a rotation: the vault moves to generation 2.
    let env = owner.environment(&p("acme/prod")).unwrap();
    let revoked = env.revoke(&second.id(), true).unwrap();
    assert_eq!(revoked.rotated_to, Some(2));
    assert!(!revoked.forward_only());
    owner.close(env).unwrap();
    let env = owner.environment(&p("acme/prod")).unwrap();
    assert_eq!(env.status_at_open().generation, 2);
    assert_eq!(env.secret("DB").unwrap().expose(), b"postgres://prod");
    owner.close(env).unwrap();
}

#[test]
fn local_state_holds_no_secret_material() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("S", b"value").unwrap();
    let token = env.mint(Scope::Admin, 0, &[]).unwrap();
    owner.audit(&env, 0).unwrap();
    owner.close(env).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let files = FileStateStore::new(dir.path());
    files.save(owner.state()).unwrap();
    for f in [files.config_path(), files.state_path()] {
        let text = std::fs::read_to_string(&f).unwrap();
        assert!(!text.contains("gvk1_"), "{}: {text}", f.display());
        assert!(!text.contains("gvt1_"), "{}: {text}", f.display());
        assert!(!text.contains(&token.expose()[5..]));
    }
    assert_eq!(files.load().unwrap(), *owner.state());
}

#[test]
fn a_mistyped_path_is_refused_before_any_request() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/prod"]);
    let before = server.requests();
    match owner.environment(&p("acme/prdo")).unwrap_err() {
        Error::UnknownPath {
            path,
            suggestion,
            project_known,
            ..
        } => {
            assert_eq!(path, "acme/prdo");
            assert_eq!(suggestion.as_deref(), Some("acme/prod"));
            assert!(project_known);
        }
        other => panic!("not an unknown path: {other:?}"),
    }
    assert_eq!(owner.closest_known(&p("acme/prdo")), Some(p("acme/prod")));
    let e = owner.environment(&p("acmee/prod")).unwrap_err();
    assert_eq!(e.code(), code::UNKNOWN_PATH);
    assert!(matches!(
        e,
        Error::UnknownPath {
            project_known: false,
            ..
        }
    ));
    assert_eq!(server.requests(), before, "refused before any request");
}

#[test]
fn a_delegation_kit_hands_over_a_subtree() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev", "acme/dev/eu", "acme/prod"]);
    let kit = owner
        .export_kit(&p("acme/dev"), GrantsSubtreeOwnership)
        .unwrap();
    assert_eq!(kit.kind(), KitKind::Delegation);
    assert_eq!(kit.file_name(), "acme-dev-delegation.gvkit");
    let text = kit.render().unwrap();

    let other = Machine::new();
    let mut theirs = other.owner();
    let found = theirs.import(&Kit::parse(&text).unwrap()).unwrap();
    assert_eq!(found.root, p("acme/dev"));
    assert_eq!(found.found, [p("acme/dev"), p("acme/dev/eu")]);
    assert!(found.unreachable.is_empty());
    assert_eq!(other.keys.names(), ["node:acme/dev"]);
    let env = theirs.environment(&p("acme/dev/eu")).unwrap();
    env.set_secret("EU", b"e").unwrap();
    theirs.close(env).unwrap();
    assert!(theirs.environment(&p("acme/prod")).is_err());

    // A delegation kit is not a recovery kit.
    let e = theirs.recover(&Kit::parse(&text).unwrap()).unwrap_err();
    assert_eq!(e.code(), code::INVALID_KIT);
}

#[test]
fn audit_advances_only_on_success() {
    let adv = Adversary::start();
    let (_m, mut owner) = project(adv.url(), &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("A", b"1").unwrap();
    let first = owner.audit(&env, 0).unwrap();
    let head = first.head.expect("the vault has audit rows");
    assert_eq!(owner.state().audit[&env.vault_id()], head);
    assert!(first.entries.iter().any(|e| e.name.as_deref() == Some("A")));
    env.set_secret("B", b"2").unwrap();

    // A forked chain: the latest row altered.
    adv.rewrite(Matcher::get("/v1/audit"), |v| {
        if let Some(rows) = v["rows"].as_array_mut()
            && let Some(last) = rows.last_mut()
        {
            let ts = last["ts"].as_i64().unwrap();
            last["ts"] = serde_json::json!(ts + 1);
        }
    });
    let e = owner.audit(&env, 0).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Integrity, "{e}");
    assert!(
        [code::AUDIT_MISMATCH, code::BINDING_MISMATCH].contains(&e.code()),
        "{e}"
    );
    assert_eq!(
        owner.state().audit[&env.vault_id()],
        head,
        "the head did not move"
    );

    adv.clear_rules();
    let next = owner.audit(&env, 0).unwrap();
    assert!(next.head.unwrap().seq > head.seq);
    assert!(next.new_rows > 0);
    owner.close(env).unwrap();
}

#[test]
fn a_rekey_re_roots_the_subtree_and_retires_its_tokens() {
    let server = start();
    let (m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("K", b"v").unwrap();
    let token = env.mint(Scope::Read, 0, &[]).unwrap();
    owner.close(env).unwrap();
    let old = owner.state().projects["acme"].tree["acme/dev"].vault_id;

    let pending = owner.begin_rekey(&p("acme/dev"), RetiresAllTokens).unwrap();
    assert_eq!((pending.nodes(), pending.tokens().len()), (1, 1));
    let new_id = pending.new_vault_id();
    assert_eq!(pending.kit().kind(), KitKind::Delegation);
    assert!(pending.kit().render().unwrap().contains("gvk1_"));
    let outcome = pending.confirm_kit_stored("kit-path").unwrap();
    assert_eq!(outcome.nodes, 1);
    assert_eq!(outcome.remint.len(), 1);
    assert_eq!(outcome.kit, std::path::PathBuf::from("kit-path"));
    assert_eq!(outcome.new_vault_id, new_id);
    assert!(owner.rekey_in_progress().is_none());

    assert!(
        server.store.vault_by_id(&old).unwrap().is_none(),
        "the old vault is gone"
    );
    assert!(
        m.events
            .progress
            .lock()
            .unwrap()
            .iter()
            .any(|e| matches!(e, Progress::RekeyPlanned { path, .. } if path == "acme/dev"))
    );
    assert_eq!(m.keys.names(), ["node:acme", "node:acme/dev"]);
    assert_eq!(
        Vault::new(token.expose(), &server.url).unwrap_err().code(),
        "unauthorized"
    );
    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.secret("K").unwrap().expose(), b"v");
    assert_eq!(env.vault_id(), new_id);
    owner.close(env).unwrap();
    assert!(owner.state().projects["acme"].tree["acme/dev"].sealed);
}

#[test]
fn a_rekey_without_the_parent_key_detaches_the_node() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let kit = owner
        .export_kit(&p("acme/dev"), GrantsSubtreeOwnership)
        .unwrap()
        .render()
        .unwrap();

    let delegate = Machine::new();
    let mut theirs = delegate.owner();
    theirs.import(&Kit::parse(&kit).unwrap()).unwrap();
    theirs
        .begin_rekey(&p("acme/dev"), RetiresAllTokens)
        .unwrap()
        .confirm_kit_stored("acme-dev.gvkit")
        .unwrap();
    let warned = delegate.events.warnings.lock().unwrap().clone();
    assert!(
        warned.iter().any(|w| matches!(
            w,
            Warning::Detached { path, parent } if path == "acme/dev" && parent == "acme"
        )),
        "{warned:?}"
    );
}

#[test]
fn expiry_reaches_only_the_observer_of_the_handle() {
    let server = start_with(|p| p.idle_expiry_days = Some(10));
    let (m, mut owner) = project(&server.url, &["acme/dev"]);
    let mut tokens = Vec::new();
    for path in ["acme", "acme/dev"] {
        let env = owner.environment(&p(path)).unwrap();
        env.set_secret("S", b"v").unwrap();
        tokens.push(env.mint(Scope::Read, 0, &[]).unwrap());
        owner.close(env).unwrap();
    }
    let owner_notices = m.events.expiry.lock().unwrap().clone();
    assert!(
        owner_notices.iter().any(|(label, _)| label == "acme/dev"),
        "{owner_notices:?}"
    );

    let (a, b) = (Arc::new(Recorder::default()), Arc::new(Recorder::default()));
    let api_a = ClientBuilder::new(&server.url)
        .events(a.clone())
        .build()
        .unwrap();
    let api_b = ClientBuilder::new(&server.url)
        .events(b.clone())
        .build()
        .unwrap();
    let va = Vault::with_api(tokens[0].expose(), &api_a).unwrap();
    let vb = Vault::with_api(tokens[1].expose(), &api_b).unwrap();
    for _ in 0..3 {
        va.secret("S").unwrap();
        vb.secret("S").unwrap();
    }
    let (na, nb) = (
        a.expiry.lock().unwrap().clone(),
        b.expiry.lock().unwrap().clone(),
    );
    assert_eq!(na.len(), 1, "once per handle: {na:?}");
    assert_eq!(nb.len(), 1, "once per handle: {nb:?}");
    // A notice carries the expiry of the response that raised it. Every later
    // request slides the expiry forward, so across a second boundary the
    // handle's latest value is a little later than the notice, never earlier.
    for (notice, latest) in [
        (na[0].1, va.expiry().vault_expires_at),
        (nb[0].1, vb.expiry().vault_expires_at),
    ] {
        let latest = latest.expect("the handle saw an expiry");
        assert!(
            (0..=5).contains(&(latest - notice)),
            "notice {notice}, latest {latest}"
        );
    }
    assert_ne!(va.vault_id(), vb.vault_id());
}

#[test]
fn a_long_lived_handle_refreshes_after_a_rotation() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("S", b"v1").unwrap();
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let handle = Vault::new(admin.expose(), &server.url).unwrap();
    assert_eq!(handle.secret("S").unwrap().expose(), b"v1");

    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.rotate().unwrap(), 2);
    owner.close(env).unwrap();

    let e = handle.set_secret("S", b"v2").unwrap_err();
    assert_eq!(e.code(), code::STALE_GENERATION, "{e}");
    assert!(matches!(e, Error::StaleGeneration { .. }), "{e:?}");
    assert_eq!(e.kind(), ErrorKind::Conflict);
    let e = handle.set_secret("NEW", b"n").unwrap_err();
    assert_eq!(e.code(), code::STALE_GENERATION, "{e}");

    handle.refresh().unwrap();
    assert_eq!(handle.set_secret("S", b"v2").unwrap(), 2);
    assert_eq!(handle.secret("S").unwrap().expose(), b"v2");
    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.secret("S").unwrap().expose(), b"v2");
    owner.close(env).unwrap();
}

#[test]
fn a_token_can_do_everything_its_scope_allows() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    for v in [b"1", b"2", b"3"] {
        env.set_secret("OLD_KEY", v).unwrap();
    }
    for name in ["A", "B", "C"] {
        env.set_secret(name, name.as_bytes()).unwrap();
    }
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    let read = env
        .mint(Scope::Read, 0, &["A".to_owned(), "B".to_owned()])
        .unwrap();
    owner.close(env).unwrap();

    let admin = Vault::new(admin.expose(), &server.url).unwrap();
    let e = admin.delete_secret("OLD_KEY", Some(2)).unwrap_err();
    assert!(
        matches!(
            e,
            Error::Conflict {
                current: Some(3),
                ..
            }
        ),
        "{e:?}"
    );
    assert_eq!(admin.delete_secret("OLD_KEY", Some(3)).unwrap(), 4);
    assert!(!admin.list().unwrap().iter().any(|e| e.name == "OLD_KEY"));
    let all = admin.list_all().unwrap();
    let old = all.iter().find(|e| e.name == "OLD_KEY").unwrap();
    assert!(old.deleted && old.version == 4);
    let history = admin.history("OLD_KEY").unwrap();
    assert_eq!(history.len(), 4);
    assert!(history[3].tombstone);
    assert_eq!(
        admin.delete_secret("OLD_KEY", None).unwrap_err().code(),
        code::NOT_FOUND
    );
    assert_eq!(admin.status().unwrap().generation, 1);

    let read = Vault::new(read.expose(), &server.url).unwrap();
    let names = |set: galata_vault::SecretSet| -> Vec<String> {
        set.iter().map(|v| v.name().to_owned()).collect()
    };
    assert_eq!(names(read.readable(None).unwrap()), ["A", "B"]);
    assert_eq!(names(read.readable(Some(&["A"])).unwrap()), ["A"]);
    assert_eq!(
        read.readable(Some(&["MISSING"])).unwrap_err().code(),
        code::NOT_FOUND
    );

    let store = MemoryStateStore::new();
    let report = read.audit(&store).unwrap();
    let head = report.head.unwrap();
    assert_eq!(store.load().unwrap().audit[&read.vault_id()], head);
    let again = read.audit(&store).unwrap();
    assert_eq!(again.new_rows, 0);
}

/// The token list goes to the owner and to an admin token, and to nobody
/// else (`docs/spec/http-api.md#2`). A lesser scope is refused by name,
/// never shown an empty list, which would say the vault has no tokens.
#[test]
fn an_admin_token_lists_tokens_and_lesser_scopes_are_refused() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("A", b"a").unwrap();
    env.set_secret("B", b"b").unwrap();
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    let read = env.mint(Scope::Read, 0, &["A".to_owned()]).unwrap();
    let meta = env.mint(Scope::Meta, 0, &[]).unwrap();
    owner.close(env).unwrap();

    // The admin token sees every token, with the read token's allow-list
    // decrypted to the name it names.
    let admin_vault = Vault::new(admin.expose(), &server.url).unwrap();
    let listed = admin_vault.tokens().unwrap();
    assert_eq!(listed.len(), 3, "{listed:?}");
    let allow: Vec<_> = listed.iter().filter_map(|t| t.only.clone()).collect();
    assert_eq!(allow, vec![vec!["A".to_owned()]], "{listed:?}");

    // The owner sees the same three.
    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.tokens().unwrap().len(), 3);
    owner.close(env).unwrap();

    // Every other scope is refused, naming the scope it lacks.
    for (scope, token) in [(Scope::Read, &read), (Scope::Meta, &meta)] {
        let v = Vault::new(token.expose(), &server.url).unwrap();
        let e = v.tokens().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Forbidden, "{scope}: {e}");
        assert!(e.to_string().contains("admin"), "{scope}: {e}");
    }
}

/// An `admin` token may revoke, as the protocol says (`http-api.md#2`), and
/// gets the same forward-only warning the owner gets, because it cannot
/// rotate: the keys the revoked token held still open what its holder
/// copied. Every lesser scope is refused by name.
#[test]
fn an_admin_token_revokes_and_is_warned_that_it_cannot_rotate() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("S", b"v").unwrap();
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    let read = env.mint(Scope::Read, 0, &[]).unwrap();
    let meta = env.mint(Scope::Meta, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let seen = Arc::new(Recorder::default());
    let api = ClientBuilder::new(&server.url)
        .events(seen.clone())
        .build()
        .unwrap();
    let admin_vault = Vault::with_api(admin.expose(), &api).unwrap();

    // Revoking the read token: forward-only, and it says what that token held.
    let revocation = admin_vault.revoke(&read.id()).unwrap();
    assert!(revocation.forward_only(), "{revocation:?}");
    assert!(revocation.held_keys().contains("the secret key"));
    let warned = seen.warnings.lock().unwrap().clone();
    assert!(
        warned.iter().any(|w| matches!(
            w,
            Warning::ForwardOnlyRevocation { scope, .. } if scope == "read"
        )),
        "{warned:?}"
    );

    // The server really dropped it.
    assert_eq!(
        Vault::new(read.expose(), &server.url).unwrap_err().code(),
        "unauthorized"
    );

    // A meta token holds nothing that outlives revocation, so no warning.
    seen.warnings.lock().unwrap().clear();
    let revocation = admin_vault.revoke(&meta.id()).unwrap();
    assert!(!revocation.forward_only(), "{revocation:?}");
    assert!(seen.warnings.lock().unwrap().is_empty());

    // A lesser scope may not revoke at all: refused by scope, client-side,
    // before anything is sent.
    let env = owner.environment(&p("acme/dev")).unwrap();
    let victim = env.mint(Scope::Read, 0, &[]).unwrap();
    let bystander = env.mint(Scope::Read, 0, &[]).unwrap();
    owner.close(env).unwrap();
    let read_vault = Vault::new(bystander.expose(), &server.url).unwrap();
    let e = read_vault.revoke(&victim.id()).unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Forbidden, "{e}");
    assert!(e.to_string().contains("admin"), "{e}");
    // And the victim still works, so nothing was sent.
    assert!(Vault::new(victim.expose(), &server.url).is_ok());
}

/// A name index comes from the generation's name key, so a handle that has
/// not refreshed after a rotation computes indexes the server has never
/// seen. Those misses must be reported as what they are -- the vault moved --
/// and never as a secret that is gone, or as a history with no versions.
#[test]
fn a_stale_handle_is_told_the_vault_moved_not_that_its_secrets_vanished() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("S", b"v1").unwrap();
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let handle = Vault::new(admin.expose(), &server.url).unwrap();
    assert_eq!(handle.secret("S").unwrap().expose(), b"v1");
    assert_eq!(handle.history("S").unwrap().len(), 1);
    // A name that never existed is a plain miss, before any rotation.
    assert_eq!(
        handle.secret("GONE").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(handle.history("GONE").unwrap().is_empty());

    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.rotate().unwrap(), 2);
    owner.close(env).unwrap();

    // Reading an existing secret: the vault moved, not "no secret named S".
    let e = handle.secret("S").unwrap_err();
    assert_eq!(e.code(), code::STALE_GENERATION, "{e}");
    assert!(e.to_string().contains("refresh"), "{e}");

    // Its history: an error, not a silent empty list that says it has none.
    let e = handle.history("S").unwrap_err();
    assert_eq!(e.code(), code::STALE_GENERATION, "{e}");

    // A name that never existed is still reported as stale here, because this
    // handle cannot tell the two apart: its indexes answer for neither.
    let e = handle.secret("GONE").unwrap_err();
    assert_eq!(e.code(), code::STALE_GENERATION, "{e}");

    // And refreshing makes every one of them right again.
    handle.refresh().unwrap();
    assert_eq!(handle.secret("S").unwrap().expose(), b"v1");
    assert_eq!(handle.history("S").unwrap().len(), 1);
    assert_eq!(
        handle.secret("GONE").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(handle.history("GONE").unwrap().is_empty());
}

/// An empty token list is a real answer, and must survive the change that
/// made an ABSENT one an error: a vault with no tokens has none, and saying
/// so is not the same as refusing to say.
#[test]
fn a_vault_with_no_tokens_lists_none_rather_than_refusing() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("S", b"v").unwrap();

    // Never minted anything: the server sends `tokens: []`, not null.
    assert!(env.tokens().unwrap().is_empty());
    // And the mint guard, which now fails closed on an absent list, still
    // lets a first mint through on an empty one.
    let first = env.mint(Scope::Admin, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let env = owner.environment(&p("acme/dev")).unwrap();
    assert_eq!(env.tokens().unwrap().len(), 1);
    owner.close(env).unwrap();

    // The same from the token side, once its own is the only one left.
    let admin = Vault::new(first.expose(), &server.url).unwrap();
    assert_eq!(admin.tokens().unwrap().len(), 1);
}

/// A token receiving the list leaves a row; the owner's own status reads do
/// not, or every environment open would fill the chain (`docs/spec/audit.md#3`).
#[test]
fn a_token_listing_tokens_is_audited_and_the_owners_reads_are_not() {
    let server = start();
    let (_m, mut owner) = project(&server.url, &["acme/dev"]);
    let env = owner.environment(&p("acme/dev")).unwrap();
    env.set_secret("A", b"a").unwrap();
    let admin = env.mint(Scope::Admin, 0, &[]).unwrap();
    let meta = env.mint(Scope::Meta, 0, &[]).unwrap();
    owner.close(env).unwrap();

    let count = |report: &AuditReport| {
        report
            .entries
            .iter()
            .filter(|e| e.action == "token_list")
            .count()
    };

    // Opening and closing the environment reads status as the owner each
    // time, and none of that is recorded.
    let env = owner.environment(&p("acme/dev")).unwrap();
    owner.close(env).unwrap();
    let admin_vault = Vault::new(admin.expose(), &server.url).unwrap();
    assert_eq!(
        count(&admin_vault.verify_audit(None).unwrap()),
        0,
        "the owner's status reads are not audited"
    );

    // A meta token reading status is not an attempt to list.
    let meta_vault = Vault::new(meta.expose(), &server.url).unwrap();
    meta_vault.status().unwrap();
    assert_eq!(
        count(&admin_vault.verify_audit(None).unwrap()),
        0,
        "a scope that is sent no list is not audited"
    );

    // The admin token receiving the list is.
    admin_vault.tokens().unwrap();
    let report = admin_vault.verify_audit(None).unwrap();
    assert_eq!(count(&report), 1, "{:?}", report.entries);
    let row = report
        .entries
        .iter()
        .find(|e| e.action == "token_list")
        .unwrap();
    assert!(matches!(row.actor, Actor::Token(_)), "{row:?}");
    assert!(!row.refused);
}
