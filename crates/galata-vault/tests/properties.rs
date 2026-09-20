//! Rotation and concurrency properties: the races that lose data in a
//! secrets store. Each
//! property drives the SDK against a real gv-server on loopback, in this
//! process, and must end in a state `docs/spec/protocol.md` allows, with no
//! acknowledged write lost:
//!
//! - token holders writing while the owner rotates (§6, §8);
//! - a rotation cut at a random request, then resumed or abandoned (§8);
//! - two owner handles rotating the same vault at once (§8, §12);
//! - config writes racing on one expected version (§6).
//!
//! "Acknowledged" means the SDK returned the version to its caller. Every
//! case starts vaults and threads on a real server, so the case counts are
//! small; the strategies pick the thread counts, names and cut points. Run
//! with `--nocapture` to see how often the races happened, and with
//! `GV_PROPS_DEBUG=1` to see every refusal.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;

use galata_vault::client::{Api, Auth, Method, Request, Response, Transport, TransportError};
use galata_vault::testing::RawVault;
use galata_vault::{ClientBuilder, ConfigFormat, Error, NewConfig, Scope, Vault, code};
use galata_vault_keys::NodeKey;
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_store::{SqliteStore, StoreConfig};
use proptest::collection::vec;
use proptest::prelude::*;
use proptest::test_runner::{Config, TestCaseError, TestRunner};

// ------------------------------------------------------------------ setup

/// A gv-server on an ephemeral loopback port, as `gv-server local` serves a
/// data directory, for the whole of one test.
struct Server {
    url: String,
    _dir: tempfile::TempDir,
}

fn start() -> Server {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("vault.db");
    let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
    let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
    let config = ServerConfig::for_database(&db);
    let state = AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap();
    let app = router(state);
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let addr = listener.local_addr().unwrap();
    thread::spawn(move || {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
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
    Server {
        url: format!("http://{addr}"),
        _dir: dir,
    }
}

// How often the races the properties are about actually happened, printed
// by `check` (see it with `--nocapture`). Shared by the tests of this file.
static STALE_REFRESHES: AtomicUsize = AtomicUsize::new(0);
static LOST_PRECONDITIONS: AtomicUsize = AtomicUsize::new(0);
static ROTATIONS_GIVEN_UP: AtomicUsize = AtomicUsize::new(0);
static CUTS_AFTER_APPLY: AtomicUsize = AtomicUsize::new(0);
static CUTS_BEFORE_APPLY: AtomicUsize = AtomicUsize::new(0);

/// Run `test` on `cases` values of `strategy`. No regression file: a
/// failure prints the shrunk input, which is enough to reproduce.
fn check<S>(cases: u32, strategy: S, test: impl Fn(S::Value) -> Result<(), TestCaseError>)
where
    S: Strategy,
    S::Value: std::fmt::Debug,
{
    let mut runner = TestRunner::new(Config {
        cases,
        failure_persistence: None,
        max_shrink_iters: 16,
        ..Config::default()
    });
    if let Err(e) = runner.run(&strategy, test) {
        panic!("{e}");
    }
    eprintln!(
        "properties so far: {} writer refreshes after a stale generation, {} lost \
         preconditions, {} rotations given up after rebuilding, {} rotations cut after \
         the server applied them, {} cut before",
        STALE_REFRESHES.load(Ordering::Relaxed),
        LOST_PRECONDITIONS.load(Ordering::Relaxed),
        ROTATIONS_GIVEN_UP.load(Ordering::Relaxed),
        CUTS_AFTER_APPLY.load(Ordering::Relaxed),
        CUTS_BEFORE_APPLY.load(Ordering::Relaxed),
    );
}

/// Run `f`, keeping a panic as a message instead of unwinding, so a failing
/// thread still reaches every barrier and no other thread waits forever.
fn contained(failures: &Mutex<Vec<String>>, f: impl FnOnce()) {
    if let Err(p) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        let message = p
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| p.downcast_ref::<&str>().map(|s| (*s).to_owned()))
            .unwrap_or_else(|| "a panic".to_owned());
        failures.lock().unwrap().push(message);
    }
}

fn client(url: &str) -> Api {
    ClientBuilder::new(url).build().unwrap()
}

/// One fresh vault on the server, and its owner.
struct Env {
    url: String,
    api: Api,
    key: NodeKey,
    label: String,
    owner: RawVault,
}

fn env(url: &str) -> Env {
    let api = client(url);
    let key = NodeKey::generate();
    let label = "props/env".to_owned();
    assert!(RawVault::create(&api, &key, &label).unwrap());
    let owner = RawVault::open_owner(&api, &key, &label).unwrap();
    Env {
        url: url.to_owned(),
        api,
        key,
        label,
        owner,
    }
}

type Acked = Vec<(String, u64, Vec<u8>)>;

impl Env {
    fn token(&self, scope: Scope) -> String {
        self.owner
            .mint(scope, 0, None)
            .unwrap()
            .0
            .token_string()
            .to_string()
    }

    fn vault(&self, token: &str) -> Vault {
        Vault::with_api(token, &client(&self.url)).unwrap()
    }

    /// Another owner handle on its own connection.
    fn owner_handle(&self) -> RawVault {
        RawVault::open_owner(&client(&self.url), &self.key, &self.label).unwrap()
    }

    /// The owner as a token client, opened now.
    fn fresh_owner(&self) -> Vault {
        self.owner_handle().into_vault()
    }

    /// Write `name` as the owner from its current version.
    fn seed(&self, name: &str, value: &[u8], acked: &mut Acked) {
        let pre = self.owner.current(name).unwrap();
        let version = self.owner.put(name, value, pre).unwrap();
        acked.push((name.to_owned(), version, value.to_vec()));
    }
}

/// A rotation the SDK gave up on after rebuilding it three times, because
/// writes kept moving the revision (§8: `conflict` means rebuild). Nothing
/// was applied; the spec allows it.
fn kept_changing(e: &Error) -> bool {
    let given_up = e.code() == code::ERROR && e.message().contains("kept changing");
    if given_up {
        ROTATIONS_GIVEN_UP.fetch_add(1, Ordering::Relaxed);
    }
    given_up
}

/// `GV_PROPS_DEBUG=1`: print every refusal and rotation outcome.
fn debug() -> bool {
    std::env::var_os("GV_PROPS_DEBUG").is_some()
}

fn describe(e: &Error) -> String {
    format!("{}: {}", e.code(), e.message())
}

/// Write `value` to secret `name` the way the spec says a writer recovers:
/// a stale generation means refresh and write again (§8), and a failed
/// precondition means another writer won, so read the new current version
/// and write again (§6). Returns the acknowledged version.
fn write_acknowledged(vault: &Vault, name: &str, value: &[u8]) -> u64 {
    for _ in 0..100 {
        let r = vault.set_secret(name, value);
        if let (Err(e), true) = (&r, debug()) {
            eprintln!("write {name}: {}", describe(e));
        }
        match r {
            Ok(version) => return version,
            Err(e) if e.code() == code::STALE_GENERATION => {
                STALE_REFRESHES.fetch_add(1, Ordering::Relaxed);
                vault.refresh().unwrap_or_else(|e| {
                    panic!("§8: a writer refreshing after a rotation: {}", describe(&e))
                })
            }
            Err(e) if e.code() == code::CONFLICT => {
                LOST_PRECONDITIONS.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => panic!("{name}: a write was refused with {}", describe(&e)),
        }
    }
    panic!("{name}: no write succeeded in 100 attempts");
}

/// Every acknowledged write is readable at its version with its value, and
/// the retained versions of each name are exactly the acknowledged ones,
/// 1 to the latest: a refused write stores nothing (§6), and a rotation
/// keeps every retained version, its number and its value (§8). Each is
/// verified and decrypted under the current descriptor. (The properties
/// keep every name under the retention quota of 20 versions, §7, so every
/// acknowledged version must still be there.)
fn assert_nothing_lost(v: &Vault, acked: &Acked) {
    let mut by_name: BTreeMap<&str, BTreeMap<u64, &[u8]>> = BTreeMap::new();
    for (name, version, value) in acked {
        let before = by_name.entry(name).or_default().insert(*version, value);
        assert!(
            before.is_none(),
            "§6: version {version} of {name} was acknowledged to two writers"
        );
    }
    for (name, versions) in &by_name {
        let listed: Vec<u64> = v
            .history(name)
            .unwrap_or_else(|e| panic!("{name}: history: {}", describe(&e)))
            .iter()
            .map(|m| m.version)
            .collect();
        let expected: Vec<u64> = (1..=versions.len() as u64).collect();
        assert_eq!(
            versions.keys().copied().collect::<Vec<_>>(),
            expected,
            "§6: {name}'s acknowledged versions are 1 to the latest, with no gap"
        );
        assert_eq!(
            listed, expected,
            "§6, §8: {name}'s retained versions are exactly the acknowledged ones"
        );
        for (version, value) in versions {
            let got = v
                .secret_version(name, *version)
                .unwrap_or_else(|e| panic!("{name} v{version}: {}", describe(&e)));
            assert_eq!(
                got.expose(),
                *value,
                "§8: version {version} of {name} kept its value"
            );
        }
    }
}

const NAMES: [&str; 3] = ["ALPHA", "BRAVO", "CHARLIE"];

// ------------------------------------------------ rotation while writing

/// Token holders (`admin` or `append`) write while the owner rotates, in
/// phases: in each phase every writer writes and the owner rotates at the
/// same time, and the next phase starts when all of them are done. So each
/// rotation races that phase's writes, and a writer that wrote before a
/// rotation applied writes next with a stale generation, which it recovers
/// from by refreshing. At the end the generation is one more than the
/// number of rotations the server applied, and nothing acknowledged is lost
/// (§6, §8).
#[test]
fn rotation_with_concurrent_writers_loses_no_acknowledged_write() {
    let server = start();
    let strategy = (1usize..=3, 1usize..=2, 1usize..=3, vec(any::<bool>(), 3));
    check(8, strategy, |(writers, per_phase, rotations, admin)| {
        let env = env(&server.url);
        let mut seeded = Acked::new();
        for name in NAMES {
            env.seed(name, b"seed", &mut seeded);
        }
        let acked = Mutex::new(seeded);
        let vaults: Vec<Vault> = (0..writers)
            .map(|i| {
                let scope = if admin[i] {
                    Scope::Admin
                } else {
                    Scope::Append
                };
                env.vault(&env.token(scope))
            })
            .collect();
        // One more phase than rotations: the last phase only writes.
        let phases = rotations + 1;
        let phase = Barrier::new(writers + 1);
        let failures = Mutex::new(Vec::new());
        let mut applied = 0u32;
        thread::scope(|s| {
            for (i, vault) in vaults.into_iter().enumerate() {
                let (phase, acked, failures) = (&phase, &acked, &failures);
                s.spawn(move || {
                    for p in 0..phases {
                        phase.wait();
                        contained(failures, || {
                            for k in 0..per_phase {
                                let j = p * per_phase + k;
                                let name = NAMES[(i + j) % NAMES.len()];
                                let value = format!("writer {i}, write {j}").into_bytes();
                                let version = write_acknowledged(&vault, name, &value);
                                acked
                                    .lock()
                                    .unwrap()
                                    .push((name.to_owned(), version, value));
                            }
                        });
                        phase.wait();
                    }
                });
            }
            for p in 0..phases {
                phase.wait();
                if p < rotations {
                    contained(&failures, || {
                        let r = env.owner.rotate(&[]);
                        if debug() {
                            eprintln!("rotate: {:?}", r.as_ref().map_err(describe));
                        }
                        match r {
                            Ok(_) => applied += 1,
                            Err(e) if kept_changing(&e) => {}
                            Err(e) => {
                                panic!("§8: the owner's rotation failed with {}", describe(&e))
                            }
                        }
                        env.owner.refresh().unwrap();
                    });
                }
                phase.wait();
            }
        });
        let failures = failures.into_inner().unwrap();
        assert!(failures.is_empty(), "{failures:?}");
        assert_eq!(
            env.owner_handle().descriptor().generation,
            1 + applied,
            "§8: each applied rotation moves the vault exactly one generation"
        );
        assert_nothing_lost(&env.fresh_owner(), &acked.into_inner().unwrap());
        Ok(())
    });
}

// ------------------------------------------------ an interrupted rotation

#[derive(Debug, Clone, Copy)]
enum CutAt {
    /// The n-th request after arming, whatever it is.
    Nth(usize),
    /// The rotation batch itself (`POST /v1/vault/rotations`).
    Rotation,
}

#[derive(Debug, Clone)]
struct Fired {
    method: Method,
    path: String,
    reached_server: bool,
}

/// A transport that fails one request: before sending it, or after the
/// server answered it (the answer is lost, as when a connection drops).
struct Cut {
    inner: Arc<dyn Transport>,
    plan: Mutex<Option<(CutAt, bool)>>,
    seen: AtomicUsize,
    fired: Mutex<Option<Fired>>,
}

impl Cut {
    fn new(inner: Arc<dyn Transport>) -> Cut {
        Cut {
            inner,
            plan: Mutex::new(None),
            seen: AtomicUsize::new(0),
            fired: Mutex::new(None),
        }
    }

    fn arm(&self, at: CutAt, after_send: bool) {
        self.seen.store(0, Ordering::SeqCst);
        *self.plan.lock().unwrap() = Some((at, after_send));
    }

    fn disarm(&self) -> Option<Fired> {
        *self.plan.lock().unwrap() = None;
        self.fired.lock().unwrap().take()
    }
}

impl Transport for Cut {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let plan = *self.plan.lock().unwrap();
        if let Some((at, after_send)) = plan {
            let n = self.seen.fetch_add(1, Ordering::SeqCst);
            let hit = match at {
                CutAt::Nth(k) => n == k,
                CutAt::Rotation => {
                    request.method == Method::Post
                        && request.path_and_query == "/v1/vault/rotations"
                }
            };
            if hit {
                *self.plan.lock().unwrap() = None;
                if after_send {
                    self.inner.send(request)?;
                }
                *self.fired.lock().unwrap() = Some(Fired {
                    method: request.method,
                    path: request.path_and_query.to_owned(),
                    reached_server: after_send,
                });
                return Err(TransportError::new(
                    "loopback",
                    "the test cut the connection",
                ));
            }
        }
        self.inner.send(request)
    }
}

/// A rotation cut at a random request (before it is sent, or after the
/// server answered), then resumed by the same owner handle or abandoned,
/// with or without a write in between. The batch is atomic: the vault is at
/// the old or the new generation, never between; a resumed rotation
/// completes; a reader that kept its pins follows; nothing acknowledged is
/// lost (§8, §12).
#[test]
fn an_interrupted_rotation_resumes_or_is_abandoned_without_loss() {
    let server = start();
    let strategy = (
        1usize..=3,
        0usize..=2,
        prop_oneof![(0usize..24).prop_map(CutAt::Nth), Just(CutAt::Rotation)],
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
    );
    check(16, strategy, |args| {
        interrupted_rotation(&server.url, args);
        Ok(())
    });
}

/// The case a run of the strategy may miss: the server applied the
/// rotation and its answer was lost. Resumed and abandoned, with and
/// without a write in between (§8).
#[test]
fn a_rotation_applied_but_unacknowledged_is_resumed_or_abandoned() {
    let server = start();
    for resume in [true, false] {
        for write_between in [true, false] {
            let applied = interrupted_rotation(
                &server.url,
                (2, 1, CutAt::Rotation, true, resume, write_between),
            );
            assert!(applied, "the cut landed after the server applied the batch");
        }
    }
}

/// One interrupted rotation: `secrets` secrets of two versions each and
/// `configs` configs, a read token that has read them, then a rotation cut
/// `at` a request (`after_send`: after the server answered it), then
/// resumed or abandoned. Returns whether the cut rotation was applied.
fn interrupted_rotation(
    url: &str,
    (secrets, configs, at, after_send, resume, write_between): (
        usize,
        usize,
        CutAt,
        bool,
        bool,
        bool,
    ),
) -> bool {
    let env = env(url);
    let mut acked = Acked::new();
    for i in 0..secrets {
        for round in 0..2 {
            let name = format!("S{i}");
            env.seed(&name, format!("{name} v{round}").as_bytes(), &mut acked);
        }
    }
    let bodies: Vec<(String, Vec<u8>)> = (0..configs)
        .map(|i| (format!("c{i}"), format!("k = {i}\n").into_bytes()))
        .collect();
    for (name, body) in &bodies {
        let pre = env.owner.config_current(name).unwrap();
        env.owner
            .put_config(name, ConfigFormat::Toml, body, pre)
            .unwrap();
    }
    let reader = env.vault(&env.token(Scope::Read));
    for (name, _, _) in &acked {
        reader.secret(name).unwrap();
    }

    let cut = Arc::new(Cut::new(env.api.transport().clone()));
    let rotator = RawVault::open_owner(&Api::shared(cut.clone()), &env.key, &env.label).unwrap();
    cut.arm(at, after_send);
    let first = rotator.rotate(&[]);
    let fired = cut.disarm();
    let applied = match (&first, &fired) {
        (Ok(g), None) => {
            assert_eq!(*g, 2, "§8: a rotation moves one generation");
            true
        }
        (Err(e), Some(f)) => {
            assert_eq!(e.code(), code::UNREACHABLE, "{}", describe(e));
            let applied =
                f.reached_server && f.method == Method::Post && f.path == "/v1/vault/rotations";
            if applied {
                CUTS_AFTER_APPLY.fetch_add(1, Ordering::Relaxed);
            } else {
                CUTS_BEFORE_APPLY.fetch_add(1, Ordering::Relaxed);
            }
            applied
        }
        (r, f) => panic!(
            "a cut fails the rotation, and nothing else does: {:?}, {f:?}",
            r.as_ref().map_err(describe)
        ),
    };
    let now = env.owner_handle();
    assert_eq!(
        now.descriptor().generation,
        if applied { 2 } else { 1 },
        "§8: a rotation is one atomic batch: the old generation or the new one, never between"
    );
    if write_between && secrets > 0 {
        let pre = now.current("S0").unwrap();
        let version = now.put("S0", b"written between", pre).unwrap();
        acked.push(("S0".to_owned(), version, b"written between".to_vec()));
    }
    let generation = if resume {
        rotator.refresh().unwrap();
        if rotator.descriptor().generation == 1 {
            let g = rotator
                .rotate(&[])
                .unwrap_or_else(|e| panic!("§8: the resumed rotation: {}", describe(&e)));
            assert_eq!(g, 2, "§8: the resumed rotation completes");
        }
        2
    } else if applied {
        2
    } else {
        1
    };
    assert_eq!(
        env.owner_handle().descriptor().generation,
        generation,
        "§8: resumed means rotated once; abandoned means as the cut left it"
    );
    let owner = env.fresh_owner();
    assert_nothing_lost(&owner, &acked);
    for (name, body) in &bodies {
        let doc = owner.config(name).unwrap();
        assert_eq!(
            (doc.version(), doc.expose()),
            (1, &body[..]),
            "§8: {name} kept"
        );
    }
    reader.refresh().unwrap_or_else(|e| {
        panic!(
            "§12: a reader that kept its pins follows the rotation: {}",
            describe(&e)
        )
    });
    let latest: BTreeMap<&str, (u64, &[u8])> = acked
        .iter()
        .map(|(n, v, value)| (n.as_str(), (*v, &value[..])))
        .collect();
    for (name, (version, value)) in latest {
        let got = reader
            .secret(name)
            .unwrap_or_else(|e| panic!("§12: {name}: {}", describe(&e)));
        assert_eq!((got.version(), got.expose()), (version, value));
    }
    applied
}

// ------------------------------------------------ two owners, one vault

fn rotate_until_applied(owner: &RawVault, generation: u32) -> u32 {
    for _ in 0..10 {
        match owner.rotate(&[]) {
            Ok(g) => {
                assert_eq!(g, generation + 1, "§8: one generation per rotation");
                return g;
            }
            Err(e) if kept_changing(&e) || e.code() == code::STALE_GENERATION => {
                owner.refresh().unwrap();
            }
            Err(e) => panic!("§8: a refreshed owner's rotation: {}", describe(&e)),
        }
    }
    panic!("§8: the refreshed owner never rotated");
}

/// Two owner handles (the same key, two connections) rotate at once, round
/// after round, while a token holder writes in the same round. Per round at
/// most one rotation applies; the other is refused as stale (or given up
/// after rebuilding), and applies once its handle refreshes. Both handles
/// then verify the same descriptor; the server's descriptor list is one
/// owner-signed chain from generation 1; a reader that kept its pins, and a
/// new handle given the pins from generation 1, both follow it without a
/// rollback error; nothing acknowledged is lost (§8, §12).
#[test]
fn two_owners_racing_to_rotate_agree_on_one_chain() {
    let server = start();
    check(8, (1usize..=3, 0usize..=2), |(rounds, per_round)| {
        let env = env(&server.url);
        let mut seeded = Acked::new();
        env.seed("ALPHA", b"seed", &mut seeded);
        env.seed("BRAVO", b"seed", &mut seeded);
        let acked = Mutex::new(seeded);
        let (a, b) = (env.owner_handle(), env.owner_handle());
        let reader_token = env.token(Scope::Read);
        let reader = env.vault(&reader_token);
        reader.secret("ALPHA").unwrap();
        let pins_at_generation_1 = reader.pins();
        let writer = env.vault(&env.token(Scope::Admin));
        let failures = Mutex::new(Vec::new());
        let mut generation = 1u32;
        for round in 0..rounds {
            let go = Barrier::new(3);
            let (ra, rb) = thread::scope(|race| {
                let ha = race.spawn(|| {
                    go.wait();
                    a.rotate(&[])
                });
                let hb = race.spawn(|| {
                    go.wait();
                    b.rotate(&[])
                });
                let hw = race.spawn(|| {
                    go.wait();
                    contained(&failures, || {
                        for k in 0..per_round {
                            let j = round * per_round + k;
                            let name = ["ALPHA", "BRAVO"][j % 2];
                            let value = format!("write {j}").into_bytes();
                            let version = write_acknowledged(&writer, name, &value);
                            acked
                                .lock()
                                .unwrap()
                                .push((name.to_owned(), version, value));
                        }
                    });
                });
                hw.join().unwrap();
                (ha.join().unwrap(), hb.join().unwrap())
            });
            let wins = u32::from(ra.is_ok()) + u32::from(rb.is_ok());
            assert!(
                wins <= 1,
                "§8: two rotations built on generation {generation} cannot both apply"
            );
            for r in [&ra, &rb] {
                match r {
                    Ok(g) => assert_eq!(*g, generation + 1, "§8"),
                    Err(e) => assert!(
                        e.code() == code::STALE_GENERATION || kept_changing(e),
                        "§8: the losing owner is refused as stale, not {}",
                        describe(e)
                    ),
                }
            }
            generation += wins;
            a.refresh().unwrap();
            b.refresh().unwrap();
            assert_eq!(
                a.descriptor(),
                b.descriptor(),
                "§8, §12: after a race both handles verify the same descriptor"
            );
            let loser = if ra.is_ok() { &b } else { &a };
            generation = rotate_until_applied(loser, generation);
            a.refresh().unwrap();
            b.refresh().unwrap();
            assert_eq!(a.descriptor(), b.descriptor(), "§8, §12");
            assert_eq!(a.descriptor().generation, generation, "§8");
            reader.refresh().unwrap_or_else(|e| {
                panic!("§12: a reader that kept its pins follows: {}", describe(&e))
            });
        }
        let failures = failures.into_inner().unwrap();
        assert!(failures.is_empty(), "{failures:?}");

        // The chain the server serves, verified from the pinned vault id.
        let owner_keys = env.key.owner();
        let chain = env
            .api
            .descriptors(Auth::Owner(&owner_keys), 0)
            .unwrap()
            .value
            .descriptors;
        assert_eq!(
            chain.len() as u32,
            generation,
            "§12: one descriptor per generation"
        );
        let mut prev: Option<Descriptor> = None;
        for signed in &chain {
            let d = signed
                .verify_for(&env.owner.vault_id(), &owner_keys.sign_pub())
                .unwrap();
            match &prev {
                None => assert!(d.is_first(), "§12: the chain starts at generation 1"),
                Some(p) => d
                    .check_follows(p)
                    .unwrap_or_else(|e| panic!("§12: an unbroken chain: {e}")),
            }
            prev = Some(d);
        }
        assert_eq!(prev.as_ref(), Some(&a.descriptor()), "§12");

        let late = env.vault(&reader_token);
        late.set_pins(pins_at_generation_1).unwrap_or_else(|e| {
            panic!(
                "§12: pins from generation 1 are an ancestor, not a rollback: {}",
                describe(&e)
            )
        });
        late.secret("ALPHA").unwrap();
        assert_nothing_lost(&env.fresh_owner(), &acked.into_inner().unwrap());
        Ok(())
    });
}

// ------------------------------------------------ racing config writes

/// Several `config-write` holders race, round after round, each writing
/// with the version it just read as the expectation (`If-Match`). Exactly
/// one write succeeds per version, as that version plus one; every loser is
/// refused and overwrites nothing; each round has a winner; the final
/// version is the seed plus the number of wins, and every winning body is in
/// the history at its version (§6).
#[test]
fn racing_config_writes_with_an_expected_version_never_overwrite() {
    let server = start();
    check(10, (2usize..=4, 1usize..=4), |(threads, rounds)| {
        let env = env(&server.url);
        let pre = env.owner.config_current("app").unwrap();
        let seed = env
            .owner
            .put_config("app", ConfigFormat::Toml, b"k = \"seed\"\n", pre)
            .unwrap();
        assert_eq!(seed, 1);
        let token = env.token(Scope::ConfigWrite);
        let vaults: Vec<Vault> = (0..threads).map(|_| env.vault(&token)).collect();
        let won: Mutex<Vec<(u64, u64, Vec<u8>)>> = Mutex::new(Vec::new());
        let lost = AtomicUsize::new(0);
        let unexpected: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let go = Barrier::new(threads);
        thread::scope(|s| {
            for (t, vault) in vaults.into_iter().enumerate() {
                let (go, won, lost, unexpected) = (&go, &won, &lost, &unexpected);
                s.spawn(move || {
                    for r in 0..rounds {
                        // Every thread reaches every barrier, whatever happens.
                        go.wait();
                        let expected = match vault.config("app") {
                            Ok(doc) => doc.version(),
                            Err(e) => {
                                unexpected.lock().unwrap().push(describe(&e));
                                continue;
                            }
                        };
                        let body = format!("k = \"thread {t}, round {r}\"\n").into_bytes();
                        let new = NewConfig::toml(body.clone()).expect_version(expected);
                        match vault.set_config("app", new) {
                            Ok(version) => won.lock().unwrap().push((expected, version, body)),
                            Err(e) if e.code() == code::CONFLICT => {
                                if !e.message().contains("nothing was overwritten") {
                                    unexpected.lock().unwrap().push(describe(&e));
                                }
                                lost.fetch_add(1, Ordering::SeqCst);
                                LOST_PRECONDITIONS.fetch_add(1, Ordering::Relaxed);
                            }
                            Err(e) => unexpected.lock().unwrap().push(describe(&e)),
                        }
                    }
                });
            }
        });
        let unexpected = unexpected.into_inner().unwrap();
        assert!(
            unexpected.is_empty(),
            "§6: unexpected refusals: {unexpected:?}"
        );
        let won = won.into_inner().unwrap();
        assert_eq!(
            won.len() + lost.load(Ordering::SeqCst),
            threads * rounds,
            "every attempt either won or was refused"
        );
        assert!(won.len() >= rounds, "§6: every round has a winner");
        let mut versions: Vec<u64> = won.iter().map(|w| w.1).collect();
        versions.sort_unstable();
        versions.dedup();
        assert_eq!(
            versions.len(),
            won.len(),
            "§6: exactly one write succeeds per version"
        );
        for (expected, version, _) in &won {
            assert_eq!(
                *version,
                expected + 1,
                "§6: a write under If-Match: v creates v + 1"
            );
        }
        let owner = env.fresh_owner();
        let last = 1 + won.len() as u64;
        assert_eq!(
            owner.config("app").unwrap().version(),
            last,
            "§6: the seed plus one version per acknowledged write"
        );
        let history: Vec<u64> = owner
            .config_history("app")
            .unwrap()
            .iter()
            .map(|m| m.version)
            .collect();
        assert_eq!(
            history,
            (1..=last).collect::<Vec<_>>(),
            "§6: no gap, nothing extra"
        );
        for (_, version, body) in &won {
            assert_eq!(
                owner.config_version("app", *version).unwrap().expose(),
                &body[..],
                "§6: the body acknowledged as version {version} is version {version}"
            );
        }
        Ok(())
    });
}
