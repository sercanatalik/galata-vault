//! gv-mcp against a real server on loopback, with real vaults and real
//! ciphertext built by the client crates (dev-dependencies only: the
//! shipped binary links no value-decryption code).

use std::io::{BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::Response;
use galata_vault_keys::{
    FullBundle, NodeKey, OwnerKeys, TokenKeys, seal_for_scope, seal_owner_bundle,
};
use galata_vault_mcp::{McpServer, config, open_all};
use galata_vault_proto::api::{CreateVaultRequest, RegisterTokenRequest, Scope};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{B64, Hash32};
use galata_vault_proto::mcp::{McpConfig, McpEntry};
use galata_vault_proto::sig::{SigActor, SigParams, SignedRequest};
use galata_vault_seal::Writer;
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, Clock, ServerConfig, router};
use galata_vault_store::{SqliteStore, Store, StoreConfig};

struct TestClock(AtomicI64);

impl Clock for TestClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct Seen {
    uri: String,
    /// The token id of a token-signed request.
    token: Option<String>,
}

#[derive(Clone)]
struct Spy(Arc<Mutex<Vec<Seen>>>);

async fn spy(State(spy): State<Spy>, req: Request, next: Next) -> Response {
    let token = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| SigParams::parse(v).ok())
        .and_then(|p| match p.actor {
            SigActor::Token(id) => Some(id.to_hex()),
            _ => None,
        });
    spy.0.lock().unwrap().push(Seen {
        uri: req.uri().to_string(),
        token,
    });
    next.run(req).await
}

struct Fixture {
    url: String,
    clock: Arc<TestClock>,
    spy: Spy,
    store: Arc<SqliteStore>,
    agent: ureq::Agent,
    dir: tempfile::TempDir,
}

/// A vault this test owns: its keys and generation 1's descriptor.
struct Owned {
    owner: OwnerKeys,
    full: FullBundle,
    descriptor: Descriptor,
}

fn real_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

impl Fixture {
    fn start() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
        let config = ServerConfig::for_database(&db);
        let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
        let clock = Arc::new(TestClock(AtomicI64::new(real_now())));
        let state = AppState::new(store.clone(), journal, config, clock.clone()).unwrap();
        let spy_state = Spy(Arc::default());
        let app = router(state).layer(middleware::from_fn_with_state(spy_state.clone(), spy));
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
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        Fixture {
            url: format!("http://{addr}"),
            clock,
            spy: spy_state,
            store,
            agent,
            dir,
        }
    }

    fn send(
        &self,
        method: &str,
        pq: &str,
        body: &[u8],
        headers: &[(&str, String)],
    ) -> (u16, serde_json::Value) {
        let url = format!("{}{pq}", self.url);
        let mut resp = match method {
            "GET" => {
                let mut rb = self.agent.get(&url);
                for (k, v) in headers {
                    rb = rb.header(*k, v.as_str());
                }
                rb.call()
            }
            _ => {
                let mut rb = if method == "PUT" {
                    self.agent.put(&url)
                } else {
                    self.agent.post(&url)
                };
                for (k, v) in headers {
                    rb = rb.header(*k, v.as_str());
                }
                rb.header("content-type", "application/json").send(body)
            }
        }
        .unwrap();
        let status = resp.status().as_u16();
        let bytes = resp.body_mut().read_to_vec().unwrap();
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        )
    }

    /// An owner-signed request; the signature covers the preconditions.
    fn signed(
        &self,
        owner: &OwnerKeys,
        method: &str,
        pq: &str,
        body: &[u8],
        extra: &[(&str, String)],
    ) -> (u16, serde_json::Value) {
        let header = |name: &str| {
            extra
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.as_str())
        };
        let request = SignedRequest {
            method,
            path_and_query: pq,
            body,
            if_match: header("if-match"),
            if_none_match: header("if-none-match"),
        };
        let sig = owner.sign_request(&request, self.clock.now());
        let mut headers = vec![("authorization", sig.to_header_value())];
        headers.extend(extra.iter().cloned());
        self.send(method, pq, body, &headers)
    }

    fn create_vault(&self) -> Owned {
        // The default server asks for no proof of work.
        let owner = NodeKey::generate().owner();
        let full = FullBundle::generate(1);
        let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), self.clock.now());
        let request = CreateVaultRequest::new(
            owner.vault_id(),
            owner.sign_pub(),
            owner.box_pub(),
            owner.sign_descriptor(&descriptor),
            seal_owner_bundle(&owner, &full).unwrap(),
        );
        let (status, body) = self.signed(
            &owner,
            "POST",
            "/v1/vaults",
            &serde_json::to_vec(&request).unwrap(),
            &[],
        );
        assert_eq!(status, 201, "{body}");
        Owned {
            owner,
            full,
            descriptor,
        }
    }

    /// Write a new secret, sealed and signed as the owner's client would.
    fn put(&self, v: &Owned, name: &str, value: &[u8]) {
        let writer = Writer {
            descriptor: &v.descriptor,
            name_key: &v.full.name_key,
            writer: &v.full.secret_writer,
        };
        let record = writer.secret(name, value, 1, self.clock.now()).unwrap();
        let body = serde_json::to_vec(&record.put_request().unwrap()).unwrap();
        let pq = format!("/v1/secrets/{}", record.name_hmac.to_hex());
        let (status, reply) = self.signed(
            &v.owner,
            "PUT",
            &pq,
            &body,
            &[("if-none-match", "*".into())],
        );
        assert_eq!(status, 201, "{reply}");
    }

    /// Register a token. `bundle_scope` decides what its bundle holds, which
    /// a misbehaving client could make differ from `scope`. Returns the
    /// server's status and the token.
    fn mint_as(&self, v: &Owned, scope: Scope, bundle_scope: Scope, ttl: u64) -> (u16, TokenKeys) {
        let t = TokenKeys::generate(v.owner.vault_id());
        let request = RegisterTokenRequest::new(
            t.id(),
            t.auth_pub(),
            t.box_pub(),
            scope,
            ttl,
            None,
            v.full.generation,
            seal_for_scope(&v.owner, &t.box_pub(), &t.id(), bundle_scope, &v.full).unwrap(),
        );
        let (status, _) = self.signed(
            &v.owner,
            "POST",
            "/v1/tokens",
            &serde_json::to_vec(&request).unwrap(),
            &[],
        );
        (status, t)
    }

    fn mint(&self, v: &Owned, scope: Scope) -> TokenKeys {
        let (status, t) = self.mint_as(v, scope, scope, 0);
        assert_eq!(status, 201);
        t
    }

    fn write_config(&self, entries: &[(&str, &TokenKeys)]) -> PathBuf {
        let config = McpConfig {
            env: entries
                .iter()
                .map(|(path, t)| McpEntry {
                    path: path.parse().unwrap(),
                    server: self.url.clone(),
                    token: t.token_string().to_string(),
                })
                .collect(),
        };
        let file = self.dir.path().join("mcp.toml");
        std::fs::write(&file, toml::to_string(&config).unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        file
    }

    fn clear_seen(&self) {
        self.spy.0.lock().unwrap().clear();
    }

    fn seen(&self) -> Vec<Seen> {
        self.spy.0.lock().unwrap().clone()
    }
}

/// `acme/staging` and `acme/prod`, each with shared and unshared names and a
/// meta token.
struct Project {
    f: Fixture,
    staging: TokenKeys,
    prod: TokenKeys,
    config: PathBuf,
}

fn project() -> Project {
    let f = Fixture::start();
    let s = f.create_vault();
    let p = f.create_vault();
    f.put(&s, "DATABASE_URL", b"postgres://staging-secret");
    f.put(&s, "DEBUG", b"1");
    f.put(&p, "DATABASE_URL", b"postgres://prod-secret");
    f.put(&p, "REDIS_URL", b"redis://prod-secret");
    let staging = f.mint(&s, Scope::Meta);
    let prod = f.mint(&p, Scope::Meta);
    let config = f.write_config(&[("acme/staging", &staging), ("acme/prod", &prod)]);
    Project {
        f,
        staging,
        prod,
        config,
    }
}

fn server(p: &Project) -> McpServer {
    McpServer::new(open_all(config::load(&p.config).unwrap()).unwrap())
}

#[test]
fn the_tool_list_is_exactly_four() {
    let mut names: Vec<String> = McpServer::tool_router()
        .list_all()
        .into_iter()
        .map(|t| t.name.to_string())
        .collect();
    names.sort();
    assert_eq!(names, ["audit", "diff_envs", "list_secrets", "status"]);
}

#[test]
fn tools_report_names_and_metadata_only() {
    let p = project();
    let s = server(&p);

    let list = s.list_secrets_json("acme/prod").unwrap();
    let names: Vec<&str> = list["secrets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["DATABASE_URL", "REDIS_URL"]);
    assert_eq!(list["secrets"][0]["version"], 1);
    assert!(list["secrets"][0]["size_bytes"].as_u64().unwrap() > 0);

    let audit = s.audit_json("acme/prod").unwrap();
    assert_eq!(audit["chain"], "verified");
    let text = audit.to_string();
    assert!(
        text.contains("secret_put") && text.contains("REDIS_URL"),
        "{text}"
    );

    let status = s.status_json("acme/staging").unwrap();
    assert_eq!(status["this_token"]["scope"], "meta");
    assert_eq!(status["this_token"]["id"], p.staging.id().to_hex());
    assert_eq!(status["generation"], 1);

    let err = s.list_secrets_json("acme/qa").unwrap_err();
    assert!(
        err.contains("acme/qa") && err.contains("acme/prod, acme/staging"),
        "{err}"
    );
}

#[test]
fn diff_compares_locally_from_independent_requests() {
    let p = project();
    let s = server(&p);
    p.f.clear_seen();
    let diff = s.diff_json("acme/staging", "acme/prod").unwrap();
    assert_eq!(
        diff["missing_from"]["acme/staging"],
        serde_json::json!(["REDIS_URL"])
    );
    assert_eq!(
        diff["missing_from"]["acme/prod"],
        serde_json::json!(["DEBUG"])
    );
    assert_eq!(diff["in_both"], serde_json::json!(["DATABASE_URL"]));

    let seen = p.f.seen();
    let tokens: std::collections::BTreeSet<_> =
        seen.iter().filter_map(|s| s.token.clone()).collect();
    assert_eq!(
        tokens,
        [p.staging.id().to_hex(), p.prod.id().to_hex()]
            .into_iter()
            .collect(),
        "each listing uses its own environment's token"
    );
    assert!(
        seen.iter().all(|s| s.uri.starts_with("/v1/secrets")),
        "{seen:?}"
    );
    assert!(
        seen.iter().all(|s| !s.uri.contains("acme")
            && !s.uri.contains("staging")
            && !s.uri.contains("prod")),
        "no path reaches the server: {seen:?}"
    );
}

#[test]
fn startup_refuses_anything_but_names_only_meta_tokens() {
    let f = Fixture::start();
    let v = f.create_vault();
    let meta = f.mint(&v, Scope::Meta);
    let read = f.mint(&v, Scope::Read);
    let file = f.write_config(&[("acme", &meta), ("acme/prod", &read)]);
    let err = format!(
        "{:#}",
        open_all(config::load(&file).unwrap()).err().unwrap()
    );
    assert!(
        err.contains("acme/prod")
            && err.contains(&read.id().to_hex())
            && err.contains("scope read"),
        "{err}"
    );

    // A config token decrypts configs: refused, whatever it could do.
    let config = f.mint(&v, Scope::Config);
    let file = f.write_config(&[("acme", &config)]);
    let err = format!(
        "{:#}",
        open_all(config::load(&file).unwrap()).err().unwrap()
    );
    assert!(err.contains("scope config"), "{err}");

    // A "meta" token whose bundle holds more: the owner's bundle signature
    // binds the scope, so the server refuses to register it at all (and
    // gv-mcp would refuse any bundle but the name key's, by kind).
    for bundle_scope in [Scope::Read, Scope::ConfigWrite] {
        let (status, _) = f.mint_as(&v, Scope::Meta, bundle_scope, 0);
        assert!((400..500).contains(&status), "{bundle_scope}: {status}");
    }

    // The binary exits non-zero before serving, naming the entry.
    let key = NodeKey::generate().encode();
    std::fs::write(
        &file,
        format!(
            "[[env]]\npath = \"acme/dev\"\nserver = \"{}\"\ntoken = \"{}\"\n",
            f.url,
            key.as_str()
        ),
    )
    .unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_gv-mcp"))
        .arg("--config")
        .arg(&file)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(out.stdout.is_empty(), "nothing on the protocol channel");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("acme/dev") && err.contains("node key") && !err.contains(&key[5..]),
        "{err}"
    );
}

#[test]
fn an_expired_token_is_reported_by_path_id_and_code_only() {
    let f = Fixture::start();
    let v = f.create_vault();
    let (status, t) = f.mint_as(&v, Scope::Meta, Scope::Meta, 60);
    assert_eq!(status, 201);
    let s = McpServer::new(
        open_all(config::load(&f.write_config(&[("acme/dev", &t)])).unwrap()).unwrap(),
    );
    // Past the token's expiry, but within the request-signature skew the
    // server checks first.
    f.clock.0.fetch_add(120, Ordering::SeqCst);
    let err = s.list_secrets_json("acme/dev").unwrap_err();
    assert!(
        err.contains("acme/dev") && err.contains(&t.id().to_hex()) && err.contains("token_expired"),
        "{err}"
    );
    assert!(!err.contains(t.token_string().as_str()));
}

#[test]
fn tool_output_never_carries_token_material_or_values() {
    let p = project();
    let s = server(&p);
    let mut outputs = vec![
        s.list_secrets_json("acme/prod").unwrap().to_string(),
        s.list_secrets_json("acme/staging").unwrap().to_string(),
        s.diff_json("acme/staging", "acme/prod")
            .unwrap()
            .to_string(),
        s.audit_json("acme/prod").unwrap().to_string(),
        s.status_json("acme/prod").unwrap().to_string(),
        s.list_secrets_json("acme/nope").unwrap_err(),
    ];
    p.f.clock.0.fetch_add(200 * 86_400, Ordering::SeqCst);
    outputs.push(s.status_json("acme/prod").unwrap_err());

    let bundles: Vec<String> = [&p.staging, &p.prod]
        .iter()
        .map(|t| {
            B64::encode_str(
                &p.f.store
                    .token_by_id(&t.id())
                    .unwrap()
                    .unwrap()
                    .bundle
                    .sealed
                    .0,
            )
        })
        .collect();
    for out in &outputs {
        assert!(!out.contains("gvt1_"), "{out}");
        assert!(!out.contains("-secret"), "no value plaintext: {out}");
        assert!(
            !out.contains("age-encryption.org"),
            "no value ciphertext: {out}"
        );
        for b in &bundles {
            assert!(!out.contains(&b[..24]), "no bundle bytes: {out}");
        }
    }
}

/// gv-mcp opens every vault before it serves anything, and its own HTTP
/// client waits up to `galata_vault_mcp::env::TIMEOUT` (60s) for each. A
/// test deadline shorter than the deadline of the thing under test turns a
/// slow open into a failure with the child still alive and silent, so the
/// startup budget here must exceed the child's own.
const STARTUP: Duration = Duration::from_secs(90);
/// Once it is serving, a metadata call is local work over an open pipe.
const REPLY: Duration = Duration::from_secs(20);

fn read_lines<R: std::io::Read + Send + 'static>(r: R) -> std::sync::mpsc::Receiver<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(r).lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Wait for the readiness line gv-mcp prints once every vault is open, so
/// the protocol exchange is never racing startup. Draining stderr also
/// keeps its pipe from filling if the binary ever grows chattier.
fn wait_until_serving(err: &std::sync::mpsc::Receiver<String>) {
    let deadline = std::time::Instant::now() + STARTUP;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match err.recv_timeout(left) {
            Ok(line) if line.contains("serving metadata") => return,
            // Another diagnostic: keep it for the failure message and read on.
            Ok(_) => continue,
            Err(e) => panic!("gv-mcp never reported itself serving: {e:?}"),
        }
    }
}

fn response_for(rx: &std::sync::mpsc::Receiver<String>, id: u64) -> serde_json::Value {
    loop {
        let line = rx.recv_timeout(REPLY).expect("gv-mcp answered");
        let v: serde_json::Value = serde_json::from_str(&line)
            .unwrap_or_else(|_| panic!("stdout carries only JSON-RPC: {line}"));
        if v["id"] == id {
            return v;
        }
    }
}

fn listening_sockets(pid: u32) -> Option<String> {
    let out = Command::new("lsof")
        .args(["-a", "-p", &pid.to_string(), "-iTCP", "-sTCP:LISTEN", "-Fn"])
        .output()
        .ok()?;
    Some(
        String::from_utf8_lossy(&out.stdout)
            .lines()
            .filter(|l| l.starts_with('n'))
            .collect(),
    )
}

#[test]
fn the_binary_speaks_mcp_on_stdio_and_listens_on_nothing() {
    let p = project();
    let mut child = Command::new(env!("CARGO_BIN_EXE_gv-mcp"))
        .arg("--config")
        .arg(&p.config)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let err = read_lines(child.stderr.take().unwrap());
    let rx = read_lines(child.stdout.take().unwrap());
    wait_until_serving(&err);
    let mut stdin = child.stdin.take().unwrap();
    let mut send = |v: serde_json::Value| {
        writeln!(stdin, "{v}").unwrap();
        stdin.flush().unwrap();
    };

    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"}}}),
    );
    let init = response_for(&rx, 1);
    assert_eq!(
        init["result"]["serverInfo"]["name"], "galata-vault",
        "{init}"
    );
    send(serde_json::json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));

    send(serde_json::json!({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}));
    let mut tools: Vec<String> = response_for(&rx, 2)["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap().to_owned())
        .collect();
    tools.sort();
    assert_eq!(tools, ["audit", "diff_envs", "list_secrets", "status"]);

    send(
        serde_json::json!({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {
        "name": "diff_envs", "arguments": {"path_a": "acme/staging", "path_b": "acme/prod"}}}),
    );
    let call = response_for(&rx, 3);
    let text = call["result"]["content"][0]["text"].as_str().unwrap();
    assert!(text.contains("REDIS_URL"), "{call}");
    assert_ne!(call["result"]["isError"], true);

    if let Some(listening) = listening_sockets(child.id()) {
        assert!(listening.is_empty(), "gv-mcp listens on {listening}");
    }
    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success(), "gv-mcp exits cleanly when stdin closes");
}
