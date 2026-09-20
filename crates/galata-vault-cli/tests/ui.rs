//! `gv ui` in-process against a real server on loopback, driven over HTTP as
//! a browser would, with its terminal and the clipboard stood in for.
//!
//! Projects are made with the real `gv` binary (a temporary GV_HOME and the
//! file credential store); the UI then opens the same home. Nothing here
//! touches the OS keychain, the real clipboard or the user's configuration.

#![cfg(feature = "ui")]

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::process::Output;
use std::sync::Arc;
use std::time::{Duration, Instant};

use galata_vault_cli::ui::{Clipboard, Timings, UiHandle, UiOptions};
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_store::{SqliteStore, StoreConfig};
use serde_json::{Value, json};

mod common;

struct Server {
    url: String,
    _dir: tempfile::TempDir,
}

impl Server {
    fn start() -> Server {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("vault.db");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).unwrap());
        let config = ServerConfig::for_database(&db);
        let journal = Arc::new(FileJournal::open(dir.path().join("journal")).unwrap());
        let app = router(AppState::new(store, journal, config, Arc::new(SystemClock)).unwrap());
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
            _dir: dir,
        }
    }
}

/// One user's machine: a home and a working directory.
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

    fn run(&self, args: &[&str], stdin: &[u8]) -> Output {
        common::gv(self.home.path(), self.work.path(), args, stdin, &[])
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

    fn init(&self, project: &str) {
        self.ok(&["init", project, "--server", &self.server], b"saved\n");
    }

    fn set(&self, env: &str, name: &str, value: &str) {
        self.ok(&["set", name, "--env", env], value.as_bytes());
    }

    fn generation(&self, env: &str) -> u32 {
        let out = self.ok(&["status", "--env", env], b"");
        let line = out.lines().find(|l| l.starts_with("generation")).unwrap();
        line.split_whitespace().last().unwrap().parse().unwrap()
    }

    fn ui(&self, clipboard: Clipboard, timings: Timings) -> UiHandle {
        galata_vault_cli::ui::start(UiOptions {
            home: Some(self.home.path().to_owned()),
            file_store: true,
            clipboard,
            timings,
        })
        .unwrap()
    }
}

/// A stand-in clipboard: a file, written from stdin and read back.
struct FakeClip {
    dir: tempfile::TempDir,
}

impl FakeClip {
    fn new() -> FakeClip {
        FakeClip {
            dir: tempfile::tempdir().unwrap(),
        }
    }

    fn file(&self) -> String {
        self.dir.path().join("clip").display().to_string()
    }

    fn clipboard(&self) -> Clipboard {
        let file = self.file();
        Clipboard::Commands {
            copy: vec!["/bin/sh".into(), "-c".into(), format!("cat > '{file}'")],
            paste: vec!["/bin/cat".into(), file],
        }
    }

    fn read(&self) -> String {
        std::fs::read_to_string(self.file()).unwrap_or_default()
    }
}

fn quick() -> Timings {
    Timings {
        code_lapse: Duration::from_secs(30),
        idle: Duration::from_secs(60),
        confirm_lapse: Duration::from_secs(30),
        clipboard_clear: Duration::from_millis(600),
        reveal: Duration::from_secs(10),
    }
}

/// Read the terminal until a line contains `needle`.
fn wait_feed(ui: &UiHandle, needle: &str) -> String {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        let line = ui
            .feed
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("the terminal never printed {needle:?}"));
        if line.contains(needle) {
            return line;
        }
    }
}

fn link_code(ui: &UiHandle) -> String {
    let line = wait_feed(ui, "/#c=");
    let at = line.find("/#c=").unwrap() + 4;
    line[at..].split_whitespace().next().unwrap().to_owned()
}

fn agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .build()
        .into()
}

struct Reply {
    status: u16,
    headers: ureq::http::HeaderMap,
    body: String,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or(Value::Null)
    }
}

/// Exchange a link's code for a session cookie, as the page script does.
fn exchange(origin: &str, code: &str, headers: &[(&str, &str)]) -> (u16, Option<String>) {
    let mut rb = agent()
        .post(format!("{origin}/session"))
        .header("Content-Type", "application/json");
    for (k, v) in headers {
        rb = rb.header(*k, *v);
    }
    let r = rb
        .send(serde_json::to_vec(&json!({ "code": code })).unwrap())
        .unwrap();
    let cookie = r
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    (r.status().as_u16(), cookie)
}

/// The page, as a browser holding the session cookie. Every body it
/// receives is kept, for the leak check.
struct Browser {
    origin: String,
    cookie: String,
    seen: Vec<(String, String)>,
}

impl Browser {
    fn open(ui: &UiHandle) -> Browser {
        let code = link_code(ui);
        let (status, cookie) = exchange(
            &ui.origin,
            &code,
            &[("Origin", &ui.origin), ("X-GV-UI", "1")],
        );
        assert_eq!(status, 200);
        Browser {
            origin: ui.origin.clone(),
            cookie: cookie.expect("a session cookie"),
            seen: Vec::new(),
        }
    }

    fn keep(&mut self, path: &str, mut r: ureq::http::Response<ureq::Body>) -> Reply {
        let body = r.body_mut().read_to_string().unwrap_or_default();
        self.seen.push((path.to_owned(), body.clone()));
        Reply {
            status: r.status().as_u16(),
            headers: r.headers().clone(),
            body,
        }
    }

    fn get(&mut self, path: &str) -> Reply {
        let r = agent()
            .get(format!("{}{path}", self.origin))
            .header("Cookie", &self.cookie)
            .call()
            .unwrap();
        self.keep(path, r)
    }

    fn post(&mut self, path: &str, body: Value) -> Reply {
        let r = agent()
            .post(format!("{}{path}", self.origin))
            .header("Cookie", &self.cookie)
            .header("Origin", &self.origin)
            .header("X-GV-UI", "1")
            .header("Content-Type", "application/json")
            .send(serde_json::to_vec(&body).unwrap())
            .unwrap();
        self.keep(path, r)
    }

    /// Poll a confirmation until the terminal has answered it.
    fn outcome(&mut self, id: u64) -> Value {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let s = self.get(&format!("/api/confirm/{id}")).json();
            if s["state"] != "waiting" || Instant::now() > deadline {
                return s;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

fn raw(host: &str, request: &str) -> String {
    let mut s = TcpStream::connect(host).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out
}

#[test]
fn a_full_session_leaks_no_key_and_shows_values_only_when_revealed() {
    let server = Server::start();
    let gv = Gv::new(&server);
    gv.init("acme");
    gv.ok(&["env", "add", "acme/dev"], b"");
    gv.ok(&["env", "add", "acme/prod"], b"");
    let dev_value = "postgres://dev-only-value";
    let shared = "same-in-both-7c1f";
    let prod_only = "prod-only-value-9a2e";
    gv.set("acme/dev", "DATABASE_URL", dev_value);
    gv.set("acme/dev", "SHARED_TOKEN", shared);
    gv.set("acme/prod", "SHARED_TOKEN", shared);
    gv.set("acme/prod", "PROD_ONLY", prod_only);

    let clip = FakeClip::new();
    let ui = gv.ui(clip.clipboard(), quick());
    let mut b = Browser::open(&ui);

    let r = b.get("/projects");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("acme/dev") && r.body.contains("acme/prod"));

    let r = b.get("/e/acme/dev/secrets");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("DATABASE_URL") && r.body.contains("SHARED_TOKEN"));

    let r = b.post(
        "/api/reveal",
        json!({ "env": "acme/dev", "name": "DATABASE_URL" }),
    );
    assert_eq!(r.status, 200);
    assert_eq!(r.json()["value"], dev_value);
    assert_eq!(r.headers.get("cache-control").unwrap(), "no-store");
    let line = wait_feed(&ui, "reveal");
    assert!(line.contains("acme/dev") && line.contains("DATABASE_URL"));
    assert!(!line.contains(dev_value));

    let r = b.post(
        "/api/copy",
        json!({ "env": "acme/dev", "name": "DATABASE_URL" }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    assert_eq!(clip.read(), dev_value);

    let r = b.get("/e/acme/dev/compare?with=acme%2Fprod");
    assert_eq!(r.status, 200, "{}", r.body);
    assert!(r.body.contains("same value in both"));
    assert!(r.body.contains("PROD_ONLY"));

    let r = b.get("/e/acme/dev/secrets?name=DATABASE_URL");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("every version kept"));

    let r = b.get("/e/acme/dev/audit");
    assert_eq!(r.status, 200);
    assert!(r.body.contains("chain verified"), "{}", r.body);
    let r = b.get("/e/acme/dev/audit");
    assert!(r.body.contains("it extends the head this machine stored"));

    // A token, confirmed in the terminal and handed over to a file.
    let r = b.post(
        "/api/mint",
        json!({ "env": "acme/dev", "scope": "read", "ttl": "7d" }),
    );
    assert_eq!(r.status, 202, "{}", r.body);
    let code = r.json()["code"].as_str().unwrap().to_owned();
    let id = r.json()["confirm"].as_u64().unwrap();
    let prompt = wait_feed(&ui, "code ");
    assert!(prompt.contains(&code), "{prompt}");
    assert_eq!(
        b.get(&format!("/api/confirm/{id}")).json()["state"],
        "waiting"
    );
    ui.terminal.send("y".into()).unwrap();
    assert_eq!(b.outcome(id)["state"], "handover");
    let file = gv.work.path().join("capture.token");
    let r = b.post(
        "/api/handover/save",
        json!({ "confirm": id, "path": file.display().to_string() }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let saved = std::fs::read_to_string(&file).unwrap();
    assert!(saved.starts_with("gvt1_"));
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
    // Exactly once.
    let r = b.post("/api/handover/copy", json!({ "confirm": id }));
    assert_eq!(r.status, 400);

    // Nothing the page received holds a key or a token, and a value only
    // ever arrived in answer to a reveal.
    for (path, body) in &b.seen {
        assert!(!body.contains("gvk1_"), "{path} carried a key");
        assert!(!body.contains("gvt1_"), "{path} carried a token");
        for v in [dev_value, shared, prod_only] {
            assert!(
                !body.contains(v) || path == "/api/reveal",
                "{path} carried a value"
            );
        }
    }
}

#[test]
fn every_request_is_checked_and_every_response_hardened() {
    let server = Server::start();
    let gv = Gv::new(&server);
    gv.init("acme");
    gv.set("acme", "API_KEY", "v1");
    let ui = gv.ui(Clipboard::Off, quick());
    let origin = ui.origin.clone();
    let host = origin.trim_start_matches("http://").to_owned();
    let port = host.rsplit(':').next().unwrap().to_owned();
    let code = link_code(&ui);

    // DNS rebinding: another name, resolving here, is refused first.
    let out = raw(
        &host,
        &format!(
            "GET /projects HTTP/1.1\r\nHost: attacker.example:{port}\r\nConnection: close\r\n\r\n"
        ),
    );
    assert!(out.starts_with("HTTP/1.1 421"), "{out}");
    assert!(!out.contains("acme"));

    // The exchange itself needs the page's origin and header.
    assert_eq!(exchange(&origin, &code, &[("Origin", &origin)]).0, 403);
    assert_eq!(
        exchange(
            &origin,
            &code,
            &[("Origin", "http://evil.example"), ("X-GV-UI", "1")]
        )
        .0,
        403
    );
    let (status, cookie) = exchange(&origin, &code, &[("Origin", &origin), ("X-GV-UI", "1")]);
    assert_eq!(status, 200);
    let cookie = cookie.unwrap();
    // A link opens one session, once.
    assert_eq!(
        exchange(&origin, &code, &[("Origin", &origin), ("X-GV-UI", "1")]).0,
        410
    );

    let mut b = Browser {
        origin: origin.clone(),
        cookie,
        seen: Vec::new(),
    };
    for path in [
        "/projects",
        "/assets/app.css",
        "/api/ping",
        "/nope",
        "/e/acme/secrets",
    ] {
        let r = b.get(path);
        let h = |k: &str| r.headers.get(k).map(|v| v.to_str().unwrap().to_owned());
        assert!(
            h("content-security-policy")
                .unwrap()
                .starts_with("default-src 'none'; script-src 'self'"),
            "{path}"
        );
        assert_eq!(h("cache-control").as_deref(), Some("no-store"), "{path}");
        assert_eq!(h("x-content-type-options").as_deref(), Some("nosniff"));
        assert_eq!(h("referrer-policy").as_deref(), Some("no-referrer"));
        assert_eq!(h("x-frame-options").as_deref(), Some("DENY"));
    }
    let page = b.get("/e/acme/secrets").body;
    assert!(!page.contains("<script>") && !page.contains(" style="));

    // A URL may carry no value.
    assert_eq!(b.get("/e/acme/secrets?value=hunter2").status, 400);
    // A same-origin change without the header is refused.
    let r = agent()
        .post(format!("{origin}/api/set"))
        .header("Cookie", &b.cookie)
        .header("Origin", &origin)
        .header("Content-Type", "application/json")
        .send(serde_json::to_vec(&json!({ "env": "acme", "name": "X", "value": "y" })).unwrap())
        .unwrap();
    assert_eq!(r.status().as_u16(), 403);

    // A name shaped like markup is shown as text.
    let r = b.post(
        "/api/set",
        json!({ "env": "acme", "name": "<b>bold</b>", "value": "v" }),
    );
    assert_eq!(r.status, 200, "{}", r.body);
    let page = b.get("/e/acme/secrets").body;
    assert!(page.contains("&lt;b&gt;bold&lt;/b&gt;") && !page.contains("<b>bold</b>"));

    // A lost race is reported, never overwritten.
    let r = b.post(
        "/api/set",
        json!({ "env": "acme", "name": "API_KEY", "value": "v2", "expected": 7 }),
    );
    assert_eq!(r.status, 409, "{}", r.body);
    assert_eq!(gv.ok(&["get", "API_KEY", "--env", "acme"], b""), "v1");

    // Enter prints a new link, and the old session ends.
    ui.terminal.send(String::new()).unwrap();
    wait_feed(&ui, "/#c=");
    let r = b.get("/projects");
    assert_eq!(r.status, 401);
    assert!(r.body.contains("locked"));
    assert_eq!(b.post("/api/ping", json!({})).status, 401);
}

#[test]
fn an_idle_session_locks() {
    let server = Server::start();
    let gv = Gv::new(&server);
    gv.init("acme");
    let ui = gv.ui(
        Clipboard::Off,
        Timings {
            idle: Duration::from_millis(400),
            ..quick()
        },
    );
    let mut b = Browser::open(&ui);
    assert_eq!(b.get("/projects").status, 200);
    std::thread::sleep(Duration::from_millis(900));
    assert_eq!(b.get("/projects").status, 401);
    wait_feed(&ui, "locked after idle");
}

#[test]
fn changes_that_matter_wait_for_the_terminal() {
    let server = Server::start();
    let gv = Gv::new(&server);
    gv.init("acme");
    let ui = gv.ui(
        Clipboard::Off,
        Timings {
            confirm_lapse: Duration::from_millis(700),
            ..quick()
        },
    );
    let mut b = Browser::open(&ui);
    let mint = json!({ "env": "acme", "scope": "read" });

    // Nobody answers: nothing is minted.
    let id = b.post("/api/mint", mint.clone()).json()["confirm"]
        .as_u64()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(b.outcome(id)["state"], "lapsed");
    assert_eq!(gv.ok(&["token", "ls", "--env", "acme"], b""), "");

    // n cancels.
    let id = b.post("/api/mint", mint.clone()).json()["confirm"]
        .as_u64()
        .unwrap();
    wait_feed(&ui, "[y/N]");
    ui.terminal.send("n".into()).unwrap();
    assert_eq!(b.outcome(id)["state"], "cancelled");

    // One at a time.
    let first = b.post("/api/mint", mint.clone()).json()["confirm"]
        .as_u64()
        .unwrap();
    let r = b.post("/api/rotate", json!({ "env": "acme" }));
    assert_eq!(r.status, 409);
    wait_feed(&ui, "[y/N]");
    ui.terminal.send("y".into()).unwrap();
    assert_eq!(b.outcome(first)["state"], "handover");
    b.post("/api/handover/discard", json!({ "confirm": first }));

    // Revoking a read token rotates in the same step.
    let before = gv.generation("acme");
    let listed = gv.ok(&["token", "ls", "--env", "acme"], b"");
    let token = listed.split_whitespace().next().unwrap().to_owned();
    let id = b
        .post("/api/revoke", json!({ "env": "acme", "id": token }))
        .json()["confirm"]
        .as_u64()
        .unwrap();
    assert!(wait_feed(&ui, "and rotate acme").contains("sign nothing"));
    ui.terminal.send("y".into()).unwrap();
    let done = b.outcome(id);
    assert_eq!(done["state"], "done", "{done}");
    assert_eq!(gv.generation("acme"), before + 1);
    assert_eq!(gv.ok(&["token", "ls", "--env", "acme"], b""), "");

    // Environments: made from the page, deleted through the terminal.
    let r = b.post("/api/env/add", json!({ "path": "acme/qa" }));
    assert_eq!(r.status, 200, "{}", r.body);
    let id = b
        .post("/api/env/delete", json!({ "path": "acme/qa" }))
        .json()["confirm"]
        .as_u64()
        .unwrap();
    wait_feed(&ui, "[y/N]");
    ui.terminal.send("y".into()).unwrap();
    assert_eq!(b.outcome(id)["state"], "done");
    assert!(!gv.ok(&["env", "ls"], b"").contains("acme/qa"));

    // The session ending cancels what is pending.
    b.post("/api/mint", mint);
    wait_feed(&ui, "[y/N]");
    b.post("/api/lock", json!({}));
    wait_feed(&ui, "the request was cancelled");
}

#[test]
fn the_clipboard_is_cleared_only_while_it_holds_the_value() {
    let server = Server::start();
    let gv = Gv::new(&server);
    gv.init("acme");
    gv.set("acme", "API_KEY", "the-value");
    let clip = FakeClip::new();
    let mut ui = gv.ui(clip.clipboard(), quick());
    let mut b = Browser::open(&ui);
    let copy = json!({ "env": "acme", "name": "API_KEY" });

    let r = b.post("/api/copy", copy.clone());
    assert!(!r.body.contains("the-value"));
    assert_eq!(clip.read(), "the-value");
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(clip.read(), "");

    // Something copied since stays.
    b.post("/api/copy", copy.clone());
    std::fs::write(clip.file(), "something else").unwrap();
    std::thread::sleep(Duration::from_millis(1200));
    assert_eq!(clip.read(), "something else");

    // Stopping clears what is still due.
    b.post("/api/copy", copy);
    ui.stop();
    assert_eq!(clip.read(), "");
}

#[test]
fn gv_ui_needs_a_terminal() {
    let server = Server::start();
    let gv = Gv::new(&server);
    let out = gv.run(&["ui", "--no-open"], b"");
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("needs a terminal"));
}
