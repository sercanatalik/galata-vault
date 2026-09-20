//! A malicious server for tests: a
//! real in-process gv-server behind a scriptable proxy on `127.0.0.1`.
//!
//! The proxy sees every request and every response, as an operator, a
//! request log, a TLS terminator or a process squatting the port would. It
//! can:
//! - log every request, headers and body ([`Adversary::log`]);
//! - replay a logged request, or send one of its own ([`Adversary::replay`],
//!   [`Adversary::send`]);
//! - rewrite a response body before the client sees it
//!   ([`Adversary::rewrite`], [`Adversary::rewrite_as`]), which is also how
//!   it injects records built from material it holds;
//! - capture a genuine response and serve it again later
//!   ([`Adversary::record`], [`Adversary::serve_recorded`]);
//! - answer in the server's place ([`Adversary::respond`]).
//!
//! What it must not be able to do is what the protocol promises: make a
//! client accept a key, bundle, descriptor, record or children record that
//! the key it pinned did not sign, or decrypt anything from what it saw.
//! The scenarios that check this live with each client's tests.
//!
//! Deterministic: rules apply in the order they were added, the first match
//! wins, and nothing is random except the keys the tests generate.
//!
//! Tests in other languages drive the `gv-adversary` binary, which serves
//! the same proxy with a JSON control API under `/__adversary/` (see
//! [`Adversary::start_controlled`]).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::Response;
use galata_vault_proto::ids::{B64, TokenId};
use galata_vault_proto::sig::{SigActor, SigParams};
use galata_vault_server::journal::FileJournal;
use galata_vault_server::{AppState, ServerConfig, SystemClock, router};
use galata_vault_store::{SqliteStore, StoreConfig};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Where the control API lives, when it is on.
const CONTROL: &str = "/__adversary/";

/// One request as the proxy saw it.
#[derive(Debug, Clone)]
pub struct Logged {
    pub method: String,
    /// The path and query, as sent.
    pub path: String,
    /// Lower-case names, in arrival order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Logged {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Who signed it, if it carries a valid-looking `GV-Sig` header.
    pub fn actor(&self) -> Option<SigActor> {
        SigParams::parse(self.header("authorization")?)
            .ok()
            .map(|p| p.actor)
    }

    /// Every byte an eavesdropper saw of this request: the request line, the
    /// headers and the body.
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = format!("{} {}\n", self.method, self.path).into_bytes();
        for (k, v) in &self.headers {
            out.extend_from_slice(format!("{k}: {v}\n").as_bytes());
        }
        out.push(b'\n');
        out.extend_from_slice(&self.body);
        out
    }
}

/// Which path a [`Matcher`] selects.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PathMatch {
    /// This path exactly, whatever the query.
    Exact(String),
    /// Every path starting with this.
    Prefix(String),
}

/// Which requests a rule or a recording applies to.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Matcher {
    pub method: String,
    pub path: PathMatch,
    /// Only requests signed by this token; `None` for any caller.
    pub token: Option<TokenId>,
}

impl Matcher {
    /// `method` on exactly `path` (the query is ignored), from any caller.
    fn exact(method: &str, path: &str) -> Matcher {
        Matcher {
            method: method.to_owned(),
            path: PathMatch::Exact(path.to_owned()),
            token: None,
        }
    }

    /// `GET` on exactly `path`.
    pub fn get(path: &str) -> Matcher {
        Matcher::exact("GET", path)
    }

    /// `method` on every path starting with `prefix`.
    pub fn prefix(method: &str, prefix: &str) -> Matcher {
        Matcher {
            method: method.to_owned(),
            path: PathMatch::Prefix(prefix.to_owned()),
            token: None,
        }
    }

    /// Only requests signed by `token`.
    pub fn by(mut self, token: TokenId) -> Matcher {
        self.token = Some(token);
        self
    }

    fn matches(&self, method: &str, path: &str, token: Option<TokenId>) -> bool {
        self.method.eq_ignore_ascii_case(method)
            && match &self.path {
                PathMatch::Exact(p) => p == path,
                PathMatch::Prefix(p) => path.starts_with(p.as_str()),
            }
            && self.token.is_none_or(|t| Some(t) == token)
    }
}

type Edit = Arc<dyn Fn(&mut Value) + Send + Sync>;

#[derive(Clone)]
enum Action {
    /// Forward, then edit the JSON body the server answered.
    Rewrite(Edit),
    /// Answer in the server's place; the server never sees the request.
    Respond { status: u16, body: Vec<u8> },
}

#[derive(Default)]
struct Script {
    /// Serve the control API under [`CONTROL`].
    control: bool,
    log: Vec<Logged>,
    rules: Vec<(Matcher, Action)>,
    /// Capture the next genuine response to each of these.
    recording: Vec<Matcher>,
    recorded: HashMap<Matcher, (u16, Vec<u8>)>,
}

/// A real gv-server, and the malicious proxy in front of it.
pub struct Adversary {
    url: String,
    script: Arc<Mutex<Script>>,
    agent: ureq::Agent,
    _dir: tempfile::TempDir,
}

fn lock(script: &Mutex<Script>) -> MutexGuard<'_, Script> {
    script.lock().unwrap_or_else(|e| e.into_inner())
}

fn json_response(status: u16, body: Vec<u8>) -> Response {
    let mut response = Response::new(Body::from(body));
    *response.status_mut() =
        axum::http::StatusCode::from_u16(status).unwrap_or(axum::http::StatusCode::OK);
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
}

/// A [`Matcher`], as the control API takes it: `{"method", "path",
/// "prefix": false, "token": "<token id hex>" | null}`.
#[derive(Deserialize)]
struct MatchSpec {
    method: String,
    path: String,
    #[serde(default)]
    prefix: bool,
    #[serde(default)]
    token: Option<String>,
}

impl MatchSpec {
    fn matcher(self) -> Result<Matcher, String> {
        let m = if self.prefix {
            Matcher::prefix(&self.method, &self.path)
        } else {
            Matcher::exact(&self.method, &self.path)
        };
        match self.token {
            None => Ok(m),
            Some(hex) => TokenId::from_hex(&hex)
                .map(|t| m.by(t))
                .map_err(|_| "token: a token id is 32 hex digits".to_owned()),
        }
    }
}

/// One control request. `set` replaces the values at JSON pointers (`""` is
/// the whole body); `flip` changes one byte of the base64 value at a pointer.
#[derive(Deserialize)]
struct Command {
    #[serde(rename = "match")]
    matcher: Option<MatchSpec>,
    #[serde(default)]
    set: Vec<(String, Value)>,
    #[serde(default)]
    flip: Vec<(String, usize)>,
}

/// Change byte `at` of the base64 value at `pointer`, if there is one.
fn flip_b64(v: &mut Value, pointer: &str, at: usize) {
    let Some(slot) = v.pointer_mut(pointer) else {
        return;
    };
    let Ok(mut b) = serde_json::from_value::<B64>(slot.clone()) else {
        return;
    };
    if let Some(byte) = b.0.get_mut(at) {
        *byte ^= 0x5a;
        *slot = serde_json::to_value(&b).expect("base64 serializes");
    }
}

fn reply(status: u16, v: Value) -> Response {
    json_response(status, serde_json::to_vec(&v).expect("JSON serializes"))
}

/// The control API, for tests outside Rust:
/// - `GET log`: every request so far, `{method, path, headers, body}`;
/// - `POST clear` (rules), `POST clear_log`;
/// - `POST rewrite {match, set, flip}`;
/// - `POST record {match}`, `POST recorded {match}` (`{status, body}`),
///   `POST serve_recorded {match}`.
fn control(script: &Mutex<Script>, method: &str, what: &str, body: &[u8]) -> Response {
    if method == "GET" && what == "log" {
        let log: Vec<Value> = lock(script)
            .log
            .iter()
            .map(|l| {
                json!({
                    "method": l.method,
                    "path": l.path,
                    "headers": l.headers,
                    "body": String::from_utf8_lossy(&l.body),
                })
            })
            .collect();
        return reply(200, Value::Array(log));
    }
    let body = if body.is_empty() { b"{}" } else { body };
    let cmd: Command = match serde_json::from_slice(body) {
        Ok(c) => c,
        Err(e) => return reply(400, json!({ "error": e.to_string() })),
    };
    let matcher = match cmd.matcher.map(MatchSpec::matcher).transpose() {
        Ok(m) => m,
        Err(e) => return reply(400, json!({ "error": e })),
    };
    let mut s = lock(script);
    match (what, matcher) {
        ("clear", _) => s.rules.clear(),
        ("clear_log", _) => s.log.clear(),
        ("rewrite", Some(m)) => {
            let (set, flip) = (cmd.set, cmd.flip);
            let edit = move |v: &mut Value| {
                for (pointer, value) in &set {
                    if let Some(slot) = v.pointer_mut(pointer) {
                        *slot = value.clone();
                    }
                }
                for (pointer, at) in &flip {
                    flip_b64(v, pointer, *at);
                }
            };
            s.rules.push((m, Action::Rewrite(Arc::new(edit))));
        }
        ("record", Some(m)) => s.recording.push(m),
        ("recorded", Some(m)) => {
            return match s.recorded.get(&m) {
                Some((status, body)) => reply(
                    200,
                    json!({
                        "status": status,
                        "body": serde_json::from_slice::<Value>(body).unwrap_or(Value::Null),
                    }),
                ),
                None => reply(404, json!({ "error": "nothing recorded for this match" })),
            };
        }
        ("serve_recorded", Some(m)) => {
            let Some((status, body)) = s.recorded.get(&m).cloned() else {
                return reply(404, json!({ "error": "nothing recorded for this match" }));
            };
            s.rules.push((m, Action::Respond { status, body }));
        }
        _ => {
            return reply(
                404,
                json!({ "error": format!("no control {method} {what}") }),
            );
        }
    }
    reply(200, json!({ "ok": true }))
}

async fn proxy(script: Arc<Mutex<Script>>, req: Request, next: Next) -> Response {
    let (parts, body) = req.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default();
    if let Some(what) = parts.uri.path().strip_prefix(CONTROL)
        && lock(&script).control
    {
        return control(&script, parts.method.as_str(), what, &bytes);
    }
    let logged = Logged {
        method: parts.method.as_str().to_owned(),
        path: parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path().to_owned(), |pq| pq.as_str().to_owned()),
        headers: parts
            .headers
            .iter()
            .map(|(k, v)| {
                (
                    k.as_str().to_ascii_lowercase(),
                    String::from_utf8_lossy(v.as_bytes()).into_owned(),
                )
            })
            .collect(),
        body: bytes.to_vec(),
    };
    let token = match logged.actor() {
        Some(SigActor::Token(id)) => Some(id),
        _ => None,
    };
    let (method, path) = (
        parts.method.as_str().to_owned(),
        parts.uri.path().to_owned(),
    );
    let (action, record) = {
        let mut s = lock(&script);
        s.log.push(logged);
        let action = s
            .rules
            .iter()
            .find(|(m, _)| m.matches(&method, &path, token))
            .map(|(_, a)| a.clone());
        let record = s
            .recording
            .iter()
            .position(|m| m.matches(&method, &path, token))
            .map(|i| s.recording.remove(i));
        (action, record)
    };

    if let Some(Action::Respond { status, body }) = action {
        return json_response(status, body);
    }

    let response = next
        .run(Request::from_parts(parts, Body::from(bytes)))
        .await;
    let (mut parts, body) = response.into_parts();
    let mut body = axum::body::to_bytes(body, usize::MAX)
        .await
        .unwrap_or_default()
        .to_vec();
    if let Some(m) = record {
        lock(&script)
            .recorded
            .insert(m, (parts.status.as_u16(), body.clone()));
    }
    if let Some(Action::Rewrite(edit)) = action
        && let Ok(mut v) = serde_json::from_slice::<Value>(&body)
    {
        edit(&mut v);
        body = serde_json::to_vec(&v).expect("a JSON value serializes");
        parts.headers.remove(header::CONTENT_LENGTH);
    }
    Response::from_parts(parts, Body::from(body))
}

impl Adversary {
    /// A fresh server (temporary SQLite store, file journal, low proof-of-work,
    /// no effective rate limits) behind the proxy, on a random loopback port.
    pub fn start() -> Adversary {
        Adversary::start_with(false)
    }

    /// As [`Adversary::start`], with the JSON control API served under
    /// `/__adversary/` (never logged, never forwarded): what the
    /// `gv-adversary` binary runs for tests in other languages.
    pub fn start_controlled() -> Adversary {
        Adversary::start_with(true)
    }

    fn start_with(control: bool) -> Adversary {
        let dir = tempfile::tempdir().expect("a temporary directory");
        let db = dir.path().join("vault.db");
        let store = Arc::new(SqliteStore::open(StoreConfig::new(&db)).expect("the store opens"));
        let config = ServerConfig::for_database(&db);
        let journal =
            Arc::new(FileJournal::open(dir.path().join("journal")).expect("the journal opens"));
        let state = AppState::new(store, journal, config, Arc::new(SystemClock))
            .expect("the server state opens");
        let script = Arc::new(Mutex::new(Script {
            control,
            ..Script::default()
        }));
        let shared = script.clone();
        let app = router(state).layer(axum::middleware::from_fn(
            move |req: Request, next: Next| proxy(shared.clone(), req, next),
        ));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
        listener
            .set_nonblocking(true)
            .expect("a non-blocking listener");
        let addr = listener.local_addr().expect("a local address");
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("a runtime");
            rt.block_on(async move {
                let listener =
                    tokio::net::TcpListener::from_std(listener).expect("a tokio listener");
                axum::serve(
                    listener,
                    app.into_make_service_with_connect_info::<SocketAddr>(),
                )
                .await
                .expect("the server runs");
            });
        });
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build()
            .into();
        Adversary {
            url: format!("http://{addr}"),
            script,
            agent,
            _dir: dir,
        }
    }

    /// Where clients connect: the proxy.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Every request so far, oldest first.
    pub fn log(&self) -> Vec<Logged> {
        lock(&self.script).log.clone()
    }

    pub fn clear_log(&self) {
        lock(&self.script).log.clear();
    }

    /// From now on, edit the JSON body of every response to `m`.
    pub fn rewrite(&self, m: Matcher, edit: impl Fn(&mut Value) + Send + Sync + 'static) {
        lock(&self.script)
            .rules
            .push((m, Action::Rewrite(Arc::new(edit))));
    }

    /// As [`Adversary::rewrite`], on the body parsed as `T` (bodies that do
    /// not parse as `T`, such as errors, pass unchanged).
    pub fn rewrite_as<T>(&self, m: Matcher, edit: impl Fn(&mut T) + Send + Sync + 'static)
    where
        T: Serialize + DeserializeOwned,
    {
        self.rewrite(m, move |v| {
            if let Ok(mut t) = serde_json::from_value::<T>(v.clone()) {
                edit(&mut t);
                *v = serde_json::to_value(&t).expect("a wire type serializes");
            }
        });
    }

    /// From now on, answer `m` with `body` without asking the server.
    pub fn respond(&self, m: Matcher, status: u16, body: &impl Serialize) {
        let body = serde_json::to_vec(body).expect("a body serializes");
        lock(&self.script)
            .rules
            .push((m, Action::Respond { status, body }));
    }

    /// Capture the next genuine response to `m` (once).
    pub fn record(&self, m: Matcher) {
        lock(&self.script).recording.push(m);
    }

    /// The response captured for `m`, if any: status and body.
    pub fn recorded(&self, m: &Matcher) -> Option<(u16, Vec<u8>)> {
        lock(&self.script).recorded.get(m).cloned()
    }

    /// The captured response for `m`, parsed as `T`.
    pub fn recorded_as<T: DeserializeOwned>(&self, m: &Matcher) -> T {
        let (_, body) = self
            .recorded(m)
            .expect("a response was recorded for this matcher");
        serde_json::from_slice(&body).expect("the recorded body parses")
    }

    /// From now on, answer `m` with the response captured for it earlier:
    /// a stale answer, genuinely signed.
    pub fn serve_recorded(&self, m: Matcher) {
        let (status, body) = self
            .recorded(&m)
            .expect("a response was recorded for this matcher");
        lock(&self.script)
            .rules
            .push((m, Action::Respond { status, body }));
    }

    /// Drop every rule; the proxy forwards faithfully again.
    pub fn clear_rules(&self) {
        lock(&self.script).rules.clear();
    }

    /// Send a logged request again, byte for byte.
    pub fn replay(&self, logged: &Logged) -> (u16, Value) {
        let headers: Vec<(&str, &str)> = logged
            .headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        self.send(&logged.method, &logged.path, &headers, &logged.body)
    }

    /// Send a request of the attacker's own making, through the proxy (so it
    /// is logged too). Returns the status and the JSON body (`Null` if none).
    pub fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(&str, &str)],
        body: &[u8],
    ) -> (u16, Value) {
        const SKIP: [&str; 7] = [
            "host",
            "content-length",
            "transfer-encoding",
            "connection",
            "user-agent",
            "accept",
            "accept-encoding",
        ];
        fn with<B>(
            mut rb: ureq::RequestBuilder<B>,
            headers: &[(&str, &str)],
        ) -> ureq::RequestBuilder<B> {
            for (k, v) in headers {
                if !SKIP.contains(&k.to_ascii_lowercase().as_str()) {
                    rb = rb.header(*k, *v);
                }
            }
            rb
        }
        let url = format!("{}{}", self.url, path);
        let a = &self.agent;
        let result = match method {
            "GET" => with(a.get(&url), headers).call(),
            "DELETE" if body.is_empty() => with(a.delete(&url), headers).call(),
            "DELETE" => with(a.delete(&url).force_send_body(), headers).send(body),
            "POST" => with(a.post(&url), headers).send(body),
            "PUT" => with(a.put(&url), headers).send(body),
            other => panic!("the adversary sends no {other} requests"),
        };
        let mut response = result.expect("the proxy answers");
        let status = response.status().as_u16();
        let bytes = response.body_mut().read_to_vec().expect("the body reads");
        (
            status,
            serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matchers_select_by_method_path_and_token() {
        let t = TokenId([1; 16]);
        let m = Matcher::get("/v1/vault").by(t);
        assert!(m.matches("GET", "/v1/vault", Some(t)));
        assert!(!m.matches("GET", "/v1/vault", None));
        assert!(!m.matches("GET", "/v1/vault", Some(TokenId([2; 16]))));
        assert!(!m.matches("PUT", "/v1/vault", Some(t)));
        assert!(!m.matches("GET", "/v1/vault/children", Some(t)));
        let p = Matcher::prefix("GET", "/v1/secrets/");
        assert!(p.matches("GET", "/v1/secrets/ab", None));
        assert!(!p.matches("GET", "/v1/secrets", None));
    }

    #[test]
    fn the_proxy_forwards_logs_rewrites_and_replays() {
        let adv = Adversary::start();
        let (status, body) = adv.send("GET", "/healthz", &[], b"");
        assert_eq!((status, body["status"].as_str()), (200, Some("ok")));
        assert_eq!(adv.log().last().unwrap().path, "/healthz");

        adv.rewrite(Matcher::get("/healthz"), |v| v["status"] = "forged".into());
        assert_eq!(adv.send("GET", "/healthz", &[], b"").1["status"], "forged");
        adv.clear_rules();

        adv.record(Matcher::get("/healthz"));
        adv.send("GET", "/healthz", &[], b"");
        assert!(adv.recorded(&Matcher::get("/healthz")).is_some());
        adv.respond(
            Matcher::get("/healthz"),
            503,
            &serde_json::json!({"status": "down"}),
        );
        assert_eq!(adv.send("GET", "/healthz", &[], b"").0, 503);
        adv.clear_rules();

        let logged = adv
            .log()
            .into_iter()
            .find(|l| l.path == "/healthz")
            .unwrap();
        assert_eq!(adv.replay(&logged).0, 200);
        // An unsigned request to an authenticated endpoint is refused.
        assert_eq!(adv.send("GET", "/v1/vault", &[], b"").0, 401);
        // No control API unless asked for: the server answers it.
        assert_eq!(adv.send("POST", "/__adversary/clear", &[], b"{}").0, 404);
    }

    #[test]
    fn the_control_api_scripts_the_same_proxy() {
        let adv = Adversary::start_controlled();
        let ctl = |what: &str, body: Value| {
            adv.send(
                "POST",
                &format!("/__adversary/{what}"),
                &[("content-type", "application/json")],
                &serde_json::to_vec(&body).unwrap(),
            )
        };
        let health = json!({ "method": "GET", "path": "/healthz" });
        assert_eq!(ctl("record", json!({ "match": health })).0, 200);
        adv.send("GET", "/healthz", &[], b"");
        let (status, got) = ctl("recorded", json!({ "match": health }));
        assert_eq!((status, &got["body"]["status"]), (200, &json!("ok")));

        let forged = json!({ "match": health, "set": [["/status", "forged"]] });
        ctl("rewrite", forged);
        assert_eq!(adv.send("GET", "/healthz", &[], b"").1["status"], "forged");
        ctl("clear", json!({}));

        let mut v = json!({ "sig": B64(vec![0; 4]) });
        flip_b64(&mut v, "/sig", 1);
        assert_eq!(
            v["sig"],
            serde_json::to_value(B64(vec![0, 0x5a, 0, 0])).unwrap()
        );

        let (status, log) = adv.send("GET", "/__adversary/log", &[], b"");
        assert_eq!(status, 200);
        let paths: Vec<&str> = log
            .as_array()
            .unwrap()
            .iter()
            .map(|l| l["path"].as_str().unwrap())
            .collect();
        assert_eq!(
            paths,
            ["/healthz", "/healthz"],
            "control calls are not logged"
        );
        assert_eq!(ctl("nonsense", json!({})).0, 404);
    }
}
