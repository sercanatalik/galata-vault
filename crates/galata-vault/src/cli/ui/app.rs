//! The event loop and everything it serves. One thread owns it all: the
//! owner API and its key store, the browser session, the pending
//! confirmation, a minted token awaiting hand-over, and the clipboard. Every
//! vault operation is the SDK's owner API.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::time::{Duration, Instant};

use crate::owner::{Environment, Owner};
use crate::proto::api::Scope;
use crate::proto::ids::TokenId;
use crate::proto::path::EnvPath;
use crate::{Error, Expect};
use anyhow::{Context as _, bail};
use maud::Markup;
use serde::Deserialize;
use serde_json::json;
use zeroize::{Zeroize, Zeroizing};

use super::Timings;
use super::clip::{Clip, Clipboard, TOOLS};
use super::pages::{self, Cmp, CmpRow, Frame, RailEnv, RailProject};
use super::web::{self, Req, Resp};
use crate::cli::branding::Branding;
use crate::cli::context::describe;
use crate::cli::secrets::{conflict_text, refuse_reserved};
use crate::cli::util::{fmt_time, now, parse_ttl};

const COOKIE: &str = "gvui";
/// Audit rows shown from before the stored head.
const AUDIT_EARLIER: usize = 200;

struct Browser {
    cookie: String,
    last_active: Instant,
}

enum Op {
    Mint { scope: Scope, ttl: u64 },
    Revoke { id: TokenId, rotate: bool },
    Rotate,
    DeleteEnv { recursive: bool },
}

struct Pending {
    id: u64,
    env: EnvPath,
    op: Op,
    asked: Instant,
}

enum Outcome {
    Waiting,
    Done(String),
    /// Done, and a minted token is waiting to be handed over.
    Handover(String),
    Cancelled,
    Lapsed,
    Failed(String),
}

/// A minted token, until it is copied, saved or discarded. The page never
/// receives it.
struct Handover {
    confirm: u64,
    env: EnvPath,
    token: Zeroizing<String>,
    token_id: String,
}

/// An environment's live values by name, decrypted, with their versions.
type Plaintexts = BTreeMap<String, (u64, Zeroizing<Vec<u8>>)>;

pub struct App {
    server: tiny_http::Server,
    origin: String,
    host: String,
    owner: Owner,
    branding: Branding,
    browser: Option<Browser>,
    code: Option<(String, Instant)>,
    pending: Option<Pending>,
    outcomes: BTreeMap<u64, Outcome>,
    next_id: u64,
    handover: Option<Handover>,
    clip: Clip,
    term: Receiver<String>,
    feed: Sender<String>,
    t: Timings,
    stop: Arc<AtomicBool>,
}

fn clock() -> String {
    let (_, _, _, h, m, s) = crate::proto::time::utc(now());
    format!("{h:02}:{m:02}:{s:02}")
}

fn parse_env(s: &str) -> anyhow::Result<EnvPath> {
    s.parse()
        .map_err(|e| anyhow::anyhow!("{s:?} is not an environment path: {e}"))
}

fn short(id: &str) -> &str {
    &id[..id.len().min(8)]
}

fn expand_home(p: &str) -> PathBuf {
    match p.strip_prefix("~/") {
        Some(rest) => std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_default()
            .join(rest),
        None => PathBuf::from(p),
    }
}

#[derive(Deserialize)]
struct Named {
    env: String,
    name: String,
    #[serde(default)]
    version: Option<u64>,
}

#[derive(Deserialize)]
struct SetBody {
    env: String,
    name: String,
    value: String,
    /// The version this write replaces; absent to create.
    #[serde(default)]
    expected: Option<u64>,
}

#[derive(Deserialize)]
struct DeleteBody {
    env: String,
    name: String,
    expected: u64,
}

#[derive(Deserialize)]
struct RestoreBody {
    env: String,
    name: String,
    version: u64,
    #[serde(default)]
    expected: Option<u64>,
}

#[derive(Deserialize)]
struct PathBody {
    path: String,
    #[serde(default)]
    recursive: bool,
}

#[derive(Deserialize)]
struct MintBody {
    env: String,
    scope: String,
    #[serde(default)]
    ttl: Option<String>,
}

#[derive(Deserialize)]
struct RevokeBody {
    env: String,
    id: String,
}

#[derive(Deserialize)]
struct EnvBody {
    env: String,
}

#[derive(Deserialize)]
struct HandBody {
    confirm: u64,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Deserialize)]
struct CodeBody {
    code: String,
}

impl App {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        owner: Owner,
        branding: Branding,
        clipboard: Clipboard,
        t: Timings,
        term: Receiver<String>,
        feed: Sender<String>,
        stop: Arc<AtomicBool>,
    ) -> anyhow::Result<App> {
        let server = tiny_http::Server::http("127.0.0.1:0").map_err(|e| {
            anyhow::anyhow!(
                "{} ui could not listen on 127.0.0.1: {e}",
                branding.bin_name
            )
        })?;
        let addr = server.server_addr().to_ip().with_context(|| {
            format!("{} ui is not listening on an IP address", branding.bin_name)
        })?;
        Ok(App {
            origin: format!("http://{addr}"),
            host: addr.to_string(),
            server,
            owner,
            branding,
            browser: None,
            code: None,
            pending: None,
            outcomes: BTreeMap::new(),
            next_id: 1,
            handover: None,
            clip: Clip::new(clipboard, t.clipboard_clear),
            term,
            feed,
            t,
            stop,
        })
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    pub fn run(mut self) {
        self.say(&format!(
            "{} ui · galata-vault {}",
            self.branding.bin_name,
            env!("CARGO_PKG_VERSION")
        ));
        self.say(
            "  keys stay in this process: the page gets names, and a value only when you reveal it",
        );
        self.new_link();
        self.say(&format!(
            "  locks    after {} idle · Enter prints a new link · Ctrl-C locks and quits",
            minutes(self.t.idle)
        ));
        while !self.stop.load(Ordering::SeqCst) {
            while let Ok(line) = self.term.try_recv() {
                self.on_line(&line);
            }
            self.tick();
            match self.server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(req)) => self.serve(req),
                Ok(None) => {}
                Err(e) => {
                    self.say(&format!(
                        "{} ui: the listener failed: {e}",
                        self.branding.bin_name
                    ));
                    break;
                }
            }
        }
        if self.browser.take().is_some() {
            self.forget();
        }
        self.clip.clear_all();
        self.say(&format!(
            "{} ui stopped. Anything it copied is gone from the clipboard unless you copied over it.",
            self.branding.bin_name
        ));
    }

    // ---------------------------------------------------------- terminal

    fn say(&self, line: &str) {
        let _ = self.feed.send(line.to_owned());
    }

    fn event(&self, kind: &str, env: &str, detail: &str) {
        self.say(&format!("{}  {kind:<8}  {env}  {detail}", clock()));
    }

    fn new_link(&mut self) {
        if self.browser.take().is_some() {
            self.forget();
            self.event("session", "", "ended: a new link was printed");
        }
        let code = web::random_hex(16);
        self.say(&format!("  page     {}/#c={code}", self.origin));
        self.code = Some((code, Instant::now()));
    }

    fn on_line(&mut self, line: &str) {
        if let Some(p) = self.pending.take() {
            if line.trim().eq_ignore_ascii_case("y") {
                self.perform(p);
            } else {
                self.outcomes.insert(p.id, Outcome::Cancelled);
                self.say("          └─ not confirmed; nothing was changed");
            }
            return;
        }
        if line.trim().is_empty() {
            self.new_link();
        } else {
            self.say("  Enter prints a new link; Ctrl-C locks and quits");
        }
    }

    fn tick(&mut self) {
        if self
            .code
            .as_ref()
            .is_some_and(|(_, at)| at.elapsed() > self.t.code_lapse)
        {
            self.code = None;
        }
        if self
            .browser
            .as_ref()
            .is_some_and(|b| b.last_active.elapsed() > self.t.idle)
        {
            self.browser = None;
            self.forget();
            self.event("session", "", "locked after idle; Enter prints a new link");
        }
        if self
            .pending
            .as_ref()
            .is_some_and(|p| p.asked.elapsed() > self.t.confirm_lapse)
            && let Some(p) = self.pending.take()
        {
            self.outcomes.insert(p.id, Outcome::Lapsed);
            self.say("          └─ no answer: the request lapsed, and nothing was changed");
        }
        self.clip.tick();
    }

    /// The browser session ended: cancel what it was waiting for and drop
    /// what it had not taken.
    fn forget(&mut self) {
        if self.pending.take().is_some() {
            self.say("          └─ the session ended: the request was cancelled");
        }
        self.handover = None;
        self.outcomes.clear();
    }

    // ---------------------------------------------------------- HTTP

    fn serve(&mut self, mut raw: tiny_http::Request) {
        let resp = match Req::read(&mut raw) {
            Ok(req) => self.route(&req),
            Err(status) => Resp::empty(status),
        };
        web::respond(raw, resp);
    }

    fn route(&mut self, req: &Req) -> Resp {
        // DNS rebinding: a page on another name that resolves here.
        if req.host.as_deref() != Some(self.host.as_str()) {
            return Resp::empty(421);
        }
        let (get, post) = (req.method == "GET", req.method == "POST");
        if !(get || post) {
            return Resp::empty(405);
        }
        if post && !(req.origin.as_deref() == Some(self.origin.as_str()) && req.gv_ui) {
            return Resp::error(
                403,
                "forbidden",
                "a change needs this page's origin and its X-GV-UI header",
            );
        }
        match (req.method.as_str(), req.path.as_str()) {
            ("GET", "/") => return Resp::html(200, pages::boot(self.branding.bin_name)),
            ("GET", p) if p.starts_with("/assets/") => return web::asset(&p["/assets/".len()..]),
            ("POST", "/session") => return self.exchange(req),
            _ => {}
        }
        let cookie = req.cookie(COOKIE).unwrap_or("");
        let Some(browser) = self
            .browser
            .as_mut()
            .filter(|b| web::same(&b.cookie, cookie))
        else {
            return if req.path.starts_with("/api/") {
                Resp::error(
                    401,
                    "locked",
                    &format!(
                        "no session: open the link {} ui printed",
                        self.branding.bin_name
                    ),
                )
            } else {
                Resp::html(401, pages::no_session(self.branding.bin_name))
            };
        };
        if req.path == "/api/ping" {
            return Resp::json(200, json!({ "ok": true }));
        }
        browser.last_active = Instant::now();
        let result = if get { self.get(req) } else { self.post(req) };
        let _ = self.owner.save();
        match result {
            Ok(r) => r,
            Err(e) => {
                let message = crate::cli::render_error(&e, &self.branding);
                if req.path.starts_with("/api/") {
                    Resp::error(400, "refused", &message)
                } else {
                    Resp::html(400, pages::problem(&self.frame(None), &message))
                }
            }
        }
    }

    fn exchange(&mut self, req: &Req) -> Resp {
        let Ok(body) = req.json::<CodeBody>() else {
            return Resp::error(400, "bad_request", "no code");
        };
        match self.code.take() {
            Some((code, _)) if web::same(&code, &body.code) => {
                if self.browser.is_some() {
                    self.forget();
                }
                let cookie = web::random_hex(32);
                self.browser = Some(Browser {
                    cookie: cookie.clone(),
                    last_active: Instant::now(),
                });
                self.event("session", "", "started · link spent");
                Resp::json(200, json!({ "ok": true })).cookie(COOKIE, &cookie)
            }
            unspent => {
                // A wrong guess does not burn the real link.
                self.code = unspent;
                Resp::error(410, "link_used", "this link has been used or has lapsed")
            }
        }
    }

    fn get(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let path = req.path.as_str();
        if let Some(id) = path.strip_prefix("/api/confirm/") {
            return Ok(self.confirm_status(id));
        }
        if path == "/projects" {
            return Ok(Resp::html(200, self.projects_page()?));
        }
        if let Some(rest) = path.strip_prefix("/e/") {
            let Some((env, tab)) = rest.rsplit_once('/') else {
                return Ok(Resp::redirect(&format!("/e/{rest}/secrets")));
            };
            let env = parse_env(env)?;
            let page = match tab {
                "secrets" => self.secrets_page(&env, req)?,
                "tokens" => self.tokens_page(&env)?,
                "audit" => self.audit_page(&env)?,
                "compare" => self.compare_page(&env, req)?,
                _ => return Ok(Resp::html(404, pages::not_found(&self.frame(None)))),
            };
            return Ok(Resp::html(200, page));
        }
        Ok(Resp::html(404, pages::not_found(&self.frame(None))))
    }

    fn post(&mut self, req: &Req) -> anyhow::Result<Resp> {
        match req.path.as_str() {
            "/api/lock" => {
                self.browser = None;
                self.forget();
                self.event(
                    "session",
                    "",
                    "locked from the page; Enter prints a new link",
                );
                Ok(Resp::json(200, json!({ "ok": true })).clear_cookie(COOKIE))
            }
            "/api/reveal" => self.reveal(req),
            "/api/copy" => self.copy(req),
            "/api/set" => {
                let mut b: SetBody = req.json()?;
                let result = self.write(&b.env, &b.name, b.value.as_bytes(), b.expected);
                b.value.zeroize();
                result
            }
            "/api/delete" => self.delete(req),
            "/api/restore" => self.restore(req),
            "/api/env/add" => {
                let b: PathBody = req.json()?;
                let path = parse_env(&b.path)?;
                self.owner.env_add(&path)?;
                self.event("create", &path.to_string(), "");
                Ok(Resp::json(200, json!({ "created": path.to_string() })))
            }
            "/api/mint" | "/api/revoke" | "/api/rotate" | "/api/env/delete" => self.ask(req),
            "/api/handover/copy" | "/api/handover/save" | "/api/handover/discard" => {
                self.hand_over(req)
            }
            _ => Ok(Resp::error(404, "not_found", "no such action")),
        }
    }

    // ---------------------------------------------------------- vaults

    /// Open a known environment as its owner. Refused before any request if
    /// the path is not in the known tree.
    fn open(&mut self, env: &EnvPath) -> anyhow::Result<Environment> {
        Ok(self.owner.environment(env)?)
    }

    /// Done with an environment: remember what it showed (its pins), saved
    /// with the owner's state after the request.
    fn close(&mut self, vault: Environment) {
        self.owner.remember(&vault);
    }

    fn frame(&self, active: Option<&EnvPath>) -> Frame {
        let mut rail = Vec::new();
        for (name, p) in &self.owner.state().projects {
            let key = if p.held.iter().any(|h| h == name) {
                "project key"
            } else if p.held.is_empty() {
                "no key"
            } else {
                "environment kit"
            };
            let mut root = None;
            let mut envs = Vec::new();
            for (path, node) in &p.tree {
                let Ok(parsed) = path.parse::<EnvPath>() else {
                    continue;
                };
                let env = RailEnv {
                    path: path.clone(),
                    label: parsed.last().as_str().to_owned(),
                    depth: parsed.depth(),
                    kit: p.held.contains(path) && !parsed.is_project(),
                    rekeyed: node.sealed,
                    vault: short(&node.vault_id.to_hex()).to_owned(),
                };
                if parsed.is_project() {
                    root = Some(env);
                } else {
                    envs.push(env);
                }
            }
            rail.push(RailProject {
                name: name.clone(),
                key,
                root,
                envs,
            });
        }
        Frame {
            bin: self.branding.bin_name,
            rail,
            active: active.map(ToString::to_string),
            server: active
                .and_then(|a| self.owner.state().project(a).ok())
                .map(|p| p.server.clone()),
            idle: minutes(self.t.idle),
        }
    }

    fn projects_page(&mut self) -> anyhow::Result<Markup> {
        // Rediscover, as `gv env ls` does, so changes from elsewhere show.
        let projects: Vec<EnvPath> = self
            .owner
            .state()
            .projects
            .keys()
            .filter_map(|k| k.parse().ok())
            .collect();
        let mut warnings = Vec::new();
        for p in &projects {
            if let Err(e) = self.owner.refresh(p) {
                warnings.push(format!(
                    "{p}: showing the cached tree: {}",
                    describe(&e, &self.branding)
                ));
            }
        }
        Ok(pages::projects(&self.frame(None), &warnings))
    }

    fn secrets_page(&mut self, env: &EnvPath, req: &Req) -> anyhow::Result<Markup> {
        let vault = self.open(env)?;
        let items = vault.list_all()?;
        let history = match req.q("name") {
            Some(n) => Some((n.to_owned(), vault.history(n)?)),
            None => None,
        };
        let status = vault.status_at_open().clone();
        self.close(vault);
        Ok(pages::secrets(
            &self.frame(Some(env)),
            &env.to_string(),
            &items,
            req.q("all").is_some(),
            history.as_ref().map(|(n, v)| (n.as_str(), v.as_slice())),
            Some(&status),
            self.clip.available().then(|| self.clip.clears_in()),
            self.t.reveal.as_secs(),
        ))
    }

    fn tokens_page(&mut self, env: &EnvPath) -> anyhow::Result<Markup> {
        let vault = self.open(env)?;
        let rows = vault.tokens()?;
        let status = vault.status_at_open().clone();
        self.close(vault);
        Ok(pages::tokens(
            &self.frame(Some(env)),
            &env.to_string(),
            &rows,
            Some(&status),
        ))
    }

    fn audit_page(&mut self, env: &EnvPath) -> anyhow::Result<Markup> {
        let vault = self.open(env)?;
        let known = self.owner.state().audit.get(&vault.vault_id()).copied();
        // The owner advances the stored head only on success.
        let report = self.owner.audit(&vault, AUDIT_EARLIER);
        let status = vault.status_at_open().clone();
        self.close(vault);
        let frame = self.frame(Some(env));
        Ok(match report {
            Ok(r) => pages::audit(&frame, &env.to_string(), Ok(&r), known, Some(&status)),
            Err(e) => pages::audit(
                &frame,
                &env.to_string(),
                Err(describe(&e, &self.branding)),
                known,
                Some(&status),
            ),
        })
    }

    fn compare_page(&mut self, env: &EnvPath, req: &Req) -> anyhow::Result<Markup> {
        let here = env.to_string();
        let others: Vec<String> = self
            .owner
            .state()
            .projects
            .values()
            .flat_map(|p| p.tree.keys().cloned())
            .filter(|p| p != &here)
            .collect();
        let result = match req.q("with").filter(|w| !w.is_empty()) {
            Some(w) => {
                let other = parse_env(w)?;
                let rows = self.compare(env, &other)?;
                Some((other.to_string(), rows))
            }
            None => None,
        };
        Ok(pages::compare(
            &self.frame(Some(env)),
            &here,
            &others,
            result.as_ref().map(|(w, r)| (w.as_str(), r.as_slice())),
        ))
    }

    /// Every live value of `env`, decrypted, with its version.
    fn read_all(&mut self, env: &EnvPath) -> anyhow::Result<Plaintexts> {
        let vault = self.open(env)?;
        let set = vault.readable(None)?;
        Ok(set
            .iter()
            .map(|s| {
                (
                    s.name().to_owned(),
                    (s.version(), Zeroizing::new(s.expose().to_vec())),
                )
            })
            .collect())
    }

    /// Two independent reads, as `gv-mcp`'s `diff_envs` does, so nothing at
    /// the server links them. The page gets only same or different.
    fn compare(&mut self, a: &EnvPath, b: &EnvPath) -> anyhow::Result<Vec<CmpRow>> {
        let left = self.read_all(a)?;
        let right = self.read_all(b)?;
        let names: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
        let rows = names
            .into_iter()
            .map(|n| {
                let (l, r) = (left.get(n), right.get(n));
                CmpRow {
                    name: n.clone(),
                    a: l.map(|x| x.0),
                    b: r.map(|x| x.0),
                    cmp: match (l, r) {
                        (Some(x), Some(y)) if x.1[..] == y.1[..] => Cmp::Same,
                        (Some(_), Some(_)) => Cmp::Differ,
                        (Some(_), None) => Cmp::OnlyA,
                        _ => Cmp::OnlyB,
                    },
                }
            })
            .collect();
        self.event("compare", &a.to_string(), &format!("with {b}"));
        Ok(rows)
    }

    // ---------------------------------------------------------- secrets

    fn reveal(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let b: Named = req.json()?;
        let env = parse_env(&b.env)?;
        let vault = self.open(&env)?;
        let value = match b.version {
            Some(v) => vault.secret_version(&b.name, v)?,
            None => vault.secret(&b.name)?,
        };
        self.close(vault);
        let mut text = String::from_utf8_lossy(value.expose()).into_owned();
        let resp = Resp::json(
            200,
            json!({ "value": text, "version": value.version(), "hide_after": self.t.reveal.as_secs() }),
        );
        text.zeroize();
        self.event("reveal", &env.to_string(), &b.name);
        Ok(resp)
    }

    fn copy(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let b: Named = req.json()?;
        let env = parse_env(&b.env)?;
        if !self.clip.available() {
            bail!("copying needs {TOOLS}, and none was found; reveal the value instead");
        }
        let vault = self.open(&env)?;
        let value = match b.version {
            Some(v) => vault.secret_version(&b.name, v)?,
            None => vault.secret(&b.name)?,
        };
        self.close(vault);
        self.clip.copy(value.expose())?;
        let secs = self.clip.clears_in();
        self.event(
            "copy",
            &env.to_string(),
            &format!("{}   clipboard clears in {secs} s", b.name),
        );
        Ok(Resp::json(
            200,
            json!({ "copied": true, "clears_in": secs }),
        ))
    }

    fn write(
        &mut self,
        env: &str,
        name: &str,
        value: &[u8],
        expected: Option<u64>,
    ) -> anyhow::Result<Resp> {
        refuse_reserved(&self.branding, name)?;
        if value.is_empty() {
            bail!("the value for {name} is empty");
        }
        let env = parse_env(env)?;
        let vault = self.open(&env)?;
        // No expected version means "it does not exist yet": a live record
        // is still a conflict, but a deleted one is revived.
        let expect = match expected {
            Some(v) => Expect::Version(v),
            None => Expect::Absent,
        };
        let result = vault.set_secret_expecting(name, value, expect);
        self.close(vault);
        match result {
            Ok(v) => {
                self.event("write", &env.to_string(), &format!("{name} → v{v}"));
                Ok(Resp::json(200, json!({ "version": v })))
            }
            Err(Error::Conflict {
                name: n,
                expected,
                current,
                ..
            }) => Ok(Resp::error(
                409,
                "conflict",
                &format!(
                    "{env}: {}; nothing was overwritten",
                    conflict_text(&n, &expected, current)
                ),
            )),
            Err(e) => Err(e.into()),
        }
    }

    fn delete(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let b: DeleteBody = req.json()?;
        refuse_reserved(&self.branding, &b.name)?;
        let env = parse_env(&b.env)?;
        let vault = self.open(&env)?;
        let result = vault.delete_secret(&b.name, Some(b.expected));
        self.close(vault);
        match result {
            Ok(v) => {
                self.event("delete", &env.to_string(), &format!("{} → v{v}", b.name));
                Ok(Resp::json(200, json!({ "version": v })))
            }
            Err(Error::Conflict {
                name: n,
                expected,
                current,
                ..
            }) => Ok(Resp::error(
                409,
                "conflict",
                &format!(
                    "{env}: {}; nothing was deleted",
                    conflict_text(&n, &expected, current)
                ),
            )),
            Err(e) => Err(e.into()),
        }
    }

    fn restore(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let b: RestoreBody = req.json()?;
        let env = parse_env(&b.env)?;
        let vault = self.open(&env)?;
        let value = vault.secret_version(&b.name, b.version)?;
        self.close(vault);
        self.write(&b.env, &b.name, value.expose(), b.expected)
    }

    // ---------------------------------------------------------- confirmations

    fn ask(&mut self, req: &Req) -> anyhow::Result<Resp> {
        if self.pending.is_some() {
            return Ok(Resp::error(
                409,
                "confirmation_pending",
                "another request is waiting for the terminal",
            ));
        }
        let (env, op, lines, verb) = match req.path.as_str() {
            "/api/mint" => {
                let b: MintBody = req.json()?;
                let env = parse_env(&b.env)?;
                let scope = Scope::parse(&b.scope)
                    .context("a scope is meta, append, read, admin, config or config-write")?;
                let ttl = b.ttl.as_deref().map(parse_ttl).transpose()?.unwrap_or(0);
                let lines = vec![
                    format!("mint a token for {env}"),
                    format!("  scope     {scope} · decrypts {}", pages::decrypts(scope)),
                    format!(
                        "  expires   {}",
                        if ttl == 0 {
                            "the server's default".to_owned()
                        } else {
                            format!("in {}", pages::span(ttl as i64))
                        }
                    ),
                ];
                (env, Op::Mint { scope, ttl }, lines, "mint it")
            }
            "/api/revoke" => {
                let b: RevokeBody = req.json()?;
                let env = parse_env(&b.env)?;
                let id = TokenId::from_hex(&b.id)
                    .map_err(|_| anyhow::anyhow!("a token id is 32 hexadecimal characters"))?;
                let vault = self.open(&env)?;
                let scope = vault
                    .tokens()?
                    .into_iter()
                    .find(|t| t.id == id)
                    .map(|t| t.scope)
                    .with_context(|| format!("{env} has no token {}", short(&b.id)))?;
                self.close(vault);
                // A token holding any key beyond the name key (one that
                // decrypts, or a writer key) is revoked with a rotation, run
                // as the owner: its keys open and sign nothing afterwards.
                let rotate = scope != Scope::Meta;
                let mut lines = vec![format!("revoke {scope} token {} in {env}", short(&b.id))];
                if rotate {
                    lines.push(format!(
                        "  and rotate {env}: the token's keys open and sign nothing afterwards"
                    ));
                }
                (env, Op::Revoke { id, rotate }, lines, "revoke it")
            }
            "/api/rotate" => {
                let b: EnvBody = req.json()?;
                let env = parse_env(&b.env)?;
                let lines = vec![format!(
                    "rotate {env}: re-encrypt it under fresh keys, and reseal every token"
                )];
                (env, Op::Rotate, lines, "rotate it")
            }
            _ => {
                let b: PathBody = req.json()?;
                let env = parse_env(&b.path)?;
                self.owner.require_known(&env)?;
                let below = self.owner.state().project(&env)?.descendants(&env);
                if !below.is_empty() && !b.recursive {
                    let names: Vec<String> = below.iter().map(ToString::to_string).collect();
                    bail!(
                        "{env} has environments below it ({}); delete those first",
                        names.join(", ")
                    );
                }
                let lines = vec![format!(
                    "delete {env} and its vault: every secret and token in it is gone"
                )];
                (
                    env,
                    Op::DeleteEnv {
                        recursive: b.recursive,
                    },
                    lines,
                    "delete it",
                )
            }
        };
        let id = self.next_id;
        self.next_id += 1;
        let code = web::random_code();
        self.say(&format!(
            "{}  ┌─ confirm ────────────────────────────────────────────",
            clock()
        ));
        for line in &lines {
            self.say(&format!("          │  {line}"));
        }
        self.say(&format!(
            "          │  code      {code}   the browser must show the same code"
        ));
        self.say(&format!("          └─ {verb}? [y/N]"));
        self.pending = Some(Pending {
            id,
            env,
            op,
            asked: Instant::now(),
        });
        self.outcomes.insert(id, Outcome::Waiting);
        Ok(Resp::json(202, json!({ "confirm": id, "code": code })))
    }

    fn perform(&mut self, p: Pending) {
        let outcome = self
            .run_op(&p)
            .unwrap_or_else(|e| Outcome::Failed(crate::cli::render_error(&e, &self.branding)));
        match &outcome {
            Outcome::Done(m) | Outcome::Handover(m) => {
                self.say(&format!("          └─ done: {m}"));
            }
            Outcome::Failed(m) => self.say(&format!("          └─ failed: {m}")),
            _ => {}
        }
        self.outcomes.insert(p.id, outcome);
    }

    fn run_op(&mut self, p: &Pending) -> anyhow::Result<Outcome> {
        let env = p.env.to_string();
        Ok(match &p.op {
            Op::Mint { scope, ttl } => {
                let vault = self.open(&p.env)?;
                let token = vault.mint(*scope, *ttl, &[])?;
                self.close(vault);
                let token_id = token.id().to_string();
                let message = format!(
                    "minted {scope} token {} for {env}, expiring {}; take it from the page",
                    short(&token_id),
                    fmt_time(token.expires_at())
                );
                self.handover = Some(Handover {
                    confirm: p.id,
                    env: p.env.clone(),
                    token: Zeroizing::new(token.expose().to_owned()),
                    token_id,
                });
                Outcome::Handover(message)
            }
            Op::Revoke { id, rotate } => {
                let vault = self.open(&p.env)?;
                let hex = id.to_hex();
                match vault.revoke(id, *rotate)?.rotated_to {
                    Some(generation) => Outcome::Done(format!(
                        "revoked token {} and rotated {env} to generation {generation}; change any value you think its holder read",
                        short(&hex)
                    )),
                    None => Outcome::Done(format!("revoked token {} in {env}", short(&hex))),
                }
            }
            Op::Rotate => {
                let generation = self.open(&p.env)?.rotate()?;
                Outcome::Done(format!("rotated {env} to generation {generation}"))
            }
            Op::DeleteEnv { recursive } => {
                let removal = self.owner.env_remove(&p.env, *recursive)?;
                let gone: Vec<String> = removal.deleted.iter().map(ToString::to_string).collect();
                Outcome::Done(format!("deleted {}", gone.join(", ")))
            }
        })
    }

    fn confirm_status(&self, id: &str) -> Resp {
        let Some(outcome) = id.parse::<u64>().ok().and_then(|id| self.outcomes.get(&id)) else {
            return Resp::error(404, "unknown", "no such request in this session");
        };
        let (state, message) = match outcome {
            Outcome::Waiting => ("waiting", "waiting for the terminal"),
            Outcome::Done(m) => ("done", m.as_str()),
            Outcome::Handover(m) => ("handover", m.as_str()),
            Outcome::Cancelled => (
                "cancelled",
                "not confirmed in the terminal; nothing was changed",
            ),
            Outcome::Lapsed => (
                "lapsed",
                "nobody answered in the terminal; nothing was changed",
            ),
            Outcome::Failed(m) => ("failed", m.as_str()),
        };
        Resp::json(200, json!({ "state": state, "message": message }))
    }

    fn hand_over(&mut self, req: &Req) -> anyhow::Result<Resp> {
        let b: HandBody = req.json()?;
        let Some(ho) = self.handover.take_if(|h| h.confirm == b.confirm) else {
            bail!("this token was already handed over, or its session ended; mint another");
        };
        let env = ho.env.to_string();
        match req.path.as_str() {
            "/api/handover/copy" => match self.clip.copy(ho.token.as_bytes()) {
                Ok(()) => {
                    let secs = self.clip.clears_in();
                    self.event(
                        "copy",
                        &env,
                        &format!(
                            "token {}   clipboard clears in {secs} s",
                            short(&ho.token_id)
                        ),
                    );
                    Ok(Resp::json(
                        200,
                        json!({ "copied": true, "clears_in": secs }),
                    ))
                }
                Err(e) => {
                    self.handover = Some(ho);
                    Err(e)
                }
            },
            "/api/handover/save" => {
                let Some(p) = b.path.as_deref().map(str::trim).filter(|p| !p.is_empty()) else {
                    self.handover = Some(ho);
                    bail!("give the file to save the token to");
                };
                let path = expand_home(p);
                let line = Zeroizing::new(format!("{}\n", ho.token.as_str()));
                match crate::cli::fsutil::create_private(&path, line.as_bytes(), false) {
                    Ok(()) => {
                        self.event(
                            "save",
                            &env,
                            &format!(
                                "token {} to {} (mode 0600)",
                                short(&ho.token_id),
                                path.display()
                            ),
                        );
                        Ok(Resp::json(
                            200,
                            json!({ "saved": path.display().to_string() }),
                        ))
                    }
                    Err(e) => {
                        self.handover = Some(ho);
                        Err(e)
                    }
                }
            }
            _ => {
                self.event(
                    "discard",
                    &env,
                    &format!(
                        "token {} was not kept; it stays registered until it expires or is revoked",
                        short(&ho.token_id)
                    ),
                );
                Ok(Resp::json(200, json!({ "ok": true })))
            }
        }
    }
}

fn minutes(d: Duration) -> String {
    let s = d.as_secs();
    if s >= 60 {
        format!("{} min", s / 60)
    } else {
        format!("{s} s")
    }
}
