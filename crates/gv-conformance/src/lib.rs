//! The conformance suite (`docs/spec/README.md#6`): numbered cases that
//! check a server's behaviour against the specification as a black box.
//!
//! A [`Target`] is a server reached through a `Transport`: over HTTP (any
//! URL), or in-process through the SDK's embedded backend. Each [`Case`]
//! cites the section it checks, creates its own vaults with random keys, and
//! answers pass, fail with a reason, or skip (a check that needs HTTP headers
//! on the embedded target). Every vault a run creates is deleted at the end.
//!
//! Vectors check bytes; this suite checks a server; the adversarial harness
//! (`gv-adversary`) checks clients against a hostile server.

use std::sync::{Arc, Mutex};

use galata_vault::client::{Api, ApiError, Auth, Method, Pre, Reply, Request, Transport};
use galata_vault::keys::{NodeKey, TokenKeys};
use galata_vault::proto::api::{
    Capabilities, ErrorCode, PROTOCOL, PutSecretRequest, Scope, SecretList, VersionList,
};
use galata_vault::proto::ids::NameHmac;
use galata_vault::proto::record::RecordKind;
use galata_vault::proto::sig::SignedRequest;
use galata_vault::seal::Writer;
use galata_vault::testing::RawVault;

/// What a case found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Pass(String),
    Fail(String),
    Skip(String),
}

/// One numbered case.
#[derive(Clone, Copy)]
pub struct Case {
    pub id: &'static str,
    /// The specification section it checks.
    pub anchor: &'static str,
    pub title: &'static str,
    run: fn(&Ctx<'_>) -> Result<String, Verdict>,
}

impl std::fmt::Debug for Case {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.id, self.anchor)
    }
}

/// A server under test.
pub struct Target {
    name: String,
    transport: Arc<dyn Transport>,
    /// The base URL, for the checks only HTTP can make.
    http: Option<String>,
}

impl Target {
    /// A server over HTTP. `url` must be `https://`, or `http://` to
    /// loopback (the SDK's rule); [`is_loopback`] says whether a run needs
    /// `--allow-remote`.
    pub fn http(url: &str) -> Result<Target, String> {
        let transport = galata_vault::ClientBuilder::new(url)
            .build_transport()
            .map_err(|e| e.to_string())?;
        Ok(Target {
            name: url.trim_end_matches('/').to_owned(),
            transport: Arc::new(transport),
            http: Some(url.trim_end_matches('/').to_owned()),
        })
    }

    /// A data directory, served in-process by the SDK's embedded backend.
    /// Needs this crate's `embedded` feature; without it, refused by name.
    pub fn embedded(dir: &std::path::Path) -> Result<Target, String> {
        #[cfg(feature = "embedded")]
        {
            let transport = galata_vault::embedded::open(dir).map_err(|e| e.to_string())?;
            Ok(Target {
                name: format!("embedded:{}", dir.display()),
                transport: Arc::new(transport),
                http: None,
            })
        }
        #[cfg(not(feature = "embedded"))]
        {
            Err(format!(
                "{}: this gv-conformance was built without its `embedded` feature; \
                 rebuild it with `--features embedded` to run the embedded target",
                dir.display()
            ))
        }
    }

    /// Any transport (a test's planted server), with the base URL of the
    /// HTTP server behind it if there is one.
    pub fn with_transport(
        name: &str,
        transport: Arc<dyn Transport>,
        http: Option<String>,
    ) -> Target {
        Target {
            name: name.to_owned(),
            transport,
            http,
        }
    }
}

/// Whether `url` names this machine. The suite creates vaults, consumes
/// quota and solves proof of work, so anywhere else needs `--allow-remote`.
pub fn is_loopback(url: &str) -> bool {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = if let Some(bracketed) = rest.strip_prefix('[') {
        bracketed.split(']').next().unwrap_or("")
    } else {
        rest.split(['/', ':']).next().unwrap_or("")
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

/// What one case needs.
pub struct Ctx<'a> {
    target: &'a Target,
    api: Api,
    created: Mutex<Vec<NodeKey>>,
}

type Step<T> = Result<T, Verdict>;

fn fail<T>(why: impl Into<String>) -> Step<T> {
    Err(Verdict::Fail(why.into()))
}

fn skip<T>(why: impl Into<String>) -> Step<T> {
    Err(Verdict::Skip(why.into()))
}

fn now() -> i64 {
    galata_vault::client::now()
}

/// A random record index: nothing is stored under it.
fn fresh_index() -> NameHmac {
    galata_vault::keys::NameKey::generate().hmac("conformance")
}

/// The status and code of a refusal, or why it was not one.
fn refusal<T>(r: Result<T, ApiError>) -> Step<(u16, String)> {
    match r {
        Ok(_) => fail("the server accepted what it must refuse"),
        Err(e) => match e.status() {
            Some(status) => Ok((status, e.stable_code())),
            None => fail(format!("no answer: {e}")),
        },
    }
}

fn expect_refusal<T>(r: Result<T, ApiError>, status: u16, code: &str, what: &str) -> Step<()> {
    let got = refusal(r)?;
    if got != (status, code.to_owned()) {
        return fail(format!(
            "{what}: expected {status} {code}, got {} {}",
            got.0, got.1
        ));
    }
    Ok(())
}

struct Vault {
    key: NodeKey,
    raw: RawVault,
}

impl Vault {
    fn owner(&self) -> galata_vault::keys::OwnerKeys {
        self.key.owner()
    }

    fn index(&self, name: &str) -> NameHmac {
        self.raw.name_key().hmac(name)
    }

    /// A secret write signed for `version`, as a client would build it.
    fn record(&self, name: &str, value: &[u8], version: u64) -> Step<(NameHmac, PutSecretRequest)> {
        let descriptor = self.raw.descriptor();
        let name_key = self.raw.name_key();
        let writer = self
            .raw
            .secret_writer()
            .ok_or(Verdict::Fail("no writer key".into()))?;
        let w = Writer {
            descriptor: &descriptor,
            name_key: &name_key,
            writer: &writer,
        };
        let rec = w
            .secret(name, value, version, now())
            .map_err(|e| Verdict::Fail(e.to_string()))?;
        let request = rec
            .put_request()
            .ok_or(Verdict::Fail("no request".into()))?;
        Ok((rec.name_hmac, request))
    }
}

impl<'a> Ctx<'a> {
    fn new(target: &'a Target) -> Ctx<'a> {
        Ctx {
            target,
            api: Api::shared(target.transport.clone()),
            created: Mutex::new(Vec::new()),
        }
    }

    /// A new vault with random keys, deleted at the end of the run.
    fn vault(&self) -> Step<Vault> {
        let key = NodeKey::generate();
        match RawVault::create(&self.api, &key, "conformance") {
            Ok(true) => {}
            Ok(false) => return fail("a new vault id already existed"),
            Err(e) => return fail(format!("creating a vault: {e}")),
        }
        self.created.lock().unwrap().push(key.clone());
        let raw = RawVault::open_owner(&self.api, &key, "conformance")
            .map_err(|e| Verdict::Fail(format!("opening the new vault: {e}")))?;
        Ok(Vault { key, raw })
    }

    fn mint(&self, v: &Vault, scope: Scope) -> Step<TokenKeys> {
        v.raw
            .mint(scope, 0, None)
            .map(|(t, _)| t)
            .map_err(|e| Verdict::Fail(format!("minting a {scope} token: {e}")))
    }

    fn call(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        auth: Auth<'_>,
        pre: Option<Pre>,
    ) -> Result<Reply, ApiError> {
        self.api.call(method, path, body, auth, pre)
    }

    /// One request exactly as given: its status and body.
    fn send(&self, request: Request<'_>) -> Step<(u16, Vec<u8>)> {
        self.target
            .transport
            .send(request)
            .map(|r| (r.status, r.body))
            .map_err(|e| Verdict::Fail(format!("no answer: {e}")))
    }

    /// Delete every vault this run created. Best effort.
    fn clean_up(&self) {
        for key in self.created.lock().unwrap().drain(..) {
            let _ = self.api.call(
                Method::Delete,
                "/v1/vault",
                None,
                Auth::Owner(&key.owner()),
                None,
            );
        }
    }
}

// ------------------------------------------------------------------ cases

fn c01_capabilities(cx: &Ctx<'_>) -> Step<String> {
    let first = cx
        .call(Method::Get, "/v1/capabilities", None, Auth::None, None)
        .map_err(|e| Verdict::Fail(format!("GET /v1/capabilities: {e}")))?;
    let caps: Capabilities = serde_json::from_slice(&first.body)
        .map_err(|e| Verdict::Fail(format!("not a capabilities document: {e}")))?;
    let json: serde_json::Value = serde_json::from_slice(&first.body).unwrap_or_default();
    for field in [
        "protocols",
        "formats",
        "proof_of_work",
        "idle_expiry_days",
        "limits",
        "features",
    ] {
        if json.get(field).is_none() {
            return fail(format!("the document has no {field:?}"));
        }
    }
    if !caps.speaks(PROTOCOL) {
        return fail(format!(
            "protocols {:?} do not include \"2\"",
            caps.protocols
        ));
    }
    let second = cx
        .call(Method::Get, "/v1/capabilities", None, Auth::None, None)
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    let v = cx.vault()?;
    let signed = cx
        .call(
            Method::Get,
            "/v1/capabilities",
            None,
            Auth::Owner(&v.owner()),
            None,
        )
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    if first.body != second.body || first.body != signed.body {
        return fail("the document differs between callers or calls");
    }
    if String::from_utf8_lossy(&first.body).contains(&v.owner().vault_id().to_hex()) {
        return fail("the document names a vault");
    }
    Ok(format!(
        "protocols {:?}, proof of work {}, idle expiry {}",
        caps.protocols,
        caps.proof_of_work
            .map_or("off".into(), |p| format!("{} bits", p.difficulty)),
        caps.idle_expiry_days
            .map_or("off".into(), |d| format!("{d} days"))
    ))
}

fn c02_lifecycle(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    match RawVault::create(&cx.api, &v.key, "conformance") {
        Ok(false) => {}
        other => {
            return fail(format!(
                "creating it again: expected a conflict, got {other:?}"
            ));
        }
    }
    let status = cx
        .api
        .status(Auth::Owner(&v.owner()))
        .map_err(|e| Verdict::Fail(e.to_string()))?
        .value;
    if status.generation != 1 || status.vault_id != v.owner().vault_id() {
        return fail("the status does not describe the new vault at generation 1");
    }
    let deleted = cx.call(
        Method::Delete,
        "/v1/vault",
        None,
        Auth::Owner(&v.owner()),
        None,
    );
    if deleted.map(|r| r.status).ok() != Some(200) {
        return fail("DELETE /v1/vault did not answer 200");
    }
    expect_refusal(
        cx.call(
            Method::Get,
            "/v1/vault",
            None,
            Auth::Owner(&v.owner()),
            None,
        ),
        401,
        "unauthorized",
        "the deleted vault's status",
    )?;
    Ok("created, conflict on re-creation, status verified, deleted, then 401".into())
}

fn c03_precondition_required(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let path = format!("/v1/secrets/{}", fresh_index().to_hex());
    expect_refusal(
        cx.call(
            Method::Put,
            &path,
            Some(b"{}"),
            Auth::Owner(&v.owner()),
            None,
        ),
        428,
        "precondition_required",
        "a PUT without a precondition",
    )?;
    expect_refusal(
        cx.call(
            Method::Delete,
            &path,
            Some(b"{}"),
            Auth::Owner(&v.owner()),
            None,
        ),
        428,
        "precondition_required",
        "a DELETE without If-Match",
    )?;
    Ok("a write or delete with no precondition is 428".into())
}

fn c04_precondition_failed(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    v.raw
        .put("A", b"one", Pre::Create)
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    let (index, stale) = v.record("A", b"stale", 6)?;
    expect_refusal(
        cx.api.put(
            Auth::Owner(&v.owner()),
            RecordKind::Secret,
            &index,
            &stale,
            Pre::Update(5),
        ),
        412,
        "precondition_failed",
        "If-Match: 5 on version 1",
    )?;
    let (_, again) = v.record("A", b"again", 1)?;
    expect_refusal(
        cx.api.put(
            Auth::Owner(&v.owner()),
            RecordKind::Secret,
            &index,
            &again,
            Pre::Create,
        ),
        412,
        "precondition_failed",
        "If-None-Match: * on an existing record",
    )?;
    match v.raw.get("A", None) {
        Ok((1, _)) => Ok(
            "stale If-Match and If-None-Match on an existing record are 412; version 1 stands"
                .into(),
        ),
        other => fail(format!("the record changed: {other:?}")),
    }
}

fn c05_version_mismatch(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    v.raw
        .put("A", b"one", Pre::Create)
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    let (index, request) = v.record("A", b"seven", 7)?;
    expect_refusal(
        cx.api.put(
            Auth::Owner(&v.owner()),
            RecordKind::Secret,
            &index,
            &request,
            Pre::Update(1),
        ),
        409,
        "version_mismatch",
        "If-Match: 1 with a record signed for version 7",
    )?;
    match v.raw.get("A", None) {
        Ok((1, _)) => {
            Ok("a signed version other than the assigned one is 409 version_mismatch".into())
        }
        other => fail(format!("the record changed: {other:?}")),
    }
}

fn c06_history(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let e = |e: galata_vault::Error| Verdict::Fail(e.to_string());
    v.raw.put("A", b"one", Pre::Create).map_err(e)?;
    v.raw.put("A", b"two", Pre::Update(1)).map_err(e)?;
    let tomb = v.raw.delete("A", 2).map_err(e)?;
    if tomb != 3 {
        return fail(format!("the tombstone is version {tomb}, not 3"));
    }
    let index = v.index("A");
    let path = format!("/v1/secrets/{}", index.to_hex());
    expect_refusal(
        cx.call(Method::Get, &path, None, Auth::Owner(&v.owner()), None),
        404,
        "not_found",
        "the latest version of a deleted record",
    )?;
    let versions: VersionList = serde_json::from_slice(
        &cx.call(
            Method::Get,
            &format!("{path}/versions"),
            None,
            Auth::Owner(&v.owner()),
            None,
        )
        .map_err(|e| Verdict::Fail(e.to_string()))?
        .body,
    )
    .map_err(|e| Verdict::Fail(e.to_string()))?;
    let flags: Vec<(u64, bool)> = versions
        .versions
        .iter()
        .map(|m| (m.version, m.tombstone))
        .collect();
    if flags != [(1, false), (2, false), (3, true)] {
        return fail(format!("history is {flags:?}"));
    }
    let old = cx
        .call(
            Method::Get,
            &format!("{path}/versions/2"),
            None,
            Auth::Owner(&v.owner()),
            None,
        )
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    if old.etag.as_deref().map(|t| t.trim_matches('"')) != Some("2") {
        return fail(format!("version 2's ETag is {:?}", old.etag));
    }
    Ok("delete writes tombstone 3; latest is 404; history keeps 1–3; version 2 reads with ETag \"2\"".into())
}

fn c07_listing(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let e = |e: galata_vault::Error| Verdict::Fail(e.to_string());
    for name in ["A", "B", "C"] {
        v.raw.put(name, b"x", Pre::Create).map_err(e)?;
    }
    v.raw.delete("B", 1).map_err(e)?;
    let owner = v.owner();
    let page = |q: &str| -> Step<(SecretList, serde_json::Value)> {
        let body = cx
            .call(
                Method::Get,
                &format!("/v1/secrets?{q}"),
                None,
                Auth::Owner(&owner),
                None,
            )
            .map_err(|e| Verdict::Fail(e.to_string()))?
            .body;
        let list = serde_json::from_slice(&body).map_err(|e| Verdict::Fail(e.to_string()))?;
        Ok((list, serde_json::from_slice(&body).unwrap_or_default()))
    };
    let (first, raw) = page("limit=2")?;
    let Some(cursor) = first.next_cursor.filter(|_| first.items.len() == 2) else {
        return fail("a page of 2 out of 3 has no cursor");
    };
    let (second, _) = page(&format!("limit=2&after={}", cursor.to_hex()))?;
    if second.items.len() != 1 || second.next_cursor.is_some() {
        return fail("the second page does not hold exactly the last record");
    }
    let all: Vec<_> = first.items.iter().chain(&second.items).collect();
    let tombstones = all.iter().filter(|i| i.tombstone).count();
    if tombstones != 1
        || all
            .iter()
            .any(|i| i.tombstone && i.name_hmac != v.index("B"))
    {
        return fail("the deleted record is not the one listed as a tombstone");
    }
    if raw.to_string().contains("value_ct\"") {
        return fail("a listing carries value ciphertext");
    }
    Ok("3 records over 2 pages, one tombstone, no value ciphertext".into())
}

/// What C08 checks: a request (what, method, path, precondition) and the
/// scopes the server's policy permits it for.
type Rule<'a> = (&'a str, Method, &'a str, Option<Pre>, &'a [Scope]);

fn c08_scopes(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let secret = format!("/v1/secrets/{}", fresh_index().to_hex());
    let config = format!("/v1/configs/{}", fresh_index().to_hex());
    let other_token = format!("/v1/tokens/{}", "ab".repeat(16));
    use Scope::*;
    // (what, method, path, precondition, scopes the core permits)
    let rules: Vec<Rule<'_>> = vec![
        (
            "list secrets",
            Method::Get,
            "/v1/secrets",
            None,
            &[Meta, Append, Read, Admin, Config, ConfigWrite],
        ),
        (
            "status",
            Method::Get,
            "/v1/vault",
            None,
            &[Meta, Append, Read, Admin, Config, ConfigWrite],
        ),
        (
            "audit",
            Method::Get,
            "/v1/audit",
            None,
            &[Meta, Append, Read, Admin, Config, ConfigWrite],
        ),
        (
            "its own view",
            Method::Get,
            "/v1/tokens/self",
            None,
            &[Meta, Append, Read, Admin, Config, ConfigWrite],
        ),
        ("read a secret", Method::Get, &secret, None, &[Read, Admin]),
        (
            "write a secret",
            Method::Put,
            &secret,
            Some(Pre::Create),
            &[Append, Admin],
        ),
        (
            "delete a secret",
            Method::Delete,
            &secret,
            Some(Pre::Update(1)),
            &[Append, Admin],
        ),
        (
            "read a config",
            Method::Get,
            &config,
            None,
            &[Read, Admin, Config, ConfigWrite],
        ),
        (
            "write a config",
            Method::Put,
            &config,
            Some(Pre::Create),
            &[Append, Admin, ConfigWrite],
        ),
        (
            "revoke a token",
            Method::Delete,
            &other_token,
            None,
            &[Admin],
        ),
        ("mint a token", Method::Post, "/v1/tokens", None, &[]),
        ("rotate", Method::Post, "/v1/vault/rotations", None, &[]),
        (
            "read the children record",
            Method::Get,
            "/v1/vault/children",
            None,
            &[],
        ),
        (
            "write the children record",
            Method::Put,
            "/v1/vault/children",
            Some(Pre::Update(1)),
            &[],
        ),
        ("delete the vault", Method::Delete, "/v1/vault", None, &[]),
    ];
    let mut checked = 0;
    for scope in Scope::ALL {
        let token = cx.mint(&v, scope)?;
        for (what, method, path, pre, allowed) in &rules {
            let body =
                matches!(method, Method::Put | Method::Post | Method::Delete).then_some(&b"{}"[..]);
            let got = cx.call(*method, path, body, Auth::Token(&token), *pre);
            let forbidden = matches!(&got, Err(e) if e.status() == Some(403));
            if forbidden == allowed.contains(&scope) {
                let verdict = if forbidden { "refused" } else { "allowed" };
                return fail(format!("a {scope} token was {verdict} to {what}"));
            }
            if forbidden
                && got.as_ref().err().map(ApiError::stable_code).as_deref() != Some("forbidden")
            {
                return fail(format!(
                    "a {scope} token's refusal to {what} is not `forbidden`"
                ));
            }
            checked += 1;
        }
    }
    Ok(format!("{checked} scope checks over every scope"))
}

fn c09_quotas(cx: &Ctx<'_>) -> Step<String> {
    let caps = cx
        .api
        .capabilities()
        .map_err(|e| Verdict::Fail(e.to_string()))?
        .ok_or(Verdict::Fail("no capabilities document".into()))?;
    let max = caps.limits.max_value_bytes as usize;
    let v = cx.vault()?;
    v.raw
        .put("SMALL", b"fits", Pre::Create)
        .map_err(|e| Verdict::Fail(format!("a small value: {e}")))?;
    match v.raw.put("BIG", &vec![b'x'; max], Pre::Create) {
        Err(e) if e.code() == "value_too_large" => {}
        other => {
            return fail(format!(
                "a value of {max} bytes (the advertised quota, before encryption): {other:?}"
            ));
        }
    }
    Ok(format!(
        "a value over the advertised {max}-byte quota is value_too_large"
    ))
}

fn c10_uniform_401(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let owner = v.owner();
    let stranger = NodeKey::generate().owner();
    let get = SignedRequest::new("GET", "/v1/vault", b"");
    let header =
        |keys: &galata_vault::keys::OwnerKeys, ts| keys.sign_request(&get, ts).to_header_value();
    let good = header(&owner, now());
    // One character in the middle of the signature: still well-formed
    // base64url, no longer a valid signature.
    let at = good
        .find("sig=")
        .ok_or(Verdict::Fail("no sig= in a header".into()))?
        + 20;
    let mut flipped = good.clone();
    let c = if &good[at..=at] == "A" { "B" } else { "A" };
    flipped.replace_range(at..=at, c);
    let attempts: Vec<(&str, Option<String>)> = vec![
        ("no Authorization", None),
        (
            "a Bearer credential",
            Some("Bearer gvt1_conformance".into()),
        ),
        ("GV-Sig v=2", Some(good.replacen("v=1", "v=2", 1))),
        (
            "a vault the server does not know",
            Some(header(&stranger, now())),
        ),
        ("a signature that does not verify", Some(flipped)),
        (
            "a signature an hour old",
            Some(header(&owner, now() - 3600)),
        ),
        ("a replayed signature", Some(good.clone())),
    ];
    let first_use =
        cx.send(Request::new(Method::Get, "/v1/vault").with_authorization(Some(&good)))?;
    if first_use.0 != 200 {
        return fail(format!("the genuine request answered {}", first_use.0));
    }
    let mut body: Option<Vec<u8>> = None;
    for (what, auth) in &attempts {
        let (status, got) =
            cx.send(Request::new(Method::Get, "/v1/vault").with_authorization(auth.as_deref()))?;
        if status != 401 {
            return fail(format!("{what}: answered {status}"));
        }
        match &body {
            None => body = Some(got),
            Some(b) if *b != got => return fail(format!("{what}: a different 401 body")),
            Some(_) => {}
        }
    }
    let body = String::from_utf8_lossy(body.as_deref().unwrap_or_default()).into_owned();
    if !body.contains("\"unauthorized\"") {
        return fail(format!("the 401 body is {body}"));
    }
    Ok(format!(
        "{} ways to fail authentication, one 401 body",
        attempts.len()
    ))
}

fn http_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

fn c11_not_renderable(cx: &Ctx<'_>) -> Step<String> {
    let Some(base) = &cx.target.http else {
        return skip("response headers exist only over HTTP");
    };
    let agent = http_agent();
    for path in ["/v1/capabilities", "/v1/vault", "/v3/anything"] {
        let response = agent
            .get(format!("{base}{path}"))
            .header("accept", "text/html")
            .call()
            .map_err(|e| Verdict::Fail(format!("{path}: {e}")))?;
        let h = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_owned()
        };
        if !h("content-type").starts_with("application/json") {
            return fail(format!(
                "{path} answered {:?} to a browser",
                h("content-type")
            ));
        }
        if h("x-content-type-options") != "nosniff"
            || !h("content-security-policy").contains("default-src 'none'")
            || !h("cache-control").contains("no-store")
        {
            return fail(format!(
                "{path} lacks nosniff, CSP default-src 'none' or no-store"
            ));
        }
    }
    Ok("JSON and nosniff, CSP default-src 'none', no-store on success, 401 and 404".into())
}

/// An `Authorization` value for exactly this request, with no precondition.
fn sign(auth: Auth<'_>, method: &str, path: &str, body: &[u8]) -> String {
    let request = SignedRequest::new(method, path, body);
    match auth {
        Auth::Owner(owner) => owner.sign_request(&request, now()).to_header_value(),
        Auth::Token(token) => token.sign_request(&request, now()).to_header_value(),
        _ => String::new(),
    }
}

fn c12_error_bodies(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let owner = v.owner();
    let reader = cx.mint(&v, Scope::Meta)?;
    let marker = "sk_live_conformance_marker";
    let junk = format!("{{\"scope\":\"meta\",\"secret\":\"{marker}\"}}");
    let junk = junk.as_bytes();
    let secret = format!("/v1/secrets/{}", fresh_index().to_hex());
    let bad_body = sign(Auth::Owner(&owner), "POST", "/v1/tokens", junk);
    let scope = sign(Auth::Token(&reader), "GET", &secret, b"");
    let no_pre = sign(Auth::Owner(&owner), "PUT", &secret, junk);
    let requests = [
        ("no credential", Request::new(Method::Get, "/v1/vault")),
        ("an unknown path", Request::new(Method::Get, "/v3/vault")),
        (
            "a body that is not a request",
            Request::new(Method::Post, "/v1/tokens")
                .with_authorization(Some(&bad_body))
                .with_body(Some(junk)),
        ),
        (
            "a scope that does not allow it",
            Request::new(Method::Get, &secret).with_authorization(Some(&scope)),
        ),
        (
            "no precondition",
            Request::new(Method::Put, &secret)
                .with_authorization(Some(&no_pre))
                .with_body(Some(junk)),
        ),
        (
            "an unsigned creation",
            Request::new(Method::Post, "/v1/vaults").with_body(Some(junk)),
        ),
    ];
    let mut statuses = Vec::new();
    for (what, request) in requests {
        let (status, body) = cx.send(request)?;
        if status < 400 {
            return fail(format!("{what}: answered {status}"));
        }
        if String::from_utf8_lossy(&body).contains(marker) {
            return fail(format!("{what}: the error echoed the request body"));
        }
        let json: serde_json::Value = serde_json::from_slice(&body)
            .map_err(|_| Verdict::Fail(format!("{what}: a {status} body that is not JSON")))?;
        let keys: Vec<&str> = json
            .as_object()
            .map(|m| m.keys().map(String::as_str).collect())
            .unwrap_or_default();
        if keys != ["error", "message"] {
            return fail(format!("{what}: the {status} body has fields {keys:?}"));
        }
        match json["error"].as_str().and_then(ErrorCode::parse) {
            Some(code) if code.status() == status => {}
            _ => {
                return fail(format!(
                    "{what}: {} is not a documented code for {status}",
                    json["error"]
                ));
            }
        }
        if json["message"].as_str().is_none_or(str::is_empty) {
            return fail(format!("{what}: an empty message"));
        }
        statuses.push(status);
    }
    Ok(format!(
        "error bodies for {statuses:?} are exactly {{error, message}} with documented codes; nothing echoed"
    ))
}

fn c13_unknown_request_fields(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let (index, request) = v.record("A", b"v", 1)?;
    let mut body = serde_json::to_value(&request).map_err(|e| Verdict::Fail(e.to_string()))?;
    body["plaintext"] = "added by a newer client".into();
    let bytes = serde_json::to_vec(&body).unwrap_or_default();
    let path = format!("/v1/secrets/{}", index.to_hex());
    expect_refusal(
        cx.call(
            Method::Put,
            &path,
            Some(&bytes),
            Auth::Owner(&v.owner()),
            Some(Pre::Create),
        ),
        400,
        "invalid_request",
        "a write with an unknown field",
    )?;
    expect_refusal(
        cx.call(Method::Get, &path, None, Auth::Owner(&v.owner()), None),
        404,
        "not_found",
        "the record after the refused write",
    )?;
    Ok("a request with an unknown field is 400 invalid_request, and nothing is stored".into())
}

fn c14_unknown_protocols(cx: &Ctx<'_>) -> Step<String> {
    for path in [
        "/v0/vault",
        "/v2/capabilities",
        "/v2/vault",
        "/v1/nothing-here",
    ] {
        let (status, body) = cx.send(Request::new(Method::Get, path))?;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if status != 404 || json["error"] != "not_found" {
            return fail(format!("{path} answered {status} {json}"));
        }
    }
    Ok("/v0, /v2 and unknown /v1 paths are 404 not_found".into())
}

fn c15_credentials_in_query(cx: &Ctx<'_>) -> Step<String> {
    if cx.target.http.is_none() {
        return skip("the query-string check belongs to the HTTP shell");
    }
    for query in ["token=abc", "sig=1", "x=gvt1_AAAA"] {
        let path = format!("/v1/vault?{query}");
        let (status, body) = cx.send(Request::new(Method::Get, &path))?;
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
        if status != 400 || json["error"] != "credential_in_query" {
            return fail(format!("?{query} answered {status} {json}"));
        }
    }
    Ok("credentials in the query string are 400 credential_in_query".into())
}

fn c16_rotation(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    v.raw
        .put("A", b"v", Pre::Create)
        .map_err(|e| Verdict::Fail(e.to_string()))?;
    let doomed = cx.mint(&v, Scope::Read)?;
    let kept = cx.mint(&v, Scope::Admin)?;
    let generation = v
        .raw
        .rotate(&[doomed.id()])
        .map_err(|e| Verdict::Fail(format!("rotating: {e}")))?;
    if generation != 2 {
        return fail(format!("the rotation went to generation {generation}"));
    }
    expect_refusal(
        cx.call(Method::Get, "/v1/vault", None, Auth::Token(&doomed), None),
        401,
        "unauthorized",
        "the revoked token",
    )?;
    let reopened = RawVault::open_token(&cx.api, kept, "conformance")
        .map_err(|e| Verdict::Fail(format!("the surviving token no longer verifies: {e}")))?;
    match reopened.get("A", None) {
        Ok((1, _)) => Ok(
            "rotation to generation 2 revoked one token; the other reads version 1 under new keys"
                .into(),
        ),
        other => fail(format!("the surviving token reads {other:?}")),
    }
}

fn c17_children(cx: &Ctx<'_>) -> Step<String> {
    let v = cx.vault()?;
    let read = cx.mint(&v, Scope::Read)?;
    let append = cx.mint(&v, Scope::Append)?;
    expect_refusal(
        cx.call(
            Method::Get,
            "/v1/vault/children",
            None,
            Auth::Token(&read),
            None,
        ),
        403,
        "forbidden",
        "a read token reading the children record",
    )?;
    expect_refusal(
        cx.call(
            Method::Put,
            "/v1/vault/children",
            Some(b"{}"),
            Auth::Token(&append),
            Some(Pre::Update(1)),
        ),
        403,
        "forbidden",
        "an append token writing the children record",
    )?;
    v.raw
        .children()
        .map_err(|e| Verdict::Fail(format!("the owner's children record: {e}")))?;
    Ok("only the owner reads and writes the children record".into())
}

/// Every case, in order.
pub fn cases() -> Vec<Case> {
    vec![
        Case {
            id: "C01",
            anchor: "http-api.md#6",
            title: "capabilities",
            run: c01_capabilities,
        },
        Case {
            id: "C02",
            anchor: "protocol.md#2",
            title: "vault lifecycle",
            run: c02_lifecycle,
        },
        Case {
            id: "C03",
            anchor: "http-api.md#4.2",
            title: "a write without a precondition is 428",
            run: c03_precondition_required,
        },
        Case {
            id: "C04",
            anchor: "http-api.md#4.2",
            title: "failed preconditions are 412",
            run: c04_precondition_failed,
        },
        Case {
            id: "C05",
            anchor: "protocol.md#6",
            title: "a signed version other than the assigned one",
            run: c05_version_mismatch,
        },
        Case {
            id: "C06",
            anchor: "protocol.md#7",
            title: "history and tombstones",
            run: c06_history,
        },
        Case {
            id: "C07",
            anchor: "protocol.md#7",
            title: "listing and pagination",
            run: c07_listing,
        },
        Case {
            id: "C08",
            anchor: "http-api.md#2",
            title: "server-side scope policy",
            run: c08_scopes,
        },
        Case {
            id: "C09",
            anchor: "http-api.md#6",
            title: "quotas as advertised",
            run: c09_quotas,
        },
        Case {
            id: "C10",
            anchor: "http-api.md#3",
            title: "uniform 401",
            run: c10_uniform_401,
        },
        Case {
            id: "C11",
            anchor: "http-api.md#4.4",
            title: "responses a browser will not render",
            run: c11_not_renderable,
        },
        Case {
            id: "C12",
            anchor: "http-api.md#5",
            title: "error bodies and codes",
            run: c12_error_bodies,
        },
        Case {
            id: "C13",
            anchor: "http-api.md#7.1",
            title: "unknown request fields refused",
            run: c13_unknown_request_fields,
        },
        Case {
            id: "C14",
            anchor: "http-api.md#1",
            title: "unknown protocol versions in the path",
            run: c14_unknown_protocols,
        },
        Case {
            id: "C15",
            anchor: "http-api.md#4.1",
            title: "credentials in the query string",
            run: c15_credentials_in_query,
        },
        Case {
            id: "C16",
            anchor: "protocol.md#8",
            title: "rotation that revokes a token",
            run: c16_rotation,
        },
        Case {
            id: "C17",
            anchor: "records.md#5",
            title: "the children record is owner-only",
            run: c17_children,
        },
    ]
}

/// What a run found, case by case.
#[derive(Debug)]
pub struct Report {
    pub target: String,
    pub results: Vec<(Case, Verdict)>,
}

impl Report {
    pub fn failed(&self) -> usize {
        self.results
            .iter()
            .filter(|(_, v)| matches!(v, Verdict::Fail(_)))
            .count()
    }

    /// One line per case, then a summary.
    pub fn lines(&self) -> Vec<String> {
        let mut out: Vec<String> = self
            .results
            .iter()
            .map(|(c, v)| {
                let (word, detail) = match v {
                    Verdict::Pass(d) => ("pass", d.as_str()),
                    Verdict::Fail(d) => ("FAIL", d.as_str()),
                    Verdict::Skip(d) => ("skip", d.as_str()),
                };
                format!("{}  {:<16} {word}: {} ({detail})", c.id, c.anchor, c.title)
            })
            .collect();
        let count = |f: fn(&Verdict) -> bool| self.results.iter().filter(|(_, v)| f(v)).count();
        out.push(format!(
            "conformance ({}): {} passed, {} failed, {} skipped",
            self.target,
            count(|v| matches!(v, Verdict::Pass(_))),
            count(|v| matches!(v, Verdict::Fail(_))),
            count(|v| matches!(v, Verdict::Skip(_))),
        ));
        out
    }
}

/// Run `cases` (every case when `None`) against `target`, then delete every
/// vault the run created.
pub fn run(target: &Target, only: Option<&[&str]>) -> Report {
    let cx = Ctx::new(target);
    let mut results = Vec::new();
    for case in cases() {
        if only.is_some_and(|o| !o.contains(&case.id)) {
            continue;
        }
        let verdict = match (case.run)(&cx) {
            Ok(detail) => Verdict::Pass(detail),
            Err(v) => v,
        };
        results.push((case, verdict));
    }
    cx.clean_up();
    Report {
        target: target.name.clone(),
        results,
    }
}
