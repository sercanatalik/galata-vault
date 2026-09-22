//! Which operation a canonical request names: one static table of every
//! endpoint (method, path, authentication scheme), which routes every call
//! the core serves and builds `galata-vault-server`'s own routes, and which a test
//! compares with the endpoint table of `docs/spec/http-api.md#2`.
//!
//! Matching: the most specific path pattern that matches wins (a literal
//! segment before a `{placeholder}`), then the method. An unknown path is 404
//! `not_found`; a known path with another method is 400 `invalid_request`.
//!
//! Authentication runs before any path parameter or query is parsed, so a
//! malformed one gets a JSON error only once the caller is known.

use std::borrow::Cow;

use crate::backend::RecordKind;

use crate::server_core::error::CoreError;
use crate::server_core::{CanonicalRequest, Core, CoreResponse, critical, records, tokens, vaults};

type Answer = Result<CoreResponse, CoreError>;

/// How a request to an endpoint authenticates (`docs/spec/http-api.md#3`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthScheme {
    /// No `Authorization`; a request that carries one is not authenticated
    /// by it.
    None,
    /// `GV-Sig v=1`, `actor=owner`.
    Owner,
    /// `GV-Sig v=1`, `actor=token`.
    Token,
    /// `GV-Sig v=1`, by the owner or a token; the scope decides the rest.
    OwnerOrToken,
}

impl AuthScheme {
    /// How the specification's endpoint table writes it.
    pub fn as_str(self) -> &'static str {
        match self {
            AuthScheme::None => "none",
            AuthScheme::Owner => "owner",
            AuthScheme::Token => "token",
            AuthScheme::OwnerOrToken => "owner, token",
        }
    }
}

/// Who answers an endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Served {
    /// The core, through [`Core::call`]: every transport.
    Core,
    /// The HTTP shell only (`gv-server`), never the embedded transport.
    Shell,
}

/// What an endpoint does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RouteId {
    Capabilities,
    Challenges,
    CreateVault,
    Status,
    DeleteVault,
    Descriptors,
    ChildrenGet,
    ChildrenPut,
    Rotate,
    RegisterToken,
    TokenSelf,
    ReportToken,
    RevokeToken,
    Audit,
    RecordList(RecordKind),
    RecordGet(RecordKind),
    RecordPut(RecordKind),
    RecordDelete(RecordKind),
    RecordVersions(RecordKind),
    RecordVersion(RecordKind),
    Healthz,
    Readyz,
}

/// One endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Route {
    pub method: &'static str,
    /// The path, with `{name}` for a segment parameter.
    pub path: &'static str,
    pub auth: AuthScheme,
    pub served: Served,
    pub id: RouteId,
}

const fn core(method: &'static str, path: &'static str, auth: AuthScheme, id: RouteId) -> Route {
    Route {
        method,
        path,
        auth,
        served: Served::Core,
        id,
    }
}

const fn shell(path: &'static str, id: RouteId) -> Route {
    Route {
        method: "GET",
        path,
        auth: AuthScheme::None,
        served: Served::Shell,
        id,
    }
}

use AuthScheme::{None as Unauthenticated, Owner, OwnerOrToken, Token};
use RecordKind::{Config, Secret};

/// Every endpoint, literal paths before the parameterised ones they could
/// also match.
pub const ROUTES: &[Route] = &[
    core(
        "GET",
        "/v1/capabilities",
        Unauthenticated,
        RouteId::Capabilities,
    ),
    core(
        "POST",
        "/v1/challenges",
        Unauthenticated,
        RouteId::Challenges,
    ),
    core("POST", "/v1/vaults", Owner, RouteId::CreateVault),
    core("GET", "/v1/vault", OwnerOrToken, RouteId::Status),
    core("DELETE", "/v1/vault", Owner, RouteId::DeleteVault),
    core(
        "GET",
        "/v1/vault/descriptors",
        OwnerOrToken,
        RouteId::Descriptors,
    ),
    core("GET", "/v1/vault/children", Owner, RouteId::ChildrenGet),
    core("PUT", "/v1/vault/children", Owner, RouteId::ChildrenPut),
    core("POST", "/v1/vault/rotations", Owner, RouteId::Rotate),
    core("POST", "/v1/tokens", Owner, RouteId::RegisterToken),
    core("GET", "/v1/tokens/self", Token, RouteId::TokenSelf),
    core(
        "POST",
        "/v1/tokens/report",
        Unauthenticated,
        RouteId::ReportToken,
    ),
    core(
        "DELETE",
        "/v1/tokens/{token_id}",
        OwnerOrToken,
        RouteId::RevokeToken,
    ),
    core("GET", "/v1/audit", OwnerOrToken, RouteId::Audit),
    core(
        "GET",
        "/v1/secrets",
        OwnerOrToken,
        RouteId::RecordList(Secret),
    ),
    core(
        "GET",
        "/v1/secrets/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordGet(Secret),
    ),
    core(
        "PUT",
        "/v1/secrets/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordPut(Secret),
    ),
    core(
        "DELETE",
        "/v1/secrets/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordDelete(Secret),
    ),
    core(
        "GET",
        "/v1/secrets/{name_hmac}/versions",
        OwnerOrToken,
        RouteId::RecordVersions(Secret),
    ),
    core(
        "GET",
        "/v1/secrets/{name_hmac}/versions/{version}",
        OwnerOrToken,
        RouteId::RecordVersion(Secret),
    ),
    core(
        "GET",
        "/v1/configs",
        OwnerOrToken,
        RouteId::RecordList(Config),
    ),
    core(
        "GET",
        "/v1/configs/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordGet(Config),
    ),
    core(
        "PUT",
        "/v1/configs/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordPut(Config),
    ),
    core(
        "DELETE",
        "/v1/configs/{name_hmac}",
        OwnerOrToken,
        RouteId::RecordDelete(Config),
    ),
    core(
        "GET",
        "/v1/configs/{name_hmac}/versions",
        OwnerOrToken,
        RouteId::RecordVersions(Config),
    ),
    core(
        "GET",
        "/v1/configs/{name_hmac}/versions/{version}",
        OwnerOrToken,
        RouteId::RecordVersion(Config),
    ),
    shell("/healthz", RouteId::Healthz),
    shell("/readyz", RouteId::Readyz),
];

/// What a path and method name.
#[derive(Debug, PartialEq, Eq)]
pub enum Lookup<'a> {
    /// This endpoint, with its `{parameter}` segments in order.
    Found(&'static Route, Vec<&'a str>),
    /// The path is an endpoint's, the method is not.
    MethodNotAllowed,
    /// No endpoint has this path.
    NotFound,
}

/// The parameters `pattern` binds in `path`, if it matches. A parameter
/// matches one non-empty segment.
fn bind<'a>(pattern: &str, path: &'a str) -> Option<Vec<&'a str>> {
    let mut want = pattern.split('/');
    let mut got = path.split('/');
    let mut params = Vec::new();
    loop {
        match (want.next(), got.next()) {
            (None, None) => return Some(params),
            (Some(w), Some(g)) if w.starts_with('{') => {
                if g.is_empty() {
                    return None;
                }
                params.push(g);
            }
            (Some(w), Some(g)) if w == g => {}
            _ => return None,
        }
    }
}

/// The endpoint `method` and `path` (no query) name.
pub fn lookup<'a>(method: &str, path: &'a str) -> Lookup<'a> {
    let Some((first, params)) = ROUTES
        .iter()
        .find_map(|r| bind(r.path, path).map(|params| (r, params)))
    else {
        return Lookup::NotFound;
    };
    match ROUTES
        .iter()
        .find(|r| r.path == first.path && r.method == method)
    {
        Some(route) => Lookup::Found(route, params),
        None => Lookup::MethodNotAllowed,
    }
}

pub(crate) fn dispatch(core: &Core, request: &CanonicalRequest<'_>) -> Answer {
    let (path, query) = match request.path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (request.path_and_query, None),
    };
    let (route, params) = match lookup(request.method, path) {
        Lookup::Found(route, params) => (route, params),
        Lookup::MethodNotAllowed => return Err(CoreError::method_not_allowed()),
        Lookup::NotFound => return Err(CoreError::no_endpoint()),
    };
    let arg = |i: usize| params.get(i).copied().unwrap_or("");
    match route.id {
        RouteId::Capabilities => vaults::capabilities(core),
        RouteId::Challenges => vaults::challenge(core, request),
        RouteId::CreateVault => vaults::create(core, request),
        RouteId::Status => core.authed(request, |c| vaults::status(core, c)),
        RouteId::DeleteVault => core.authed(request, |c| critical::delete_vault(core, c)),
        RouteId::Descriptors => core.authed(request, |c| vaults::descriptors(core, c, query)),
        RouteId::ChildrenGet => core.authed(request, |c| vaults::children(core, c)),
        RouteId::ChildrenPut => core.authed(request, |c| vaults::put_children(core, c, request)),
        RouteId::Rotate => core.authed(request, |c| critical::rotate(core, c, request.body)),
        RouteId::RegisterToken => core.authed(request, |c| tokens::register(core, c, request.body)),
        RouteId::TokenSelf => core.authed(request, tokens::whoami),
        RouteId::ReportToken => critical::report(core, request.body),
        RouteId::RevokeToken => {
            core.authed(request, |c| critical::revoke(core, c, &param(arg(0))?))
        }
        RouteId::Audit => core.authed(request, |c| records::audit(core, c, query)),
        RouteId::RecordList(kind) => core.authed(request, |c| records::list(core, c, kind, query)),
        RouteId::RecordGet(kind) => core.authed(request, |c| {
            records::read(core, c, kind, &param(arg(0))?, None)
        }),
        RouteId::RecordPut(kind) => core.authed(request, |c| {
            records::put(core, c, kind, &param(arg(0))?, request)
        }),
        RouteId::RecordDelete(kind) => core.authed(request, |c| {
            records::delete(core, c, kind, &param(arg(0))?, request)
        }),
        RouteId::RecordVersions(kind) => core.authed(request, |c| {
            records::versions(core, c, kind, &param(arg(0))?)
        }),
        RouteId::RecordVersion(kind) => core.authed(request, |c| {
            records::read(core, c, kind, &param(arg(0))?, Some(&param(arg(1))?))
        }),
        // The HTTP shell's own endpoints: no transport reaches them here.
        RouteId::Healthz | RouteId::Readyz => Err(CoreError::no_endpoint()),
    }
}

/// A path parameter, percent-decoded as the HTTP router decoded it.
fn param(segment: &str) -> Result<Cow<'_, str>, CoreError> {
    if !segment.contains('%') {
        return Ok(Cow::Borrowed(segment));
    }
    let bad = || CoreError::invalid("a path segment is not valid percent-encoding");
    let bytes = segment.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes
                .get(i + 1..i + 3)
                .filter(|h| h.iter().all(u8::is_ascii_hexdigit))
                .ok_or_else(bad)?;
            let hex = std::str::from_utf8(hex).map_err(|_| bad())?;
            out.push(u8::from_str_radix(hex, 16).map_err(|_| bad())?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map(Cow::Owned).map_err(|_| bad())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parameters_decode_like_the_router() {
        assert_eq!(param("abc").unwrap(), "abc");
        assert_eq!(param("a%62c").unwrap(), "abc");
        for bad in ["%", "%4", "%zz", "%ff"] {
            assert!(param(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_most_specific_path_wins_then_the_method() {
        let found = |m, p| match lookup(m, p) {
            Lookup::Found(r, params) => Some((r.id, params)),
            _ => None,
        };
        assert_eq!(
            found("GET", "/v1/tokens/self"),
            Some((RouteId::TokenSelf, vec![]))
        );
        assert_eq!(
            lookup("DELETE", "/v1/tokens/self"),
            Lookup::MethodNotAllowed
        );
        assert_eq!(lookup("GET", "/v1/tokens/report"), Lookup::MethodNotAllowed);
        assert_eq!(
            found("DELETE", "/v1/tokens/abcd"),
            Some((RouteId::RevokeToken, vec!["abcd"]))
        );
        assert_eq!(
            found("GET", "/v1/configs/ab/versions/3"),
            Some((RouteId::RecordVersion(Config), vec!["ab", "3"]))
        );
        for missing in [
            "/v2/capabilities",
            "/v0/vault",
            "/v1/secrets/",
            "/v1/secrets/a/b",
            "/",
            "",
        ] {
            assert_eq!(lookup("GET", missing), Lookup::NotFound, "{missing}");
        }
        assert_eq!(lookup("PATCH", "/v1/vault"), Lookup::MethodNotAllowed);
    }

    #[test]
    fn the_table_is_unambiguous() {
        let mut seen = std::collections::BTreeSet::new();
        for r in ROUTES {
            assert!(
                seen.insert((r.method, r.path)),
                "{} {} twice",
                r.method,
                r.path
            );
            assert!(r.path.starts_with('/'), "{}", r.path);
            // Every route is reachable: no earlier pattern shadows its path.
            let concrete = r
                .path
                .replace("{token_id}", "t")
                .replace("{name_hmac}", "n")
                .replace("{version}", "1");
            assert!(
                matches!(lookup(r.method, &concrete), Lookup::Found(found, _) if found == r),
                "{} {} is shadowed",
                r.method,
                r.path
            );
        }
    }
}
