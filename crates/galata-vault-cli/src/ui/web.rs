//! HTTP plumbing: reading a request within limits, the checks every request
//! passes, and responses that always carry the security headers.

use std::io::Read;

use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

/// No request body is larger: a secret value is at most 16 KiB.
pub const MAX_BODY: usize = 64 * 1024;

pub const CSP: &str = "default-src 'none'; script-src 'self'; style-src 'self'; font-src 'self'; \
                       img-src 'self' data:; connect-src 'self'; form-action 'self'; \
                       base-uri 'none'; frame-ancestors 'none'";

/// The only query keys a URL may carry. URLs end up in browser history, so
/// anything else is refused, as is anything that looks like a credential.
const QUERY_KEYS: &[&str] = &["name", "with", "all"];

pub struct Req {
    pub method: String,
    pub path: String,
    query: Vec<(String, String)>,
    pub host: Option<String>,
    pub origin: Option<String>,
    /// The request carries `X-GV-UI: 1`, which a cross-origin page cannot
    /// send without a preflight that is never answered.
    pub gv_ui: bool,
    cookies: Option<String>,
    pub body: Zeroizing<Vec<u8>>,
}

impl Req {
    /// Read a request, refusing a body over [`MAX_BODY`] (413) or a URL that
    /// is not allowed (400).
    pub fn read(raw: &mut tiny_http::Request) -> Result<Req, u16> {
        let url = raw.url().to_owned();
        let (path, query) = url.split_once('?').unwrap_or((&url, ""));
        let header = |name: &'static str| {
            raw.headers()
                .iter()
                .find(|h| h.field.equiv(name))
                .map(|h| h.value.as_str().to_owned())
        };
        let (host, origin, gv_ui, cookies) = (
            header("Host"),
            header("Origin"),
            header("X-GV-UI").as_deref() == Some("1"),
            header("Cookie"),
        );
        let method = raw.method().to_string();
        let path = decode(path, false).ok_or(400u16)?;
        let query = parse_query(query).ok_or(400u16)?;
        let mut body = Zeroizing::new(Vec::new());
        raw.as_reader()
            .take(MAX_BODY as u64 + 1)
            .read_to_end(&mut body)
            .map_err(|_| 400u16)?;
        if body.len() > MAX_BODY {
            return Err(413);
        }
        Ok(Req {
            method,
            path,
            query,
            host,
            origin,
            gv_ui,
            cookies,
            body,
        })
    }

    pub fn q(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn cookie(&self, name: &str) -> Option<&str> {
        self.cookies.as_deref()?.split(';').find_map(|c| {
            let (k, v) = c.trim().split_once('=')?;
            (k == name).then_some(v)
        })
    }

    pub fn json<T: DeserializeOwned>(&self) -> anyhow::Result<T> {
        serde_json::from_slice(&self.body)
            .map_err(|e| anyhow::anyhow!("the request is not what gv ui expects: {e}"))
    }
}

fn parse_query(q: &str) -> Option<Vec<(String, String)>> {
    let mut out = Vec::new();
    for pair in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        let (k, v) = (decode(k, true)?, decode(v, true)?);
        let lower = v.to_ascii_lowercase();
        // A key or a token never rides in a URL.
        let credential = [
            galata_vault_proto::codec::KEY_PREFIX,
            galata_vault_proto::codec::TOKEN_PREFIX,
        ]
        .iter()
        .any(|p| lower.contains(p));
        if !QUERY_KEYS.contains(&k.as_str()) || credential {
            return None;
        }
        out.push((k, v));
    }
    Some(out)
}

/// Percent-decoding; `plus` also turns `+` into a space (query strings).
fn decode(s: &str, plus: bool) -> Option<String> {
    let mut out = Vec::with_capacity(s.len());
    let mut bytes = s.bytes();
    while let Some(b) = bytes.next() {
        match b {
            b'%' => {
                let hi = (bytes.next()? as char).to_digit(16)?;
                let lo = (bytes.next()? as char).to_digit(16)?;
                out.push((hi * 16 + lo) as u8);
            }
            b'+' if plus => out.push(b' '),
            b => out.push(b),
        }
    }
    String::from_utf8(out).ok()
}

/// Percent-encoding for a path segment or query value.
pub fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

pub struct Resp {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
    extra: Vec<(&'static str, String)>,
}

impl Resp {
    pub fn html(status: u16, page: maud::Markup) -> Resp {
        Resp::bytes(
            status,
            "text/html; charset=utf-8",
            page.into_string().into_bytes(),
        )
    }

    pub fn json(status: u16, value: serde_json::Value) -> Resp {
        Resp::bytes(
            status,
            "application/json",
            serde_json::to_vec(&value).expect("JSON serializes"),
        )
    }

    pub fn error(status: u16, code: &str, message: &str) -> Resp {
        Resp::json(
            status,
            serde_json::json!({ "error": code, "message": message }),
        )
    }

    pub fn empty(status: u16) -> Resp {
        Resp::bytes(status, "text/plain; charset=utf-8", Vec::new())
    }

    pub fn redirect(to: &str) -> Resp {
        let mut r = Resp::empty(303);
        r.extra.push(("Location", to.to_owned()));
        r
    }

    fn bytes(status: u16, content_type: &'static str, body: Vec<u8>) -> Resp {
        Resp {
            status,
            content_type,
            body,
            extra: Vec::new(),
        }
    }

    pub fn cookie(mut self, name: &str, value: &str) -> Resp {
        self.extra.push((
            "Set-Cookie",
            format!("{name}={value}; HttpOnly; SameSite=Strict; Path=/"),
        ));
        self
    }

    pub fn clear_cookie(mut self, name: &str) -> Resp {
        self.extra.push((
            "Set-Cookie",
            format!("{name}=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"),
        ));
        self
    }
}

/// Every response carries these, whatever it is.
pub const HEADERS: &[(&str, &str)] = &[
    ("Content-Security-Policy", CSP),
    ("Cache-Control", "no-store"),
    ("X-Content-Type-Options", "nosniff"),
    ("Referrer-Policy", "no-referrer"),
    ("X-Frame-Options", "DENY"),
    ("Server", "gv-ui"),
];

fn header(name: &str, value: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(name.as_bytes(), value.as_bytes()).expect("a valid header")
}

pub fn respond(raw: tiny_http::Request, r: Resp) {
    let mut resp = tiny_http::Response::from_data(r.body).with_status_code(r.status);
    resp.add_header(header("Content-Type", r.content_type));
    for (k, v) in HEADERS {
        resp.add_header(header(k, v));
    }
    for (k, v) in &r.extra {
        resp.add_header(header(k, v));
    }
    let _ = raw.respond(resp);
}

/// The assets compiled into `gv`. Nothing is read from disk.
pub fn asset(name: &str) -> Resp {
    let (content_type, body): (&'static str, &'static [u8]) = match name {
        "app.css" => ("text/css; charset=utf-8", include_bytes!("assets/app.css")),
        "app.js" => (
            "text/javascript; charset=utf-8",
            include_bytes!("assets/app.js"),
        ),
        "plex-sans.woff2" => ("font/woff2", include_bytes!("assets/plex-sans.woff2")),
        "plex-mono-400.woff2" => ("font/woff2", include_bytes!("assets/plex-mono-400.woff2")),
        "plex-mono-500.woff2" => ("font/woff2", include_bytes!("assets/plex-mono-500.woff2")),
        "plex-mono-600.woff2" => ("font/woff2", include_bytes!("assets/plex-mono-600.woff2")),
        "newsreader-500.woff2" => ("font/woff2", include_bytes!("assets/newsreader-500.woff2")),
        "OFL.txt" => (
            "text/plain; charset=utf-8",
            include_bytes!("assets/OFL.txt"),
        ),
        _ => return Resp::empty(404),
    };
    Resp::bytes(200, content_type, body.to_vec())
}

pub fn random_hex(bytes: usize) -> String {
    let mut b = vec![0u8; bytes];
    getrandom::fill(&mut b).expect("the operating system's random source failed");
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A 4-digit code for people to compare, uniformly drawn.
pub fn random_code() -> String {
    loop {
        let mut b = [0u8; 2];
        getrandom::fill(&mut b).expect("the operating system's random source failed");
        let n = u16::from_le_bytes(b);
        if n < 60_000 {
            return format!("{:04}", n % 10_000);
        }
    }
}

/// Equality that takes the same time wherever the strings differ.
pub fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_keys_are_allow_listed() {
        assert_eq!(
            parse_query("name=DATABASE_URL&all=1").unwrap(),
            [
                ("name".into(), "DATABASE_URL".into()),
                ("all".into(), "1".into())
            ]
        );
        assert!(parse_query("value=hunter2").is_none());
        assert!(parse_query("name=gvt1_abc").is_none());
        assert!(parse_query("name=GVK1%5Fabc").is_none());
        assert!(parse_query("name=gvt1_abc").is_none());
        assert!(parse_query("name=GVK1%5Fabc").is_none());
    }

    #[test]
    fn round_trips() {
        let s = "a b/ü?&=%";
        assert_eq!(decode(&encode(s), true).unwrap(), s);
        assert!(decode("%zz", false).is_none());
    }

    #[test]
    fn codes() {
        let c = random_code();
        assert_eq!(c.len(), 4);
        assert!(c.bytes().all(|b| b.is_ascii_digit()));
        assert_eq!(random_hex(16).len(), 32);
        assert!(same("abc", "abc") && !same("abc", "abd") && !same("abc", "ab"));
    }
}
