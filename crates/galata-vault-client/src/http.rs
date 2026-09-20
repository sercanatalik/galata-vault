//! The HTTP transport: ureq on rustls, configured by [`ClientBuilder`].
//!
//! Redirects are never followed (a 3xx is a transport error), no proxy is
//! used unless one is given (ureq would otherwise read `HTTPS_PROXY` and
//! friends from the environment), and answers are capped at 16 MiB.

use std::sync::Arc;
use std::time::Duration;

use crate::api::Api;
use crate::events::{Events, NoEvents};
use crate::transport::{Method, Request, Response, Transport, TransportError};

/// The default request timeout.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

const MAX_RESPONSE_BYTES: u64 = 16 << 20;

/// A builder setting that was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BuildError {
    /// The server URL is not `https://`, or `http://` to a loopback address.
    InvalidServer(String),
    /// The proxy URL does not parse.
    InvalidProxy(String),
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::InvalidServer(m) => f.write_str(m),
            BuildError::InvalidProxy(m) => write!(f, "the proxy URL is not valid: {m}"),
        }
    }
}

impl std::error::Error for BuildError {}

/// How to reach one server. Nothing is taken from the environment.
///
/// ```no_run
/// use std::time::Duration;
/// use galata_vault_client::ClientBuilder;
///
/// let api = ClientBuilder::new("https://vault.example")
///     .timeout(Duration::from_secs(30))
///     .user_agent("acme-deploy/1.2")
///     .build()?;
/// # let _ = api;
/// # Ok::<(), galata_vault_client::BuildError>(())
/// ```
#[derive(Clone)]
pub struct ClientBuilder {
    server: String,
    timeout: Duration,
    proxy: Option<String>,
    roots: Option<Vec<Vec<u8>>>,
    platform_verifier: bool,
    user_agent: String,
    events: Arc<dyn Events>,
}

impl std::fmt::Debug for ClientBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientBuilder")
            .field("server", &self.server)
            .field("timeout", &self.timeout)
            .field("proxy", &self.proxy)
            .field("roots", &self.roots.as_ref().map(Vec::len))
            .field("platform_verifier", &self.platform_verifier)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl ClientBuilder {
    /// For `server`: `https://`, or `http://` to a loopback address only,
    /// checked when the transport is built.
    pub fn new(server: &str) -> ClientBuilder {
        ClientBuilder {
            server: server.to_owned(),
            timeout: DEFAULT_TIMEOUT,
            proxy: None,
            roots: None,
            platform_verifier: false,
            user_agent: format!("galata-vault/{}", env!("CARGO_PKG_VERSION")),
            events: Arc::new(NoEvents),
        }
    }

    /// The whole-request timeout (default 120 seconds).
    pub fn timeout(mut self, timeout: Duration) -> ClientBuilder {
        self.timeout = timeout;
        self
    }

    /// Send every request through this HTTP proxy (`http://host:port`), or
    /// none. There is no proxy by default, whatever `HTTPS_PROXY` says.
    pub fn proxy(mut self, proxy: Option<&str>) -> ClientBuilder {
        self.proxy = proxy.map(str::to_owned);
        self
    }

    /// Trust exactly these root certificates (DER), for a server behind a
    /// private CA. They replace the bundled Mozilla roots: ureq has no
    /// additive mode, so list every root the server's chain may need.
    pub fn root_certificates(mut self, roots: Vec<Vec<u8>>) -> ClientBuilder {
        self.roots = Some(roots);
        self
    }

    /// Verify with the operating system's trust store instead of the
    /// bundled roots.
    #[cfg(feature = "platform-verifier")]
    pub fn platform_verifier(mut self, on: bool) -> ClientBuilder {
        self.platform_verifier = on;
        self
    }

    /// The `User-Agent` (default `galata-vault/<version>`).
    pub fn user_agent(mut self, user_agent: impl Into<String>) -> ClientBuilder {
        self.user_agent = user_agent.into();
        self
    }

    /// Where the handles built on this client report expiry, progress and
    /// warnings (default: nowhere).
    pub fn events(mut self, events: Arc<dyn Events>) -> ClientBuilder {
        self.events = events;
        self
    }

    /// The HTTP transport alone.
    pub fn build_transport(&self) -> Result<HttpTransport, BuildError> {
        let server = galata_vault_proto::url::validate_server_url(&self.server)
            .map_err(BuildError::InvalidServer)?;
        let proxy = match &self.proxy {
            Some(p) => {
                Some(ureq::Proxy::new(p).map_err(|e| BuildError::InvalidProxy(e.to_string()))?)
            }
            None => None,
        };
        let roots = if self.platform_verifier {
            ureq::tls::RootCerts::PlatformVerifier
        } else {
            match &self.roots {
                Some(roots) => {
                    let certs: Vec<ureq::tls::Certificate<'static>> = roots
                        .iter()
                        .map(|der| ureq::tls::Certificate::from_der(der).to_owned())
                        .collect();
                    ureq::tls::RootCerts::new_with_certs(&certs)
                }
                None => ureq::tls::RootCerts::WebPki,
            }
        };
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(self.timeout))
            // Explicitly: ureq's default reads the proxy from the environment.
            .proxy(proxy)
            .user_agent(self.user_agent.as_str())
            .tls_config(ureq::tls::TlsConfig::builder().root_certs(roots).build())
            .build()
            .into();
        Ok(HttpTransport { agent, server })
    }

    /// The typed API over the HTTP transport, reporting to this builder's
    /// observer.
    pub fn build(&self) -> Result<Api, BuildError> {
        Ok(Api::new(self.build_transport()?).with_events(self.events.clone()))
    }
}

/// Requests to one server over HTTP. Cheap to clone: the connection pool is
/// shared.
#[derive(Clone)]
pub struct HttpTransport {
    agent: ureq::Agent,
    server: String,
}

impl std::fmt::Debug for HttpTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpTransport")
            .field("server", &self.server)
            .finish_non_exhaustive()
    }
}

impl HttpTransport {
    /// The server, without a trailing slash.
    pub fn server(&self) -> &str {
        &self.server
    }

    fn fail(&self, e: ureq::Error) -> TransportError {
        match e {
            ureq::Error::Io(io) => TransportError::with_source(&self.server, io),
            other => TransportError::with_source(&self.server, other),
        }
    }
}

fn with_headers<B>(
    mut rb: ureq::RequestBuilder<B>,
    request: &Request<'_>,
) -> ureq::RequestBuilder<B> {
    if let Some(a) = request.authorization {
        rb = rb.header("authorization", a);
    }
    if let Some(v) = request.if_match {
        rb = rb.header("if-match", v);
    }
    if let Some(v) = request.if_none_match {
        rb = rb.header("if-none-match", v);
    }
    if request.body.is_some() {
        rb = rb.header("content-type", "application/json");
    }
    rb
}

impl Transport for HttpTransport {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let url = format!("{}{}", self.server, request.path_and_query);
        let payload = request.body.unwrap_or(&[]);
        let result = match (request.method, request.body) {
            (Method::Get, _) => with_headers(self.agent.get(&url), &request).call(),
            (Method::Delete, None) => with_headers(self.agent.delete(&url), &request).call(),
            // A signed tombstone travels in a DELETE body.
            (Method::Delete, Some(_)) => {
                with_headers(self.agent.delete(&url).force_send_body(), &request).send(payload)
            }
            (Method::Post, _) => with_headers(self.agent.post(&url), &request).send(payload),
            (Method::Put, _) => with_headers(self.agent.put(&url), &request).send(payload),
        };
        let mut response = result.map_err(|e| self.fail(e))?;
        let status = response.status().as_u16();
        if (300..400).contains(&status) {
            return Err(TransportError::new(
                &self.server,
                format!("the server answered {status} with a redirect, which is never followed"),
            ));
        }
        let header = |name: &str| {
            response
                .headers()
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned)
        };
        let etag = header("etag");
        let expires_at = header("x-gv-expires-at");
        let body = response
            .body_mut()
            .with_config()
            .limit(MAX_RESPONSE_BYTES)
            .read_to_vec()
            .map_err(|e| self.fail(e))?;
        Ok(Response {
            status,
            etag,
            expires_at,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_urls_are_checked_when_built() {
        assert_eq!(
            ClientBuilder::new("https://vault.example/")
                .build_transport()
                .unwrap()
                .server(),
            "https://vault.example"
        );
        for bad in [
            "http://vault.example",
            "http://127.0.0.1.evil.example",
            "ftp://x",
            "https://user@vault.example",
        ] {
            assert!(matches!(
                ClientBuilder::new(bad).build_transport(),
                Err(BuildError::InvalidServer(_))
            ));
        }
        assert!(matches!(
            ClientBuilder::new("https://vault.example")
                .proxy(Some("not a url"))
                .build_transport(),
            Err(BuildError::InvalidProxy(_))
        ));
    }
}
