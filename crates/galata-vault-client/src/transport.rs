//! The seam: one canonical request in, one response out.

use std::sync::Arc;

/// The methods the protocol uses. There is no other: a request cannot be
/// built with a method the protocol does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    /// `GET`
    Get,
    /// `PUT`
    Put,
    /// `POST`
    Post,
    /// `DELETE` (a signed tombstone travels in its body)
    Delete,
}

impl Method {
    /// The method as it is sent and signed.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Put => "PUT",
            Method::Post => "POST",
            Method::Delete => "DELETE",
        }
    }
}

impl std::fmt::Display for Method {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The canonical request, exactly as the protocol authenticates it: the
/// signature in `authorization` covers the method, the path and query, the
/// body's digest and both preconditions as they appear here. A transport
/// sends these bytes unchanged; it never needs to know which operation they
/// are.
///
/// `Debug` never shows the authorization value.
#[derive(Clone, Copy)]
#[non_exhaustive]
pub struct Request<'a> {
    /// The method.
    pub method: Method,
    /// The path and query, e.g. `/v1/secrets?limit=500`, relative to the
    /// server the transport is bound to.
    pub path_and_query: &'a str,
    /// The `If-Match` header, if any.
    pub if_match: Option<&'a str>,
    /// The `If-None-Match` header, if any.
    pub if_none_match: Option<&'a str>,
    /// The `Authorization` header (`GV-Sig v=1,…`), if the request is
    /// authenticated.
    pub authorization: Option<&'a str>,
    /// The JSON body, if any. A transport sends it as `application/json`.
    pub body: Option<&'a [u8]>,
}

impl<'a> Request<'a> {
    /// A request with no preconditions, no authorization and no body: what
    /// a proxy, a test or a conformance check sends when it needs a request
    /// the typed [`crate::Api`] would never build.
    pub fn new(method: Method, path_and_query: &'a str) -> Request<'a> {
        Request {
            method,
            path_and_query,
            if_match: None,
            if_none_match: None,
            authorization: None,
            body: None,
        }
    }

    /// With this `Authorization` value.
    pub fn with_authorization(mut self, authorization: Option<&'a str>) -> Request<'a> {
        self.authorization = authorization;
        self
    }

    /// With this body.
    pub fn with_body(mut self, body: Option<&'a [u8]>) -> Request<'a> {
        self.body = body;
        self
    }

    /// With this `If-Match` value.
    pub fn with_if_match(mut self, if_match: Option<&'a str>) -> Request<'a> {
        self.if_match = if_match;
        self
    }

    /// With this `If-None-Match` value.
    pub fn with_if_none_match(mut self, if_none_match: Option<&'a str>) -> Request<'a> {
        self.if_none_match = if_none_match;
        self
    }
}

impl std::fmt::Debug for Request<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Request")
            .field("method", &self.method)
            .field("path_and_query", &self.path_and_query)
            .field("if_match", &self.if_match)
            .field("if_none_match", &self.if_none_match)
            .field("authorized", &self.authorization.is_some())
            .field("body_len", &self.body.map(<[u8]>::len))
            .finish()
    }
}

/// What came back: the status, the response headers the protocol reads,
/// and the body.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Response {
    /// The HTTP status.
    pub status: u16,
    /// The `ETag` header, if any.
    pub etag: Option<String>,
    /// The `X-GV-Expires-At` header (Unix seconds), if any.
    pub expires_at: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

impl Response {
    /// A response with this status and body and no headers.
    pub fn new(status: u16, body: impl Into<Vec<u8>>) -> Response {
        Response {
            status,
            etag: None,
            expires_at: None,
            body: body.into(),
        }
    }

    /// With an `ETag` header.
    pub fn with_etag(mut self, etag: impl Into<String>) -> Response {
        self.etag = Some(etag.into());
        self
    }

    /// With an `X-GV-Expires-At` header.
    pub fn with_expires_at(mut self, expires_at: impl Into<String>) -> Response {
        self.expires_at = Some(expires_at.into());
        self
    }
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Response")
            .field("status", &self.status)
            .field("etag", &self.etag)
            .field("expires_at", &self.expires_at)
            .field("body_len", &self.body.len())
            .finish()
    }
}

/// The request did not get an answer: the server could not be reached, the
/// connection or TLS failed, the answer was cut short or too large, or it
/// was a redirect (which is never followed).
#[derive(Debug, Clone)]
pub struct TransportError {
    server: String,
    message: String,
    source: Option<Arc<dyn std::error::Error + Send + Sync>>,
}

impl TransportError {
    /// A failure reaching `server`, described by `message`.
    pub fn new(server: impl Into<String>, message: impl Into<String>) -> TransportError {
        TransportError {
            server: server.into(),
            message: message.into(),
            source: None,
        }
    }

    /// A failure reaching `server` caused by `source` (an I/O or TLS error,
    /// say), which [`std::error::Error::source`] returns.
    pub fn with_source(
        server: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> TransportError {
        TransportError {
            server: server.into(),
            message: source.to_string(),
            source: Some(Arc::new(source)),
        }
    }

    /// The server the request was for.
    pub fn server(&self) -> &str {
        &self.server
    }

    /// What went wrong, without the server.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// The underlying cause, shared.
    pub fn cause(&self) -> Option<Arc<dyn std::error::Error + Send + Sync>> {
        self.source.clone()
    }
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "could not reach {}: {}", self.server, self.message)
    }
}

impl std::error::Error for TransportError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_deref()
            .map(|e| e as &(dyn std::error::Error + 'static))
    }
}

/// Sends canonical requests to one server. `HttpTransport` is the HTTP
/// implementation; a test, a proxy or an in-process backend can bring its
/// own. The trait is deliberately small: [`crate::Api`] builds, signs and
/// interprets every request, so an implementation only moves bytes.
pub trait Transport: Send + Sync {
    /// Send one request and return the answer, whatever its status. Only a
    /// failure to get an answer is an error.
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError>;
}

impl<T: Transport + ?Sized> Transport for Arc<T> {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        (**self).send(request)
    }
}

impl<T: Transport + ?Sized> Transport for Box<T> {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        (**self).send(request)
    }
}
