//! A transport for tests (feature `test-util`): it records every canonical
//! request, and answers from a queue of canned responses, a closure, or the
//! transport it wraps. No socket is opened unless it wraps one that does.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, MutexGuard};

use crate::transport::{Method, Request, Response, Transport, TransportError};

/// One request as a transport received it.
#[derive(Clone, PartialEq, Eq)]
pub struct Recorded {
    /// The method.
    pub method: Method,
    /// The path and query.
    pub path_and_query: String,
    /// `If-Match`.
    pub if_match: Option<String>,
    /// `If-None-Match`.
    pub if_none_match: Option<String>,
    /// `Authorization` (a `GV-Sig` header, never a credential that decrypts).
    pub authorization: Option<String>,
    /// The body.
    pub body: Option<Vec<u8>>,
}

impl std::fmt::Debug for Recorded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Recorded")
            .field("method", &self.method)
            .field("path_and_query", &self.path_and_query)
            .field("if_match", &self.if_match)
            .field("if_none_match", &self.if_none_match)
            .field("authorized", &self.authorization.is_some())
            .field("body_len", &self.body.as_ref().map(Vec::len))
            .finish()
    }
}

impl From<&Request<'_>> for Recorded {
    fn from(r: &Request<'_>) -> Recorded {
        Recorded {
            method: r.method,
            path_and_query: r.path_and_query.to_owned(),
            if_match: r.if_match.map(str::to_owned),
            if_none_match: r.if_none_match.map(str::to_owned),
            authorization: r.authorization.map(str::to_owned),
            body: r.body.map(<[u8]>::to_vec),
        }
    }
}

type Responder = dyn Fn(&Recorded) -> Result<Response, TransportError> + Send + Sync;

enum Source {
    Canned,
    Closure(Box<Responder>),
    Forward(Arc<dyn Transport>),
}

/// Records requests; answers from canned responses, a closure, or a wrapped
/// transport.
pub struct RecordingTransport {
    log: Mutex<Vec<Recorded>>,
    canned: Mutex<VecDeque<Result<Response, TransportError>>>,
    source: Source,
}

impl std::fmt::Debug for RecordingTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordingTransport")
            .field("recorded", &lock(&self.log).len())
            .finish_non_exhaustive()
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

impl Default for RecordingTransport {
    fn default() -> RecordingTransport {
        RecordingTransport::new()
    }
}

impl RecordingTransport {
    /// Answers from the queue filled by [`RecordingTransport::replay`]; an
    /// empty queue answers `404 not_found`.
    pub fn new() -> RecordingTransport {
        RecordingTransport {
            log: Mutex::new(Vec::new()),
            canned: Mutex::new(VecDeque::new()),
            source: Source::Canned,
        }
    }

    /// Answers each request with `respond`.
    pub fn responding(
        respond: impl Fn(&Recorded) -> Result<Response, TransportError> + Send + Sync + 'static,
    ) -> RecordingTransport {
        RecordingTransport {
            source: Source::Closure(Box::new(respond)),
            ..RecordingTransport::new()
        }
    }

    /// Records each request, then sends it through `inner` unchanged.
    pub fn forwarding(inner: Arc<dyn Transport>) -> RecordingTransport {
        RecordingTransport {
            source: Source::Forward(inner),
            ..RecordingTransport::new()
        }
    }

    /// Queue an answer (canned mode).
    pub fn replay(&self, response: Response) {
        lock(&self.canned).push_back(Ok(response));
    }

    /// Queue a transport failure (canned mode).
    pub fn fail_next(&self, error: TransportError) {
        lock(&self.canned).push_back(Err(error));
    }

    /// Every request so far, oldest first.
    pub fn requests(&self) -> Vec<Recorded> {
        lock(&self.log).clone()
    }

    /// Forget the requests so far.
    pub fn clear(&self) {
        lock(&self.log).clear();
    }
}

impl Transport for RecordingTransport {
    fn send(&self, request: Request<'_>) -> Result<Response, TransportError> {
        let recorded = Recorded::from(&request);
        lock(&self.log).push(recorded.clone());
        match &self.source {
            Source::Canned => lock(&self.canned).pop_front().unwrap_or_else(|| {
                Ok(Response::new(
                    404,
                    br#"{"error":"not_found","message":"nothing recorded to replay"}"#.to_vec(),
                ))
            }),
            Source::Closure(f) => f(&recorded),
            Source::Forward(inner) => inner.send(request),
        }
    }
}
