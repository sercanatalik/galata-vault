//! The typed operations over any transport. `Api` builds each canonical
//! request, signs it as its holder (the
//! signature covers the method, path, body digest and preconditions exactly
//! as sent), sends it, and maps the answer.

use std::sync::{Arc, OnceLock};

use crate::keys::{OwnerKeys, TokenKeys};
use crate::proto::api::{
    AuditPage, Capabilities, ChallengePurpose, ChallengeRequest, ChallengeResponse,
    CreateVaultRequest, CreateVaultResponse, DeleteRecordRequest, DescriptorList, ErrorCode,
    PROTOCOL, PutSecretRequest, PutSecretResponse, RegisterTokenRequest, RegisterTokenResponse,
    ReportTokenRequest, RevokeResponse, RotationRequest, RotationResponse, SecretList,
    SecretVersion, TokenSelf, VaultStatus, VersionList, VersionMeta,
};
use crate::proto::children::ChildrenBlob;
use crate::proto::ids::{NameHmac, TokenId};
use crate::proto::record::RecordKind;
use crate::proto::sig::SignedRequest;
use crate::proto::tolerant::Tolerant;
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::client::events::{Events, NoEvents};
use crate::client::transport::{Method, Request, Transport, TransportError};

/// The server's largest audit page.
pub const AUDIT_PAGE: usize = 1000;
/// The page size a record listing asks for.
pub const LIST_PAGE: usize = 500;

/// The collection a record kind lives in.
pub fn records_path(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Secret => "/v1/secrets",
        RecordKind::Config => "/v1/configs",
        // galata-vault-proto and this crate move together: a kind added there gets its
        // collection here in the same change.
    }
}

/// Who signs a request.
#[derive(Clone, Copy)]
pub enum Auth<'a> {
    /// Unauthenticated (challenges, leak reports).
    None,
    /// The vault's owner key.
    Owner(&'a OwnerKeys),
    /// A token's token-auth key.
    Token(&'a TokenKeys),
}

/// How a write expects the record to stand, and so which version it signs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pre {
    /// It has never existed: `If-None-Match: *`, signing version 1.
    Create,
    /// Its latest version is this tombstone: `If-None-Match: *` revives it,
    /// signing the next version.
    Revive(u64),
    /// Its latest version is this live one: `If-Match: v`, signing `v + 1`.
    Update(u64),
}

impl Pre {
    /// The precondition for writing after `latest`.
    pub fn after(latest: Option<&VersionMeta>) -> Pre {
        match latest {
            None => Pre::Create,
            Some(m) if m.tombstone => Pre::Revive(m.version),
            Some(m) => Pre::Update(m.version),
        }
    }

    /// The version a write under this precondition signs.
    pub fn next_version(self) -> u64 {
        match self {
            Pre::Create => 1,
            Pre::Revive(v) | Pre::Update(v) => v + 1,
        }
    }

    /// The header this precondition sends (and the request signature covers).
    pub fn header(self) -> (&'static str, String) {
        match self {
            Pre::Create | Pre::Revive(_) => ("if-none-match", "*".to_owned()),
            Pre::Update(v) => ("if-match", v.to_string()),
        }
    }
}

/// A successful answer, undecoded.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Reply {
    /// The status (2xx).
    pub status: u16,
    /// The vault expiry the server announced (`X-GV-Expires-At`), if any.
    pub expires_at: Option<i64>,
    /// The `ETag` the server sent (a record version, quoted), if any.
    pub etag: Option<String>,
    /// The body.
    pub body: Vec<u8>,
}

/// A decoded successful answer, and the vault expiry it announced.
#[derive(Debug, Clone)]
pub struct Answer<T> {
    /// The decoded body.
    pub value: T,
    /// The vault expiry the server announced (`X-GV-Expires-At`), if any.
    pub expires_at: Option<i64>,
}

/// A request that did not succeed.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ApiError {
    /// No answer: see [`TransportError`].
    Transport(TransportError),
    /// The server answered with an error status.
    Refused {
        /// The HTTP status.
        status: u16,
        /// The server's error code: one this client knows, or the string of
        /// one it does not (a newer server's). `None` when the body names
        /// no code at all.
        code: Option<Tolerant<ErrorCode>>,
        /// The server's message, or `HTTP <status>` when it sent none.
        message: String,
    },
    /// The server's capabilities do not list protocol 2
    /// (`docs/spec/http-api.md#6`). Nothing authenticated was sent.
    UnsupportedProtocol {
        /// The protocol versions the server lists.
        offered: Vec<String>,
    },
    /// A success whose body is not what the protocol says it is.
    Malformed {
        /// What did not decode.
        detail: String,
    },
    /// A request body could not be encoded (never expected in practice).
    Encode {
        /// What did not encode.
        detail: String,
    },
}

impl ApiError {
    /// The server's error code, if it refused with one this client knows.
    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            ApiError::Refused { code, .. } => code.as_ref().and_then(Tolerant::get),
            _ => None,
        }
    }

    /// The server's error code as it sent it, known to this client or not.
    pub fn code_str(&self) -> Option<&str> {
        match self {
            ApiError::Refused {
                code: Some(Tolerant::Known(c)),
                ..
            } => Some(c.as_str()),
            ApiError::Refused {
                code: Some(Tolerant::Unknown(s)),
                ..
            } => Some(s),
            _ => None,
        }
    }

    /// The HTTP status of a refusal.
    pub fn status(&self) -> Option<u16> {
        match self {
            ApiError::Refused { status, .. } => Some(*status),
            _ => None,
        }
    }

    /// The stable code: the server's (`token_expired`, …, or a code this
    /// client does not know, as the server sent it), `http_<status>` for a
    /// refusal that names no code, `unsupported_protocol` for a server that
    /// does not speak protocol 2, `unreachable` for no answer, and `error`
    /// for an answer that did not decode.
    pub fn stable_code(&self) -> String {
        match self {
            ApiError::Refused { status, .. } => self
                .code_str()
                .map_or_else(|| format!("http_{status}"), str::to_owned),
            ApiError::UnsupportedProtocol { .. } => "unsupported_protocol".to_owned(),
            ApiError::Transport(_) => "unreachable".to_owned(),
            ApiError::Malformed { .. } | ApiError::Encode { .. } => "error".to_owned(),
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::Transport(t) => t.fmt(f),
            ApiError::Refused {
                status, message, ..
            } => {
                let name = self
                    .code_str()
                    .map_or_else(|| format!("HTTP {status}"), str::to_owned);
                write!(f, "the server refused ({name}): {message}")
            }
            ApiError::UnsupportedProtocol { offered } => write!(
                f,
                "the server does not speak galata-vault protocol {PROTOCOL} (it offers {}); \
                 use a client that speaks one of those",
                if offered.is_empty() {
                    "none".to_owned()
                } else {
                    offered.join(", ")
                }
            ),
            ApiError::Malformed { detail } => {
                write!(f, "the server sent an unexpected response: {detail}")
            }
            ApiError::Encode { detail } => write!(f, "could not encode the request: {detail}"),
        }
    }
}

impl std::error::Error for ApiError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ApiError::Transport(t) => Some(t),
            _ => None,
        }
    }
}

/// An error body, read loosely (`docs/spec/http-api.md#7`): a code this
/// client does not know keeps its string, and neither it nor a missing
/// message turns a refusal into a decoding failure.
#[derive(serde::Deserialize)]
struct LooseError {
    #[serde(default)]
    error: Option<serde_json::Value>,
    #[serde(default)]
    message: Option<serde_json::Value>,
}

fn refusal(status: u16, body: &[u8]) -> ApiError {
    let parsed: Option<LooseError> = serde_json::from_slice(body).ok();
    let (code, message) = match parsed {
        Some(b) => (
            b.error
                .and_then(|e| serde_json::from_value::<Tolerant<ErrorCode>>(e).ok()),
            b.message.and_then(|m| m.as_str().map(str::to_owned)),
        ),
        None => (None, None),
    };
    ApiError::Refused {
        status,
        code,
        message: message.unwrap_or_else(|| format!("HTTP {status}")),
    }
}

fn encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, ApiError> {
    serde_json::to_vec(value).map_err(|e| ApiError::Encode {
        detail: e.to_string(),
    })
}

impl Reply {
    /// Decode the body.
    pub fn json<T: DeserializeOwned>(self) -> Result<Answer<T>, ApiError> {
        let value = serde_json::from_slice(&self.body).map_err(|e| ApiError::Malformed {
            detail: e.to_string(),
        })?;
        Ok(Answer {
            value,
            expires_at: self.expires_at,
        })
    }

    /// Ignore the body.
    pub fn empty(self) -> Answer<()> {
        Answer {
            value: (),
            expires_at: self.expires_at,
        }
    }
}

/// The typed vault API over one server's transport. Cheap to clone: the
/// transport, the observer and the server's capabilities, once fetched, are
/// shared.
#[derive(Clone)]
pub struct Api {
    transport: Arc<dyn Transport>,
    events: Arc<dyn Events>,
    /// What `GET /v1/capabilities` answered, once asked; `None` inside from
    /// a server older than the document.
    capabilities: Arc<OnceLock<Option<Capabilities>>>,
}

impl std::fmt::Debug for Api {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Api").finish_non_exhaustive()
    }
}

impl Api {
    /// The API over `transport`, with notices dropped.
    pub fn new(transport: impl Transport + 'static) -> Api {
        Api::shared(Arc::new(transport))
    }

    /// The API over a shared transport.
    pub fn shared(transport: Arc<dyn Transport>) -> Api {
        Api {
            transport,
            events: Arc::new(NoEvents),
            capabilities: Arc::new(OnceLock::new()),
        }
    }

    /// The same API, sending its notices to `events`.
    pub fn with_events(mut self, events: Arc<dyn Events>) -> Api {
        self.events = events;
        self
    }

    /// The observer this API's handles report to.
    pub fn events(&self) -> &Arc<dyn Events> {
        &self.events
    }

    /// The transport underneath.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// One request: signed for `auth` over exactly what is sent, with the
    /// precondition `pre` as its `If-Match` or `If-None-Match`. A non-2xx
    /// answer is [`ApiError::Refused`].
    pub fn call(
        &self,
        method: Method,
        path_and_query: &str,
        body: Option<&[u8]>,
        auth: Auth<'_>,
        pre: Option<Pre>,
    ) -> Result<Reply, ApiError> {
        let header = pre.map(Pre::header);
        let (if_match, if_none_match) = match &header {
            Some(("if-match", v)) => (Some(v.as_str()), None),
            Some((_, v)) => (None, Some(v.as_str())),
            None => (None, None),
        };
        let signed = SignedRequest {
            method: method.as_str(),
            path_and_query,
            body: body.unwrap_or(&[]),
            if_match,
            if_none_match,
        };
        // Held only as long as the request, and cleared after.
        let authorization: Option<Zeroizing<String>> = match auth {
            Auth::None => None,
            Auth::Owner(owner) => Some(Zeroizing::new(
                owner
                    .sign_request(&signed, crate::client::now())
                    .to_header_value(),
            )),
            Auth::Token(token) => Some(Zeroizing::new(
                token
                    .sign_request(&signed, crate::client::now())
                    .to_header_value(),
            )),
        };
        let request = Request {
            method,
            path_and_query,
            if_match,
            if_none_match,
            authorization: authorization.as_ref().map(|a| a.as_str()),
            body,
        };
        let response = self.transport.send(request).map_err(ApiError::Transport)?;
        if (200..300).contains(&response.status) {
            let expires_at = response
                .expires_at
                .as_deref()
                .and_then(|v| v.trim().parse().ok());
            return Ok(Reply {
                status: response.status,
                expires_at,
                etag: response.etag,
                body: response.body,
            });
        }
        Err(refusal(response.status, &response.body))
    }

    fn get<T: DeserializeOwned>(&self, pq: &str, auth: Auth<'_>) -> Result<Answer<T>, ApiError> {
        self.call(Method::Get, pq, None, auth, None)?.json()
    }

    // ------------------------------------------------------------ vaults

    /// `GET /v1/capabilities`: what the server asks of a client, fetched once
    /// per API handle (and its clones) and remembered. A client requests a
    /// proof-of-work challenge only when `proof_of_work` is set, and keeps
    /// vaults alive only when `idle_expiry_days` is.
    ///
    /// `Ok(None)` from a server older than the document, which answers 404:
    /// such a server always asks for proof of work, and announces expiry only
    /// in its responses.
    pub fn capabilities(&self) -> Result<Option<Capabilities>, ApiError> {
        if let Some(known) = self.capabilities.get() {
            return Ok(known.clone());
        }
        let answered = match self.get::<Capabilities>("/v1/capabilities", Auth::None) {
            Ok(answer) => Some(answer.value),
            Err(e) if e.status() == Some(404) => None,
            Err(e) => return Err(e),
        };
        Ok(self.capabilities.get_or_init(|| answered).clone())
    }

    /// Refuse a server that does not speak protocol 2, before any
    /// authenticated request (`docs/spec/http-api.md#6`). Reads the
    /// capabilities once per handle. A server that predates the document
    /// (404), or a document without `protocols`, is taken as protocol 2.
    pub fn require_protocol(&self) -> Result<(), ApiError> {
        match self.capabilities()? {
            Some(c) if !c.speaks(PROTOCOL) => Err(ApiError::UnsupportedProtocol {
                offered: c.protocols,
            }),
            _ => Ok(()),
        }
    }

    /// `GET /v1/vault`: the vault's status. As the owner it also keeps the
    /// vault alive and carries the owner bundle and the token list.
    pub fn status(&self, auth: Auth<'_>) -> Result<Answer<VaultStatus>, ApiError> {
        self.get("/v1/vault", auth)
    }

    /// `GET /v1/tokens/self`: what the server holds for this token.
    pub fn token_self(&self, token: &TokenKeys) -> Result<Answer<TokenSelf>, ApiError> {
        self.get("/v1/tokens/self", Auth::Token(token))
    }

    /// `POST /v1/challenges`: a proof-of-work challenge.
    pub fn challenge(
        &self,
        purpose: ChallengePurpose,
    ) -> Result<Answer<ChallengeResponse>, ApiError> {
        let body = encode(&ChallengeRequest::new(purpose))?;
        self.call(
            Method::Post,
            "/v1/challenges",
            Some(&body),
            Auth::None,
            None,
        )?
        .json()
    }

    /// `POST /v1/vaults`: create a vault, signed by its owner key.
    pub fn create_vault(
        &self,
        owner: &OwnerKeys,
        request: &CreateVaultRequest,
    ) -> Result<Answer<CreateVaultResponse>, ApiError> {
        let body = encode(request)?;
        self.call(
            Method::Post,
            "/v1/vaults",
            Some(&body),
            Auth::Owner(owner),
            None,
        )?
        .json()
    }

    /// `DELETE /v1/vault` (owner only).
    pub fn delete_vault(&self, owner: &OwnerKeys) -> Result<Answer<()>, ApiError> {
        Ok(self
            .call(Method::Delete, "/v1/vault", None, Auth::Owner(owner), None)?
            .empty())
    }

    /// `GET /v1/vault/descriptors?after=`: the owner-signed descriptors after
    /// a generation, unverified.
    pub fn descriptors(
        &self,
        auth: Auth<'_>,
        after: u32,
    ) -> Result<Answer<DescriptorList>, ApiError> {
        self.get(&format!("/v1/vault/descriptors?after={after}"), auth)
    }

    /// `POST /v1/vault/rotations` (owner only): move to a new generation.
    pub fn rotate(
        &self,
        owner: &OwnerKeys,
        request: &RotationRequest,
    ) -> Result<Answer<RotationResponse>, ApiError> {
        let body = encode(request)?;
        self.call(
            Method::Post,
            "/v1/vault/rotations",
            Some(&body),
            Auth::Owner(owner),
            None,
        )?
        .json()
    }

    // ------------------------------------------------------------ children

    /// `GET /v1/vault/children` (owner only): the sealed children record.
    pub fn children_get(&self, owner: &OwnerKeys) -> Result<Answer<ChildrenBlob>, ApiError> {
        self.get("/v1/vault/children", Auth::Owner(owner))
    }

    /// `PUT /v1/vault/children` (owner only) under a precondition.
    pub fn children_put(
        &self,
        owner: &OwnerKeys,
        blob: &ChildrenBlob,
        pre: Pre,
    ) -> Result<Answer<()>, ApiError> {
        let body = encode(blob)?;
        Ok(self
            .call(
                Method::Put,
                "/v1/vault/children",
                Some(&body),
                Auth::Owner(owner),
                Some(pre),
            )?
            .empty())
    }

    // ------------------------------------------------------------ records

    /// One page of a record listing, after `after`.
    pub fn list(
        &self,
        auth: Auth<'_>,
        kind: RecordKind,
        after: Option<&NameHmac>,
    ) -> Result<Answer<SecretList>, ApiError> {
        let base = records_path(kind);
        let pq = match after {
            None => format!("{base}?limit={LIST_PAGE}"),
            Some(a) => format!("{base}?limit={LIST_PAGE}&after={}", a.to_hex()),
        };
        self.get(&pq, auth)
    }

    /// A record's version history, unverified.
    pub fn versions(
        &self,
        auth: Auth<'_>,
        kind: RecordKind,
        index: &NameHmac,
    ) -> Result<Answer<VersionList>, ApiError> {
        let pq = format!("{}/{}/versions", records_path(kind), index.to_hex());
        self.get(&pq, auth)
    }

    /// A record's latest version, or the version given.
    pub fn record(
        &self,
        auth: Auth<'_>,
        kind: RecordKind,
        index: &NameHmac,
        version: Option<u64>,
    ) -> Result<Answer<SecretVersion>, ApiError> {
        let base = format!("{}/{}", records_path(kind), index.to_hex());
        let pq = match version {
            None => base,
            Some(v) => format!("{base}/versions/{v}"),
        };
        self.get(&pq, auth)
    }

    /// Write a signed record version under a precondition.
    pub fn put(
        &self,
        auth: Auth<'_>,
        kind: RecordKind,
        index: &NameHmac,
        request: &PutSecretRequest,
        pre: Pre,
    ) -> Result<Answer<PutSecretResponse>, ApiError> {
        let body = encode(request)?;
        let pq = format!("{}/{}", records_path(kind), index.to_hex());
        self.call(Method::Put, &pq, Some(&body), auth, Some(pre))?
            .json()
    }

    /// Write a signed tombstone under a precondition (a `DELETE` with a body).
    pub fn delete(
        &self,
        auth: Auth<'_>,
        kind: RecordKind,
        index: &NameHmac,
        request: &DeleteRecordRequest,
        pre: Pre,
    ) -> Result<Answer<PutSecretResponse>, ApiError> {
        let body = encode(request)?;
        let pq = format!("{}/{}", records_path(kind), index.to_hex());
        self.call(Method::Delete, &pq, Some(&body), auth, Some(pre))?
            .json()
    }

    // ------------------------------------------------------------ audit

    /// One page of the audit chain after sequence number `after`.
    pub fn audit(&self, auth: Auth<'_>, after: u64) -> Result<Answer<AuditPage>, ApiError> {
        self.get(&format!("/v1/audit?after={after}&limit={AUDIT_PAGE}"), auth)
    }

    // ------------------------------------------------------------ tokens

    /// `POST /v1/tokens` (owner only): register a minted token.
    pub fn register_token(
        &self,
        owner: &OwnerKeys,
        request: &RegisterTokenRequest,
    ) -> Result<Answer<RegisterTokenResponse>, ApiError> {
        let body = encode(request)?;
        self.call(
            Method::Post,
            "/v1/tokens",
            Some(&body),
            Auth::Owner(owner),
            None,
        )?
        .json()
    }

    /// `DELETE /v1/tokens/{id}`: revoke without rotating (owner or admin).
    pub fn revoke(&self, auth: Auth<'_>, id: &TokenId) -> Result<Answer<RevokeResponse>, ApiError> {
        let pq = format!("/v1/tokens/{}", id.to_hex());
        self.call(Method::Delete, &pq, None, auth, None)?.json()
    }

    /// `POST /v1/tokens/report`: report a leaked token by proving possession.
    pub fn report_token(
        &self,
        request: &ReportTokenRequest,
    ) -> Result<Answer<RevokeResponse>, ApiError> {
        let body = encode(request)?;
        self.call(
            Method::Post,
            "/v1/tokens/report",
            Some(&body),
            Auth::None,
            None,
        )?
        .json()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preconditions_sign_the_version_the_server_assigns() {
        assert_eq!(Pre::Create.next_version(), 1);
        assert_eq!(Pre::Revive(3).next_version(), 4);
        assert_eq!(Pre::Update(3).next_version(), 4);
        assert_eq!(Pre::Revive(3).header(), ("if-none-match", "*".to_owned()));
        assert_eq!(Pre::Update(3).header(), ("if-match", "3".to_owned()));
    }

    /// Answers every request with one status and body, and counts them.
    struct Canned {
        status: u16,
        body: &'static [u8],
        calls: std::sync::atomic::AtomicUsize,
    }

    impl Canned {
        fn new(status: u16, body: &'static [u8]) -> Arc<Canned> {
            Arc::new(Canned {
                status,
                body,
                calls: Default::default(),
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl Transport for Canned {
        fn send(
            &self,
            _: Request<'_>,
        ) -> Result<crate::client::transport::Response, TransportError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(crate::client::transport::Response::new(
                self.status,
                self.body,
            ))
        }
    }

    #[test]
    fn capabilities_are_fetched_once_per_handle_and_a_404_is_remembered() {
        let server = Canned::new(
            200,
            br#"{"proof_of_work":{"difficulty":8},"idle_expiry_days":null,"limits":{}}"#,
        );
        let api = Api::shared(server.clone());
        let clone = api.clone();
        let caps = api.capabilities().unwrap().unwrap();
        assert_eq!(caps.proof_of_work.map(|p| p.difficulty), Some(8));
        assert_eq!(caps.idle_expiry_days, None);
        assert_eq!(clone.capabilities().unwrap(), Some(caps));
        assert_eq!(server.calls(), 1, "clones share the answer");

        // A server from before the document: nothing to report, remembered.
        let older = Canned::new(
            404,
            br#"{"error":"not_found","message":"no such endpoint"}"#,
        );
        let api = Api::shared(older.clone());
        assert_eq!(api.capabilities().unwrap(), None);
        assert_eq!(api.capabilities().unwrap(), None);
        assert_eq!(older.calls(), 1);

        // Any other failure is an error, and is asked again next time.
        let down = Canned::new(503, br#"{"error":"unavailable","message":"down"}"#);
        let api = Api::shared(down.clone());
        assert!(api.capabilities().is_err());
        assert!(api.capabilities().is_err());
        assert_eq!(down.calls(), 2);
    }

    #[test]
    fn refusals_keep_known_and_unknown_codes_with_their_messages() {
        let known = refusal(401, br#"{"error":"token_expired","message":"expired"}"#);
        assert_eq!(known.stable_code(), "token_expired");
        assert_eq!(known.code(), Some(ErrorCode::TokenExpired));
        // A code from a newer server: kept, with the server's message.
        let unknown = refusal(
            409,
            br#"{"error":"future_conflict","message":"try later","x":1}"#,
        );
        assert_eq!(unknown.stable_code(), "future_conflict");
        assert_eq!(unknown.code(), None);
        assert_eq!(unknown.code_str(), Some("future_conflict"));
        assert_eq!(unknown.status(), Some(409));
        assert_eq!(
            unknown.to_string(),
            "the server refused (future_conflict): try later"
        );
        // No code at all, or not a body: reported by status.
        let garbage = refusal(500, b"\xff\x00{");
        assert_eq!(garbage.stable_code(), "http_500");
        let shapeless = refusal(401, br#"{"error":7,"message":null}"#);
        assert_eq!(shapeless.stable_code(), "http_401");
        assert_eq!(
            shapeless.to_string(),
            "the server refused (HTTP 401): HTTP 401"
        );
    }

    #[test]
    fn a_server_without_protocol_2_is_refused_before_anything_else() {
        let newer = Canned::new(200, br#"{"protocols":["3"],"limits":{}}"#);
        let api = Api::shared(newer.clone());
        let e = api.require_protocol().unwrap_err();
        assert_eq!(e.stable_code(), "unsupported_protocol");
        assert!(e.to_string().contains("offers 3"), "{e}");
        assert_eq!(newer.calls(), 1);
        // Before `protocols` existed, and before capabilities existed.
        let older = Canned::new(
            200,
            br#"{"proof_of_work":null,"idle_expiry_days":null,"limits":{}}"#,
        );
        assert!(Api::shared(older).require_protocol().is_ok());
        let oldest = Canned::new(
            404,
            br#"{"error":"not_found","message":"no such endpoint"}"#,
        );
        assert!(Api::shared(oldest).require_protocol().is_ok());
    }
}
