//! Authentication, and the scope matrix.
//!
//! One credential scheme, only in the authorization value: `GV-Sig v=1`, a
//! signature over the canonical request (actor, method, path and query, body
//! digest, vault, time, nonce and preconditions; see `crate::proto::sig`).
//!
//! * `actor=owner`: verified against the vault's stored `owner_sign_pub`.
//! * `actor=token`: verified against the token's stored `auth_pub`. The core
//!   stores no token secret, and nothing it receives or stores derives the
//!   key that opens a token's bundle.
//!
//! Within ±5 minutes, and the nonce is spent only after the signature
//! verifies (so nobody can burn someone else's nonces). A `Bearer`
//! credential, a `v=1` signature, or anything else is the same 401 as every
//! other failure before the credential is proven.

use crate::backend::{Ctx, SpentKind, TokenRow, VaultRow};
use crate::proto::api::{ErrorCode, Scope};
use crate::proto::audit::{Actor, AuditAction, AuditEvent, AuditResult};
use crate::proto::descriptor::Descriptor;
use crate::proto::ids::{Key32, NameHmac, Sig64, TokenId};
use crate::proto::integrity::verify_ed25519;
use crate::proto::sig::{MAX_SKEW_SECS, SigActor, SigParams, SignedRequest};

use crate::server_core::error::CoreError;
use crate::server_core::{CanonicalRequest, Core};

/// Who signed a request.
// A token is the common caller: boxing its row would allocate on most
// requests to save stack on the owner's.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone)]
pub enum Principal {
    Owner,
    Token(TokenRow),
}

/// An authenticated caller, bound to exactly one vault.
#[derive(Debug, Clone)]
pub struct Caller {
    pub vault: VaultRow,
    pub principal: Principal,
    /// When this vault expires if nothing else touches it; `None` when the
    /// policy expires no vault for inactivity.
    pub expires_at: Option<i64>,
}

/// What an operation needs from the credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Need {
    ReadValues,
    WriteValues,
    ReadConfigs,
    WriteConfigs,
    Manage,
    ReadAudit,
    Owner,
}

impl Caller {
    pub fn actor(&self) -> Actor {
        match &self.principal {
            Principal::Owner => Actor::Owner,
            Principal::Token(t) => Actor::Token(t.token_id),
        }
    }

    pub fn is_owner(&self) -> bool {
        matches!(self.principal, Principal::Owner)
    }

    pub fn scope(&self) -> Option<Scope> {
        match &self.principal {
            Principal::Owner => None,
            Principal::Token(t) => Some(t.scope),
        }
    }

    pub(crate) fn ctx(&self, now: i64) -> Ctx {
        Ctx {
            actor: self.actor(),
            now,
        }
    }

    /// The current generation's descriptor. It was verified before it was
    /// stored, so it is decoded here, not verified again.
    pub(crate) fn descriptor(&self) -> Result<Descriptor, CoreError> {
        self.vault.descriptor.decode_unverified().map_err(|e| {
            CoreError::internal().logged(format!("a stored descriptor does not decode: {e}"))
        })
    }

    pub(crate) fn can(&self, need: Need) -> bool {
        let Some(scope) = self.scope() else {
            return true; // the owner can do everything
        };
        match need {
            Need::ReadValues => scope.can_read_values(),
            Need::WriteValues => scope.can_write_values(),
            Need::ReadConfigs => scope.can_read_configs(),
            Need::WriteConfigs => scope.can_write_configs(),
            Need::Manage => scope.can_manage(),
            Need::ReadAudit => scope.can_read_audit(),
            Need::Owner => false,
        }
    }

    /// The read-token allow-list. Enforced here only: a read token holds the
    /// vault private key, so this is policy, not cryptography.
    pub(crate) fn allows_name(&self, name: &NameHmac) -> bool {
        match &self.principal {
            Principal::Token(TokenRow {
                allow_list: Some(list),
                ..
            }) => list.contains(name),
            _ => true,
        }
    }
}

impl Core {
    /// Refuse, and audit the refusal, if the credential lacks `need`.
    pub(crate) fn require(
        &self,
        caller: &Caller,
        need: Need,
        action: AuditAction,
        name: Option<NameHmac>,
    ) -> Result<(), CoreError> {
        if caller.can(need) {
            return Ok(());
        }
        self.refuse(caller, action, name);
        Err(CoreError::forbidden())
    }

    /// Record a refused attempt. Best effort: an audit write failing must
    /// not turn a 403 into a 500.
    pub(crate) fn refuse(&self, caller: &Caller, action: AuditAction, name: Option<NameHmac>) {
        let event = AuditEvent::simple(caller.actor(), action, name, AuditResult::Refused);
        if let Err(e) = self.store().record(caller.vault.pk, event, self.now()) {
            self.warn(&format!("could not audit a refused request: {e}"));
        }
    }
}

/// Verify a request signature against `public`, within the skew window.
/// The preconditions are part of what is signed.
pub(crate) fn verify_request(
    public: &Key32,
    request: &CanonicalRequest<'_>,
    params: &SigParams,
    now: i64,
) -> Result<(), CoreError> {
    if (now - params.ts).abs() > MAX_SKEW_SECS {
        return Err(CoreError::unauthorized());
    }
    let signed = SignedRequest {
        method: request.method,
        path_and_query: request.path_and_query,
        body: request.body,
        if_match: request.if_match,
        if_none_match: request.if_none_match,
    };
    verify_ed25519(
        public,
        &params.signing_input(&signed),
        &Sig64(params.sig),
        "request",
    )
    .map_err(|_| CoreError::unauthorized())
}

/// Spend a request-signature nonce. A replay within the skew window is a 401.
pub(crate) fn spend_nonce(core: &Core, params: &SigParams) -> Result<(), CoreError> {
    let mut id = params.vault_id.0.to_vec();
    id.extend_from_slice(&params.nonce);
    let expires_at = params.ts + 2 * MAX_SKEW_SECS;
    core.store()
        .spend(SpentKind::Nonce, &id, expires_at, core.now())
        .map_err(|_| CoreError::unauthorized())
}

/// `None` when the policy expires no vault for inactivity.
fn expires_at(core: &Core, vault: &VaultRow, now: i64) -> Option<i64> {
    core.policy()
        .idle_secs()
        .map(|idle| vault.last_active_at.max(now) + idle)
}

/// Never true when expiry is off.
fn expired(core: &Core, vault: &VaultRow, now: i64) -> bool {
    core.policy()
        .idle_secs()
        .is_some_and(|idle| vault.last_active_at + idle < now)
}

pub(crate) fn authenticate(
    core: &Core,
    request: &CanonicalRequest<'_>,
) -> Result<Caller, CoreError> {
    let header = request.authorization.ok_or_else(CoreError::unauthorized)?;
    // `Bearer …`, `v=1` and anything malformed fail here, uniformly.
    let params = SigParams::parse(header).map_err(|_| CoreError::unauthorized())?;
    let now = core.now();
    let caller = match params.actor {
        SigActor::Owner => owner_auth(core, request, &params, now)?,
        SigActor::Token(id) => token_auth(core, request, &params, id, now)?,
        // An actor kind this server does not know authenticates nothing.
    };
    core.store().touch(caller.vault.pk, now)?;
    Ok(caller)
}

fn owner_auth(
    core: &Core,
    request: &CanonicalRequest<'_>,
    params: &SigParams,
    now: i64,
) -> Result<Caller, CoreError> {
    let vault = core
        .store()
        .vault_by_id(&params.vault_id)?
        .ok_or_else(CoreError::unauthorized)?;
    verify_request(&vault.owner_sign_pub, request, params, now)?;
    if expired(core, &vault, now) {
        return Err(CoreError::unauthorized());
    }
    spend_nonce(core, params)?;
    Ok(Caller {
        expires_at: expires_at(core, &vault, now),
        vault,
        principal: Principal::Owner,
    })
}

fn token_auth(
    core: &Core,
    request: &CanonicalRequest<'_>,
    params: &SigParams,
    id: TokenId,
    now: i64,
) -> Result<Caller, CoreError> {
    let row = core
        .store()
        .token_by_id(&id)?
        .ok_or_else(CoreError::unauthorized)?;
    let vault = core
        .store()
        .vault_by_pk(row.vault_pk)?
        .ok_or_else(CoreError::unauthorized)?;
    // The token names its vault in the signature; a token of another vault
    // is unknown here.
    if vault.vault_id != params.vault_id {
        return Err(CoreError::unauthorized());
    }
    verify_request(&row.auth_pub, request, params, now)?;
    // An expired vault is about to be swept; once it is, its tokens are
    // unknown. Answer the same way before the sweep as after it.
    if expired(core, &vault, now) {
        return Err(CoreError::unauthorized());
    }
    spend_nonce(core, params)?;
    // Only a holder who proved possession learns that the token expired.
    if row.expires_at <= now {
        return Err(CoreError::new(
            ErrorCode::TokenExpired,
            "this token has expired",
        ));
    }
    Ok(Caller {
        expires_at: expires_at(core, &vault, now),
        vault,
        principal: Principal::Token(row),
    })
}

/// Parse a JSON body. The error names the type, never the input, so a
/// value can never be echoed back.
pub(crate) fn json<T: serde::de::DeserializeOwned>(
    body: &[u8],
    what: &str,
) -> Result<T, CoreError> {
    serde_json::from_slice(body).map_err(|e| {
        CoreError::invalid(format!(
            "the body is not a valid {what} (line {}, column {})",
            e.line(),
            e.column()
        ))
    })
}
