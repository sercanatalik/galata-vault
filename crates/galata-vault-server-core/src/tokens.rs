//! Registering client-minted tokens (owner only), and a token's view of
//! itself.

use galata_vault_proto::api::{
    ErrorCode, RegisterTokenRequest, RegisterTokenResponse, Scope, TokenSelf,
};
use galata_vault_proto::audit::AuditAction;
use galata_vault_store::NewToken;

use crate::auth::{Caller, Need, Principal, json};
use crate::error::CoreError;
use crate::{Core, CoreResponse};

/// `POST /v1/tokens`: owner only. The core receives two public
/// keys and an owner-signed sealed bundle; it never sees the token secret,
/// and nothing it receives derives the key that opens the bundle.
pub(crate) fn register(
    core: &Core,
    caller: &Caller,
    body: &[u8],
) -> Result<CoreResponse, CoreError> {
    core.require(caller, Need::Owner, AuditAction::TokenMint, None)?;
    let r: RegisterTokenRequest = json(body, "token registration")?;
    let ttl = if r.ttl_secs == 0 {
        r.scope.default_ttl_secs()
    } else {
        r.ttl_secs
    };
    if ttl > r.scope.max_ttl_secs() {
        return Err(CoreError::new(
            ErrorCode::TtlTooLong,
            format!(
                "a {} token lives at most {} days",
                r.scope,
                r.scope.max_ttl_secs() / 86_400
            ),
        ));
    }
    if r.allow_list.is_some() && r.scope != Scope::Read {
        return Err(CoreError::invalid(
            "only read tokens take a name allow-list",
        ));
    }
    // The bundle must be the owner's, for this token, scope and generation.
    if let Err(e) = r.bundle.verify(
        &caller.vault.owner_sign_pub,
        &caller.vault.vault_id,
        &r.token_id,
        r.scope.code(),
        r.generation,
    ) {
        core.refuse(caller, AuditAction::TokenMint, None);
        return Err(e.into());
    }
    let now = core.now();
    let token = NewToken {
        token_id: r.token_id,
        auth_pub: r.auth_pub,
        box_pub: r.box_pub,
        scope: r.scope,
        expires_at: now + ttl as i64,
        bundle: r.bundle,
        generation: r.generation,
        allow_list: r.allow_list,
    };
    let limits = core.policy().limits;
    let row = core
        .store()
        .register_token(caller.vault.pk, &token, caller.ctx(now), &limits)?;
    let response = RegisterTokenResponse::new(row.token_id, row.expires_at);
    CoreResponse::json(201, &response)
}

/// `GET /v1/tokens/self`: everything the calling token needs to verify its
/// vault from the vault id in its token string.
pub(crate) fn whoami(caller: &Caller) -> Result<CoreResponse, CoreError> {
    let Principal::Token(t) = &caller.principal else {
        return Err(CoreError::invalid(
            "the owner has no token; use GET /v1/vault for the owner bundle",
        ));
    };
    let me = TokenSelf::new(
        t.token_id,
        caller.vault.vault_id,
        t.scope,
        t.expires_at,
        t.allow_list.clone(),
        caller.vault.owner_sign_pub,
        caller.vault.descriptor.clone(),
        t.bundle.clone(),
    );
    CoreResponse::json(200, &me)
}
