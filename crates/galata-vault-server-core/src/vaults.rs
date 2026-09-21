//! The capabilities document, challenges, vault creation, vault status, the
//! descriptor chain, and the owner-only children record.

use galata_vault_proto::api::{
    ChallengeRequest, CreateVaultRequest, CreateVaultResponse, DescriptorList, ErrorCode,
    OWNER_SCOPE_CODE, OWNER_TOKEN_ID, PutSecretResponse, TokenSummary, VaultStatus,
};
use galata_vault_proto::audit::{AuditAction, AuditEvent, AuditResult};
use galata_vault_proto::children::ChildrenBlob;
use galata_vault_proto::ids::VaultId;
use galata_vault_proto::sig::{SigActor, SigParams};
use galata_vault_store::{NewVault, Precondition, RecordKind, SpentKind};

use crate::auth::{Caller, Need, json, spend_nonce, verify_request};
use crate::error::CoreError;
use crate::records::{precondition, query_value};
use crate::{CanonicalRequest, Core, CoreResponse};

/// `GET /v1/capabilities`: unauthenticated, what a client needs to know
/// before it acts.
pub(crate) fn capabilities(core: &Core) -> Result<CoreResponse, CoreError> {
    CoreResponse::json(200, &core.capabilities())
}

/// `POST /v1/challenges`: a stateless proof-of-work challenge, from a policy
/// that asks for one. Otherwise there is no such endpoint.
pub(crate) fn challenge(
    core: &Core,
    request: &CanonicalRequest<'_>,
) -> Result<CoreResponse, CoreError> {
    let admission = &core.policy().admission;
    if admission.proof_of_work().is_none() {
        return Err(CoreError::no_endpoint());
    }
    let _: ChallengeRequest = json(request.body, "challenge request")?;
    CoreResponse::json(200, &admission.challenge(core.now())?)
}

/// `POST /v1/vaults`: create a vault. No account: a request signed by the
/// key whose hash is the vault id, generation 1's descriptor and owner
/// bundle, both signed by that key, and whatever the admission asks (a
/// solved challenge, where a server asks for one).
pub(crate) fn create(
    core: &Core,
    request: &CanonicalRequest<'_>,
) -> Result<CoreResponse, CoreError> {
    let body: CreateVaultRequest = json(request.body, "vault creation request")?;
    let now = core.now();

    let admitted = core.policy().admission.admit_creation(&body, now)?;
    if VaultId::from_owner_sign_pub(&body.owner_sign_pub) != body.vault_id {
        return Err(CoreError::new(
            ErrorCode::VaultIdMismatch,
            "the vault id is not the hash of the owner signing key",
        ));
    }

    // Signed by the key being registered: only its holder can create this id.
    let header = request.authorization.ok_or_else(CoreError::unauthorized)?;
    let params = SigParams::parse(header).map_err(|_| CoreError::unauthorized())?;
    if params.actor != SigActor::Owner || params.vault_id != body.vault_id {
        return Err(CoreError::unauthorized());
    }
    verify_request(&body.owner_sign_pub, request, &params, now)?;

    // Generation 1: the descriptor and the owner bundle, both owner-signed.
    let descriptor = body
        .descriptor
        .verify_for(&body.vault_id, &body.owner_sign_pub)?;
    if !descriptor.is_first() {
        return Err(CoreError::invalid(
            "a vault starts at generation 1, with a zero previous-descriptor hash",
        ));
    }
    body.owner_bundle.verify(
        &body.owner_sign_pub,
        &body.vault_id,
        &OWNER_TOKEN_ID,
        OWNER_SCOPE_CODE,
        1,
    )?;

    if let Some(admitted) = admitted {
        core.store().spend(
            SpentKind::Challenge,
            &admitted.challenge_id,
            admitted.expires_at,
            now,
        )?;
    }
    spend_nonce(core, &params)?;

    let vault = NewVault {
        vault_id: body.vault_id,
        owner_sign_pub: body.owner_sign_pub,
        owner_box_pub: body.owner_box_pub,
        descriptor: body.descriptor,
        owner_bundle: body.owner_bundle,
    };
    let row = core.store().create_vault(&vault, now)?;
    let response = CreateVaultResponse::new(
        row.vault_id,
        row.generation,
        core.policy()
            .idle_secs()
            .map(|idle| row.last_active_at + idle),
    );
    CoreResponse::json(201, &response)
}

/// `GET /v1/vault`: status for any scope, with the owner key and the current
/// descriptor every client verifies; the token list for the owner and admin
/// tokens; the owner bundle for the owner alone.
pub(crate) fn status(core: &Core, caller: &Caller) -> Result<CoreResponse, CoreError> {
    let v = &caller.vault;
    let tokens = if caller.can(Need::Manage) {
        let rows = core.store().tokens(v.pk)?;
        // A credential other than the owner key receiving the token list is
        // worth a row: it names every token's id, scope and box key. The
        // owner's own reads are not recorded, because an environment opens
        // with one and the chain would fill with them; and a lesser scope
        // reading status is not an attempt to list, so it is not a refusal
        // either. Best effort, as `Core::refuse` is: an audit write failing
        // must not turn a served status into a 500.
        if !caller.is_owner() {
            let event = AuditEvent::simple(
                caller.actor(),
                AuditAction::TokenList,
                None,
                AuditResult::Ok,
            );
            if let Err(e) = core.store().record(v.pk, event, core.now()) {
                core.warn(&format!("could not audit a token listing: {e}"));
            }
        }
        Some(
            rows.into_iter()
                .map(|t| {
                    TokenSummary::new(
                        t.token_id,
                        t.scope,
                        t.created_at,
                        t.expires_at,
                        t.box_pub,
                        t.allow_list,
                    )
                })
                .collect(),
        )
    } else {
        None
    };
    let config_count = core.store().live_records(v.pk, RecordKind::Config)?;
    let status = VaultStatus::new(
        v.vault_id,
        v.generation,
        v.revision,
        v.owner_sign_pub,
        v.owner_box_pub,
        v.descriptor.clone(),
        config_count,
        v.created_at,
        v.last_active_at,
        caller.expires_at,
        v.bytes_used,
        core.policy().limits,
        tokens,
        caller.is_owner().then(|| v.owner_bundle.clone()),
    );
    CoreResponse::json(200, &status)
}

/// `GET /v1/vault/descriptors?after=<generation>`: the owner-signed chain,
/// ascending, for any authenticated caller.
pub(crate) fn descriptors(
    core: &Core,
    caller: &Caller,
    query: Option<&str>,
) -> Result<CoreResponse, CoreError> {
    let after = match query_value(query, "after") {
        None => 0,
        Some(s) => s
            .parse::<u32>()
            .map_err(|_| CoreError::invalid("after is a generation number"))?,
    };
    let descriptors = core.store().descriptors(caller.vault.pk, after)?;
    CoreResponse::json(200, &DescriptorList::new(descriptors))
}

/// `GET /v1/vault/children`: the owner-only children record.
pub(crate) fn children(core: &Core, caller: &Caller) -> Result<CoreResponse, CoreError> {
    if !caller.is_owner() {
        return Err(CoreError::forbidden());
    }
    let blob = core
        .store()
        .children(caller.vault.pk)?
        .ok_or_else(|| CoreError::new(ErrorCode::NotFound, "this vault has no children record"))?;
    let version = blob.version;
    Ok(CoreResponse::json(200, &blob)?.with_etag(version))
}

/// `PUT /v1/vault/children` with `If-None-Match: *` or `If-Match: <version>`:
/// owner only, and the record must carry the owner's signature for the
/// version the precondition creates.
pub(crate) fn put_children(
    core: &Core,
    caller: &Caller,
    request: &CanonicalRequest<'_>,
) -> Result<CoreResponse, CoreError> {
    core.require(caller, Need::Owner, AuditAction::ChildrenWrite, None)?;
    let pre = precondition(request.if_match, request.if_none_match)?;
    let blob: ChildrenBlob = json(request.body, "children record")?;
    if let Err(e) = blob.verify(&caller.vault.vault_id, &caller.vault.owner_sign_pub) {
        core.refuse(caller, AuditAction::ChildrenWrite, None);
        return Err(e.into());
    }
    let limits = core.policy().limits;
    let version =
        core.store()
            .put_children(caller.vault.pk, pre, &blob, caller.ctx(core.now()), &limits)?;
    let status = match pre {
        Precondition::IfNoneMatch => 201,
        Precondition::IfMatch(_) => 200,
    };
    Ok(CoreResponse::json(status, &PutSecretResponse::new(version))?.with_etag(version))
}
