//! The journaled operations: token revocation, leaked-token reports, vault
//! rotation and vault deletion.
//!
//! Each one commits locally, writes its journal record while the transaction
//! is still open, and only then answers success. If the journal write fails,
//! the transaction rolls back and the caller gets `unavailable`, so an
//! acknowledged operation always survives a restore.
//!
//! The protocol has no rekey operation: a client re-roots a subtree by
//! creating vaults, writing records and children, and deleting old vaults
//!. Deletion is journaled here.

use std::collections::HashMap;

use galata_vault_proto::api::{
    AGE_HEADER, DeleteVaultResponse, ErrorCode, OWNER_SCOPE_CODE, OWNER_TOKEN_ID,
    ReportTokenRequest, RevokeResponse, RotatedVersion, RotationRequest, RotationResponse,
    report_signing_input,
};
use galata_vault_proto::audit::{Actor, AuditAction};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{Key32, TokenId, VaultId};
use galata_vault_proto::integrity::{IntegrityError, verify_ed25519};
use galata_vault_proto::record::{RecordContext, RecordKind};
use galata_vault_proto::sig::MAX_SKEW_SECS;
use galata_vault_store::{Ctx, StoreError};

use crate::auth::{Caller, Need, json};
use crate::error::CoreError;
use crate::{Core, CoreResponse};

/// `DELETE /v1/tokens/{id}`: owner or admin. Forward-only: the holder keeps
/// whatever key material it already unwrapped; a rotation is the cut-off.
pub(crate) fn revoke(core: &Core, caller: &Caller, id: &str) -> Result<CoreResponse, CoreError> {
    core.require(caller, Need::Manage, AuditAction::TokenRevoke, None)?;
    let id = TokenId::from_hex(id)
        .map_err(|_| CoreError::invalid("a token id is 32 hexadecimal characters"))?;
    let (pk, ctx) = (caller.vault.pk, caller.ctx(core.now()));
    let revoked = core.critical(|s, hook| s.revoke_tokens(pk, &[id], false, ctx, hook))?;
    CoreResponse::json(200, &RevokeResponse::new(revoked))
}

/// `POST /v1/tokens/report`: whoever holds a token string may revoke it, by
/// proving possession with the token-auth key. The token string
/// itself never reaches the core: it would open the token's bundle.
pub(crate) fn report(core: &Core, body: &[u8]) -> Result<CoreResponse, CoreError> {
    let request: ReportTokenRequest = json(body, "token report")?;
    let id = request.token_id;
    let row = core
        .store()
        .token_by_id(&id)?
        .ok_or_else(CoreError::unauthorized)?;
    let now = core.now();
    if (now - request.ts).abs() > MAX_SKEW_SECS {
        return Err(CoreError::unauthorized());
    }
    verify_ed25519(
        &row.auth_pub,
        &report_signing_input(&id, request.ts),
        &request.sig,
        "report",
    )
    .map_err(|_| CoreError::unauthorized())?;
    let ctx = Ctx {
        actor: Actor::Token(id),
        now,
    };
    let pk = row.vault_pk;
    let revoked = core.critical(|s, hook| s.revoke_tokens(pk, &[id], true, ctx, hook))?;
    CoreResponse::json(200, &RevokeResponse::new(revoked))
}

fn verify_versions(
    vault_id: VaultId,
    generation: u32,
    kind: RecordKind,
    writer_pub: &Key32,
    batch: &[RotatedVersion],
) -> Result<(), IntegrityError> {
    for v in batch {
        RecordContext::new(
            vault_id,
            generation,
            kind,
            v.name_hmac,
            v.version,
            v.written_at,
            &v.name_ct.0,
            v.value_ct.as_ref().map(|c| &c.0[..]),
        )
        .verify(writer_pub, &v.sig)?;
    }
    Ok(())
}

/// `POST /v1/vault/rotations`: owner only; one atomic batch.
pub(crate) fn rotate(core: &Core, caller: &Caller, body: &[u8]) -> Result<CoreResponse, CoreError> {
    core.require(caller, Need::Owner, AuditAction::VaultRotate, None)?;
    let request: RotationRequest = json(body, "rotation batch")?;
    if request
        .secrets
        .iter()
        .chain(&request.configs)
        .filter_map(|s| s.value_ct.as_ref())
        .any(|v| !v.0.starts_with(AGE_HEADER))
    {
        return Err(CoreError::new(
            ErrorCode::NotAgeCiphertext,
            "every re-encrypted value must be age v1 ciphertext",
        ));
    }
    let vault = &caller.vault;
    if request.from_generation != vault.generation || request.from_revision != vault.revision {
        return Err(StoreError::Conflict.into());
    }

    // The new generation: owner-signed, and linked to the current one.
    let current: Descriptor = caller.descriptor()?;
    let next = request
        .descriptor
        .verify_for(&vault.vault_id, &vault.owner_sign_pub)?;
    if !next.follows(&current) {
        return Err(CoreError::new(
            ErrorCode::KeyMismatch,
            "the new descriptor does not follow the current one",
        ));
    }
    // Every record re-signed by the new generation's writer key for its kind.
    verify_versions(
        vault.vault_id,
        next.generation,
        RecordKind::Secret,
        &next.secret_writer_pub,
        &request.secrets,
    )?;
    verify_versions(
        vault.vault_id,
        next.generation,
        RecordKind::Config,
        &next.config_writer_pub,
        &request.configs,
    )?;
    // Every bundle owner-signed for the new generation.
    request.owner_bundle.verify(
        &vault.owner_sign_pub,
        &vault.vault_id,
        &OWNER_TOKEN_ID,
        OWNER_SCOPE_CODE,
        next.generation,
    )?;
    let pk = vault.pk;
    let scopes: HashMap<TokenId, _> = core
        .store()
        .tokens(pk)?
        .into_iter()
        .map(|t| (t.token_id, t.scope))
        .collect();
    for t in &request.tokens {
        let scope = scopes.get(&t.token_id).ok_or_else(|| {
            CoreError::from(StoreError::IncompleteRotation(
                "a resealed bundle names a token not in this vault",
            ))
        })?;
        t.bundle.verify(
            &vault.owner_sign_pub,
            &vault.vault_id,
            &t.token_id,
            scope.code(),
            next.generation,
        )?;
    }

    let ctx = caller.ctx(core.now());
    let generation = core.critical(|s, hook| s.apply_rotation(pk, &request, ctx, hook))?;
    CoreResponse::json(200, &RotationResponse::new(generation))
}

/// `DELETE /v1/vault`: owner only.
pub(crate) fn delete_vault(core: &Core, caller: &Caller) -> Result<CoreResponse, CoreError> {
    core.require(caller, Need::Owner, AuditAction::VaultDelete, None)?;
    let (pk, now) = (caller.vault.pk, core.now());
    core.critical(|s, hook| s.delete_vault(pk, now, hook))?;
    CoreResponse::json(200, &DeleteVaultResponse::new(caller.vault.vault_id))
}
