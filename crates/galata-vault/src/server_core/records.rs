//! The records API: secrets and config documents, signed and encrypted
//! records only.
//!
//! The core indexes records by name hash, stores age ciphertext it cannot
//! open, and enforces versions, scopes, the read allow-list and quotas. Every
//! write needs a precondition, so two writers can never silently overwrite
//! each other, and every write (a tombstone included) must carry a signature
//! by the current generation's writer key for its kind, over the version the
//! precondition creates. The core checks that signature against the
//! owner-signed descriptor before storing anything: a holder with no writer
//! key cannot write, and a `config-write` token cannot write a secret.
//!
//! Secrets (`/v1/secrets`) and configs (`/v1/configs`) have the same shape in
//! separate tables. The kind decides the scope a caller needs, the writer
//! key, the quotas and the audit actions.

use crate::backend::{Precondition, RecordKind, RecordWrite, StoreError, VersionRow};
use crate::proto::api::{
    AGE_HEADER, AuditPage, DeleteRecordRequest, ErrorCode, PutSecretRequest, PutSecretResponse,
    SecretList, SecretListItem, SecretVersion, VersionList, VersionMeta,
};
use crate::proto::audit::{AuditAction, AuditEvent, AuditResult};
use crate::proto::descriptor::Descriptor;
use crate::proto::ids::{B64, Hash32, Key32, NameHmac, Sig64};
use crate::proto::record::RecordContext;

use crate::server_core::auth::{Caller, Need, json};
use crate::server_core::error::CoreError;
use crate::server_core::{CanonicalRequest, Core, CoreResponse};

const DEFAULT_PAGE: usize = 100;
const MAX_PAGE: usize = 500;
const MAX_AUDIT_PAGE: usize = 1000;

fn noun(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Secret => "secret",
        RecordKind::Config => "config",
    }
}

fn need_read(kind: RecordKind) -> Need {
    match kind {
        RecordKind::Secret => Need::ReadValues,
        RecordKind::Config => Need::ReadConfigs,
    }
}

fn need_write(kind: RecordKind) -> Need {
    match kind {
        RecordKind::Secret => Need::WriteValues,
        RecordKind::Config => Need::WriteConfigs,
    }
}

fn read_action(kind: RecordKind) -> AuditAction {
    match kind {
        RecordKind::Secret => AuditAction::SecretRead,
        RecordKind::Config => AuditAction::ConfigRead,
    }
}

fn put_action(kind: RecordKind) -> AuditAction {
    match kind {
        RecordKind::Secret => AuditAction::SecretPut,
        RecordKind::Config => AuditAction::ConfigWrite,
    }
}

fn delete_action(kind: RecordKind) -> AuditAction {
    match kind {
        RecordKind::Secret => AuditAction::SecretDelete,
        RecordKind::Config => AuditAction::ConfigDelete,
    }
}

/// The key that verifies this kind's records in a generation.
fn writer_pub(descriptor: &Descriptor, kind: RecordKind) -> &Key32 {
    match kind {
        RecordKind::Secret => &descriptor.secret_writer_pub,
        RecordKind::Config => &descriptor.config_writer_pub,
    }
}

fn parse_name(s: &str) -> Result<NameHmac, CoreError> {
    NameHmac::from_hex(s)
        .map_err(|_| CoreError::invalid("the record index must be 64 hexadecimal characters"))
}

fn parse_version(s: &str) -> Result<u64, CoreError> {
    s.parse()
        .map_err(|_| CoreError::invalid("a version is a positive whole number"))
}

pub(crate) fn query_value<'a>(query: Option<&'a str>, key: &str) -> Option<&'a str> {
    query?.split('&').find_map(|pair| {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        (k == key).then_some(v)
    })
}

fn page_limit(query: Option<&str>, default: usize, max: usize) -> Result<usize, CoreError> {
    match query_value(query, "limit") {
        None => Ok(default),
        Some(s) => Ok(s
            .parse::<usize>()
            .map_err(|_| CoreError::invalid("limit must be a whole number"))?
            .clamp(1, max)),
    }
}

fn parse_etag(value: &str) -> Result<u64, CoreError> {
    let s = value.trim();
    let s = s.strip_prefix("W/").unwrap_or(s);
    s.trim_matches('"')
        .parse()
        .map_err(|_| CoreError::invalid("If-Match must be a version number"))
}

/// The write precondition: `If-None-Match: *` to create, or `If-Match:
/// <version>` to update, and never both.
pub(crate) fn precondition(
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Result<Precondition, CoreError> {
    match (if_none_match, if_match) {
        (Some(_), Some(_)) => Err(CoreError::invalid(
            "send If-Match or If-None-Match, not both",
        )),
        (Some("*"), None) => Ok(Precondition::IfNoneMatch),
        (Some(_), None) => Err(CoreError::invalid("If-None-Match accepts only *")),
        (None, Some(v)) => parse_etag(v).map(Precondition::IfMatch),
        (None, None) => Err(CoreError::new(
            ErrorCode::PreconditionRequired,
            "a write needs If-None-Match: * to create, or If-Match: <version> to update",
        )),
    }
}

fn value_hash(value_ct: Option<&[u8]>) -> Hash32 {
    Hash32::sha256(value_ct.unwrap_or(&[]))
}

fn version_body(row: VersionRow) -> SecretVersion {
    SecretVersion::new(
        row.name_hmac,
        row.version,
        B64(row.name_ct),
        row.value_ct.map(B64),
        row.generation,
        row.written_at,
        row.written_by,
        row.tombstone,
        row.sig,
    )
}

// ---------------------------------------------------------------- list

/// `GET /v1/{secrets,configs}?after=<index>&limit=<n>`: every scope may list.
pub(crate) fn list(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    query: Option<&str>,
) -> Result<CoreResponse, CoreError> {
    let after = query_value(query, "after").map(parse_name).transpose()?;
    let limit = page_limit(query, DEFAULT_PAGE, MAX_PAGE)?;
    let rows = core
        .store()
        .list_records(caller.vault.pk, kind, after.as_ref(), limit)?;
    let next_cursor = if rows.len() == limit {
        rows.last().map(|r| r.name_hmac)
    } else {
        None
    };
    let items = rows
        .into_iter()
        .map(|h| {
            SecretListItem::new(
                h.name_hmac,
                B64(h.name_ct),
                h.version,
                h.written_at,
                h.size,
                h.tombstone,
                h.generation,
                h.value_ct_hash,
                h.sig,
            )
        })
        .collect();
    CoreResponse::json(200, &SecretList::new(items, next_cursor))
}

// ---------------------------------------------------------------- read

/// `GET /v1/{secrets,configs}/{name}` (the latest value) and
/// `…/{name}/versions/{version}` (one retained version).
pub(crate) fn read(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    name: &str,
    version: Option<&str>,
) -> Result<CoreResponse, CoreError> {
    let name = parse_name(name)?;
    let version = version.map(parse_version).transpose()?;
    core.require(caller, need_read(kind), read_action(kind), Some(name))?;
    // The read allow-list names secrets; configs are the scope's to read.
    if kind == RecordKind::Secret && !caller.allows_name(&name) {
        core.refuse(caller, read_action(kind), Some(name));
        return Err(CoreError::forbidden());
    }
    let pk = caller.vault.pk;
    let row = match version {
        None => core.store().latest_record(pk, kind, &name)?,
        Some(v) => core.store().record_version(pk, kind, &name, v)?,
    }
    .ok_or_else(|| CoreError::new(ErrorCode::NotFound, format!("no such {}", noun(kind))))?;

    if row.tombstone && version.is_none() {
        let deleted = CoreError::new(
            ErrorCode::NotFound,
            format!("the {} was deleted at version {}", noun(kind), row.version),
        );
        return Ok(deleted.to_response().with_etag(row.version));
    }

    // The row names what was read, so a client can check it against the chain.
    let event = AuditEvent {
        version: row.version,
        ct_hash: row.value_ct.as_deref().map(Hash32::sha256),
        ..AuditEvent::simple(
            caller.actor(),
            read_action(kind),
            Some(name),
            AuditResult::Ok,
        )
    };
    core.store().record(pk, event, core.now())?;
    let v = row.version;
    Ok(CoreResponse::json(200, &version_body(row))?.with_etag(v))
}

/// `GET /v1/{secrets,configs}/{name}/versions`: history metadata, with what
/// a holder that cannot decrypt needs to verify each signature, for every
/// scope.
pub(crate) fn versions(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    name: &str,
) -> Result<CoreResponse, CoreError> {
    let name = parse_name(name)?;
    let rows = core.store().record_versions(caller.vault.pk, kind, &name)?;
    if rows.is_empty() {
        return Err(CoreError::new(
            ErrorCode::NotFound,
            format!("no such {}", noun(kind)),
        ));
    }
    let versions = rows
        .into_iter()
        .map(|r| {
            VersionMeta::new(
                r.version,
                r.written_at,
                r.written_by,
                r.value_ct.as_ref().map_or(0, |v| v.len() as u32),
                r.tombstone,
                r.generation,
                value_hash(r.value_ct.as_deref()),
                Hash32::sha256(&r.name_ct),
                r.sig,
            )
        })
        .collect();
    CoreResponse::json(200, &VersionList::new(versions))
}

// ---------------------------------------------------------------- write

/// The fields every signed write carries.
struct Signed<'a> {
    name_ct: &'a [u8],
    value_ct: Option<&'a [u8]>,
    generation: u32,
    version: u64,
    written_at: i64,
    sig: &'a Sig64,
}

/// Check a write's generation and signature against the current descriptor,
/// and audit a refusal. The store re-checks the generation and the version
/// inside its transaction.
fn check_signed(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    action: AuditAction,
    name: NameHmac,
    w: &Signed<'_>,
) -> Result<(), CoreError> {
    if w.generation != caller.vault.generation {
        core.refuse(caller, action, Some(name));
        return Err(StoreError::StaleGeneration.into());
    }
    let descriptor = caller.descriptor()?;
    let ctx = RecordContext::new(
        caller.vault.vault_id,
        w.generation,
        kind.wire(),
        name,
        w.version,
        w.written_at,
        w.name_ct,
        w.value_ct,
    );
    if let Err(e) = ctx.verify(writer_pub(&descriptor, kind), w.sig) {
        core.refuse(caller, action, Some(name));
        return Err(e.into());
    }
    Ok(())
}

/// `PUT /v1/{secrets,configs}/{name}` with `If-None-Match: *` or
/// `If-Match: <version>`.
pub(crate) fn put(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    name: &str,
    request: &CanonicalRequest<'_>,
) -> Result<CoreResponse, CoreError> {
    let name = parse_name(name)?;
    core.require(caller, need_write(kind), put_action(kind), Some(name))?;
    let pre = precondition(request.if_match, request.if_none_match)?;
    let body: PutSecretRequest = json(request.body, &format!("{} write", noun(kind)))?;
    if !body.value_ct.0.starts_with(AGE_HEADER) {
        return Err(CoreError::new(
            ErrorCode::NotAgeCiphertext,
            "the value is not age v1 ciphertext; values are encrypted on the client",
        ));
    }
    check_signed(
        core,
        caller,
        kind,
        put_action(kind),
        name,
        &Signed {
            name_ct: &body.name_ct.0,
            value_ct: Some(&body.value_ct.0),
            generation: body.generation,
            version: body.version,
            written_at: body.written_at,
            sig: &body.sig,
        },
    )?;
    let write = RecordWrite {
        name_ct: body.name_ct.0,
        value_ct: Some(body.value_ct.0),
        generation: body.generation,
        version: body.version,
        written_at: body.written_at,
        sig: body.sig,
    };
    let limits = core.policy().limits;
    let version = core.store().put_record(
        caller.vault.pk,
        kind,
        &name,
        pre,
        &write,
        caller.ctx(core.now()),
        &limits,
    )?;
    let status = match pre {
        Precondition::IfNoneMatch => 201,
        Precondition::IfMatch(_) => 200,
    };
    Ok(CoreResponse::json(status, &PutSecretResponse::new(version))?.with_etag(version))
}

/// `DELETE /v1/{secrets,configs}/{name}` with `If-Match: <version>`: a signed
/// tombstone.
pub(crate) fn delete(
    core: &Core,
    caller: &Caller,
    kind: RecordKind,
    name: &str,
    request: &CanonicalRequest<'_>,
) -> Result<CoreResponse, CoreError> {
    let name = parse_name(name)?;
    core.require(caller, need_write(kind), delete_action(kind), Some(name))?;
    if request.if_none_match.is_some() {
        return Err(CoreError::invalid("a delete takes If-Match only"));
    }
    let Some(if_match) = request.if_match else {
        return Err(CoreError::new(
            ErrorCode::PreconditionRequired,
            "a delete needs If-Match: <version>",
        ));
    };
    let if_match = parse_etag(if_match)?;
    let body: DeleteRecordRequest = json(request.body, &format!("{} tombstone", noun(kind)))?;
    check_signed(
        core,
        caller,
        kind,
        delete_action(kind),
        name,
        &Signed {
            name_ct: &body.name_ct.0,
            value_ct: None,
            generation: body.generation,
            version: body.version,
            written_at: body.written_at,
            sig: &body.sig,
        },
    )?;
    let write = RecordWrite {
        name_ct: body.name_ct.0,
        value_ct: None,
        generation: body.generation,
        version: body.version,
        written_at: body.written_at,
        sig: body.sig,
    };
    let limits = core.policy().limits;
    let version = core.store().delete_record(
        caller.vault.pk,
        kind,
        &name,
        if_match,
        &write,
        caller.ctx(core.now()),
        &limits,
    )?;
    Ok(CoreResponse::json(200, &PutSecretResponse::new(version))?.with_etag(version))
}

// ---------------------------------------------------------------- audit

/// `GET /v1/audit?after=<seq>&limit=<n>`: every scope.
pub(crate) fn audit(
    core: &Core,
    caller: &Caller,
    query: Option<&str>,
) -> Result<CoreResponse, CoreError> {
    if !caller.can(Need::ReadAudit) {
        return Err(CoreError::forbidden());
    }
    let after = match query_value(query, "after") {
        None => 0,
        Some(s) => parse_version(s)?,
    };
    let limit = page_limit(query, MAX_AUDIT_PAGE, MAX_AUDIT_PAGE)?;
    let (rows, head) = core.store().audit_after(caller.vault.pk, after, limit)?;
    CoreResponse::json(200, &AuditPage::new(rows, head))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preconditions() {
        assert_eq!(
            precondition(None, None).unwrap_err().code,
            ErrorCode::PreconditionRequired
        );
        assert_eq!(precondition(None, Some("*")), Ok(Precondition::IfNoneMatch));
        assert_eq!(
            precondition(Some("\"3\""), Some("*")).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            precondition(None, Some("\"3\"")).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
        assert_eq!(
            precondition(Some("\"3\""), None),
            Ok(Precondition::IfMatch(3))
        );
        assert_eq!(
            precondition(Some("W/\"7\""), None),
            Ok(Precondition::IfMatch(7))
        );
        assert_eq!(
            precondition(Some("latest"), None).unwrap_err().code,
            ErrorCode::InvalidRequest
        );
    }

    #[test]
    fn query_values() {
        assert_eq!(query_value(Some("after=ab&limit=5"), "limit"), Some("5"));
        assert_eq!(query_value(Some("after=ab"), "limit"), None);
        assert_eq!(query_value(None, "after"), None);
        assert_eq!(page_limit(Some("limit=99999"), 100, 500), Ok(500));
        assert_eq!(page_limit(Some("limit=0"), 100, 500), Ok(1));
        assert!(page_limit(Some("limit=x"), 100, 500).is_err());
    }
}
