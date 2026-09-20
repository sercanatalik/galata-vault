//! Audit verification against a persisted head.
//!
//! Every vault keeps a hash-chained audit log on the server. A client
//! verifies the chain from the head it verified last time, so a server that
//! rewrites or truncates its history is caught. The head lives in the
//! caller's [`crate::StateStore`] (or is passed explicitly to
//! [`crate::Vault::verify_audit`]), and moves only when the whole fetched
//! range verifies: a failure is an integrity error and leaves it unchanged.

use galata_vault_proto::audit::{Actor, AuditResult, ChainHead, RowStop};

use crate::error::Error;
use crate::state::LocalState;
use crate::vault::{Handle, RawAudit, short};

/// One audit row, its record name decrypted where this credential can.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditEntry {
    /// The row's sequence number.
    pub seq: u64,
    /// When it happened (Unix seconds).
    pub ts: i64,
    /// Who did it: the owner, or a token.
    pub actor: Actor,
    /// What was done (`secret_put`, `token_revoke`, …).
    pub action: String,
    /// The record it concerned: its name, or `#<index prefix>` where this
    /// credential cannot decrypt it.
    pub name: Option<String>,
    /// Whether the server refused it.
    pub refused: bool,
}

/// A verified stretch of the audit chain.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct AuditReport {
    /// The head now verified: keep it, and verify from it next time.
    pub head: Option<ChainHead>,
    /// How many rows came after the head verification started from.
    pub new_rows: usize,
    /// Oldest first: any earlier rows asked for (for display), then every
    /// new row.
    pub entries: Vec<AuditEntry>,
    /// Set when the server's chain continues in a row format this client
    /// does not know: those rows are neither verified nor tampered, and
    /// `head` stops before them. Upgrade to verify them.
    pub unverifiable: Option<Unverifiable>,
}

/// Rows a server served that this client cannot verify: from `from_seq`
/// on, they are in a newer row format (`docs/spec/audit.md#4`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Unverifiable {
    /// The first such row's sequence number, if it could be read.
    pub from_seq: Option<u64>,
    /// Its row format.
    pub format: u64,
}

fn report(raw: RawAudit) -> AuditReport {
    let RawAudit {
        rows,
        new_rows,
        head,
        names,
        unverifiable,
    } = raw;
    let entries = rows
        .into_iter()
        .map(|r| AuditEntry {
            seq: r.seq,
            ts: r.ts,
            action: r.action.as_str().to_owned(),
            name: r.name_hmac.map(|h| {
                names
                    .get(&h)
                    .cloned()
                    .unwrap_or_else(|| format!("#{}", short(&h)))
            }),
            refused: r.result == AuditResult::Refused,
            actor: r.actor,
        })
        .collect();
    AuditReport {
        head,
        new_rows,
        entries,
        unverifiable: unverifiable.and_then(|stop| match stop {
            RowStop::NewerFormat { seq, v } => Some(Unverifiable {
                from_seq: seq,
                format: v,
            }),
            _ => None,
        }),
    }
}

/// Verify from `known`, with up to `earlier` rows at or below it for
/// display.
pub(crate) fn verify(
    handle: &Handle,
    known: Option<ChainHead>,
    earlier: usize,
) -> Result<AuditReport, Error> {
    Ok(report(handle.verify_audit(known, earlier)?))
}

/// Verify from the head `state` records for this vault, and record the new
/// one only on success. Rows in a newer format stay unverified: the recorded
/// head stops before them.
pub(crate) fn verify_recorded(
    handle: &Handle,
    state: &mut LocalState,
    earlier: usize,
) -> Result<AuditReport, Error> {
    let key = handle.vault_id.to_hex();
    let known = state.audit.get(&key).copied();
    let report = verify(handle, known, earlier)?;
    if let Some(head) = report.head {
        state.audit.insert(key, head);
    }
    Ok(report)
}
