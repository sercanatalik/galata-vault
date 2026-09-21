//! The per-vault audit chain (`docs/spec/audit.md`).
//!
//! Every row carries the hash of the row before it, and its own hash is
//! blake3 over a fixed binary encoding of its fields. Rows hold no values,
//! no plaintext names and no addresses. Rows also record the version a write
//! or read touched and the hash of the ciphertext involved (for a rotation,
//! the new descriptor's hash), so a client can check that what it was served
//! is what the chain says was written.
//!
//! **Row formats.** Every row carries its format as `v`, and the hash covers
//! it:
//! - format 3, written by this build: the encoding starts with `v`;
//! - format 2, written before the marker existed: no `v` on the wire, and
//!   no marker in the encoding. Still read and verified.
//!
//! A row in a format this build does not know is *unverifiable*, never
//! tampered and never verified: verification stops before it and reports
//! where ([`RowStop`]).
//!
//! Every scope may fetch and verify its vault's chain. A client that
//! remembers the last head it verified can tell when a server shows it a
//! shorter or different history. The chain is computed by the server with no
//! key, so a server can still show different clients different, individually
//! consistent histories: detection needs client state or an external witness.

use serde::{Deserialize, Serialize};

use crate::ids::{Hash32, NameHmac, TokenId};
use crate::tolerant::Vocabulary;

/// The `prev` of a vault's first row.
pub const GENESIS: Hash32 = Hash32([0; 32]);
/// blake3's derive-key context for audit rows, in every row format.
pub const ROW_CONTEXT: &str = "galata-vault v1 audit row";
/// The row format a server writes.
pub const ROW_FORMAT: u8 = 1;
/// Every row format this build verifies.
pub const ROW_FORMATS: [u8; 1] = [ROW_FORMAT];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", content = "id", rename_all = "lowercase")]
#[non_exhaustive]
pub enum Actor {
    Owner,
    Token(TokenId),
}

impl Vocabulary for Actor {
    fn knows(name: &str) -> bool {
        matches!(name, "owner" | "token")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AuditAction {
    VaultCreate,
    VaultRotate,
    VaultDelete,
    VaultExpire,
    ChildrenWrite,
    TokenMint,
    TokenRevoke,
    TokenReport,
    TokenList,
    SecretPut,
    SecretDelete,
    SecretRead,
    ConfigWrite,
    ConfigDelete,
    ConfigRead,
}

impl AuditAction {
    /// Stable codes for the hash encoding. Never renumber; only append.
    /// Code 3 is unassigned.
    pub fn code(self) -> u16 {
        match self {
            AuditAction::VaultCreate => 1,
            AuditAction::VaultRotate => 2,
            AuditAction::VaultDelete => 4,
            AuditAction::VaultExpire => 5,
            AuditAction::ChildrenWrite => 6,
            AuditAction::TokenMint => 10,
            AuditAction::TokenRevoke => 11,
            AuditAction::TokenReport => 12,
            AuditAction::TokenList => 13,
            AuditAction::SecretPut => 20,
            AuditAction::SecretDelete => 21,
            AuditAction::SecretRead => 22,
            AuditAction::ConfigWrite => 30,
            AuditAction::ConfigDelete => 31,
            AuditAction::ConfigRead => 32,
        }
    }

    pub const ALL: [AuditAction; 15] = [
        AuditAction::VaultCreate,
        AuditAction::VaultRotate,
        AuditAction::VaultDelete,
        AuditAction::VaultExpire,
        AuditAction::ChildrenWrite,
        AuditAction::TokenMint,
        AuditAction::TokenRevoke,
        AuditAction::TokenReport,
        AuditAction::TokenList,
        AuditAction::SecretPut,
        AuditAction::SecretDelete,
        AuditAction::SecretRead,
        AuditAction::ConfigWrite,
        AuditAction::ConfigDelete,
        AuditAction::ConfigRead,
    ];

    /// The inverse of [`AuditAction::code`].
    pub fn from_code(code: u16) -> Option<AuditAction> {
        AuditAction::ALL.into_iter().find(|a| a.code() == code)
    }

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            AuditAction::VaultCreate => "vault_create",
            AuditAction::VaultRotate => "vault_rotate",
            AuditAction::VaultDelete => "vault_delete",
            AuditAction::VaultExpire => "vault_expire",
            AuditAction::ChildrenWrite => "children_write",
            AuditAction::TokenMint => "token_mint",
            AuditAction::TokenRevoke => "token_revoke",
            AuditAction::TokenReport => "token_report",
            AuditAction::TokenList => "token_list",
            AuditAction::SecretPut => "secret_put",
            AuditAction::SecretDelete => "secret_delete",
            AuditAction::SecretRead => "secret_read",
            AuditAction::ConfigWrite => "config_write",
            AuditAction::ConfigDelete => "config_delete",
            AuditAction::ConfigRead => "config_read",
        }
    }

    /// The inverse of [`AuditAction::as_str`].
    pub fn parse(s: &str) -> Option<AuditAction> {
        AuditAction::ALL.into_iter().find(|a| a.as_str() == s)
    }
}

impl std::fmt::Display for AuditAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Vocabulary for AuditAction {
    fn knows(name: &str) -> bool {
        AuditAction::parse(name).is_some()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum AuditResult {
    Ok,
    /// An authenticated attempt refused by a precondition, scope or quota.
    Refused,
}

impl AuditResult {
    pub fn code(self) -> u8 {
        match self {
            AuditResult::Ok => 0,
            AuditResult::Refused => 1,
        }
    }

    pub fn from_code(code: u8) -> Option<AuditResult> {
        match code {
            0 => Some(AuditResult::Ok),
            1 => Some(AuditResult::Refused),
            _ => None,
        }
    }
}

/// Everything a row records except its position in the chain. What a server
/// appends; not a wire type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditEvent {
    pub actor: Actor,
    pub action: AuditAction,
    pub name_hmac: Option<NameHmac>,
    /// The token an action was done *to* (minted, revoked, reported), where
    /// that differs from the actor.
    pub subject: Option<TokenId>,
    pub result: AuditResult,
    /// The record version written or read; 0 where no version applies.
    pub version: u64,
    /// SHA-256 of the stored ciphertext written or read; for a rotation, the
    /// new descriptor's hash. `None` where nothing applies.
    pub ct_hash: Option<Hash32>,
}

impl AuditEvent {
    /// An event with no version and no ciphertext hash.
    pub fn simple(
        actor: Actor,
        action: AuditAction,
        name_hmac: Option<NameHmac>,
        result: AuditResult,
    ) -> AuditEvent {
        AuditEvent {
            actor,
            action,
            name_hmac,
            subject: None,
            result,
            version: 0,
            ct_hash: None,
        }
    }
}

/// One row as served. Every field is hashed, so a row refuses a field it
/// does not know: a new field is a new row format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct AuditRow {
    /// The row format.
    pub v: u8,
    pub seq: u64,
    pub ts: i64,
    pub actor: Actor,
    pub action: AuditAction,
    pub name_hmac: Option<NameHmac>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<TokenId>,
    pub result: AuditResult,
    #[serde(default)]
    pub version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ct_hash: Option<Hash32>,
    pub prev: Hash32,
    pub hash: Hash32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChainHead {
    pub seq: u64,
    pub hash: Hash32,
}

impl ChainHead {
    pub fn new(seq: u64, hash: Hash32) -> ChainHead {
        ChainHead { seq, hash }
    }
}

/// Where a served page stops being rows this build can verify.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RowStop {
    /// A row in a row format newer than this build knows: every row from it
    /// on is unverifiable here, and neither tampered nor verified.
    NewerFormat {
        /// The row's `seq`, if it could be read.
        seq: Option<u64>,
        /// Its format.
        v: u64,
    },
    /// A row in a known format naming an action or actor this build does not
    /// know: it cannot be hashed, so verification refuses
    /// (`unsupported_by_client`).
    UnknownValue {
        /// The row's `seq`, if it could be read.
        seq: Option<u64>,
        /// `action` or `actor`.
        field: &'static str,
        /// The name it carried.
        value: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("audit rows are not contiguous: expected seq {expected}, found {got}")]
    Gap { expected: u64, got: u64 },
    #[error("audit row {seq} does not link to the row before it")]
    BrokenLink { seq: u64 },
    #[error("audit row {seq} has been altered: its hash does not match its contents")]
    BadHash { seq: u64 },
    #[error(
        "possible rollback: this client verified the chain up to seq {known}, the server now ends at {server}"
    )]
    Rollback { known: u64, server: u64 },
    #[error("possible fork: the row at seq {seq} differs from the one this client verified")]
    Fork { seq: u64 },
    #[error("the server's audit head does not match the rows it served")]
    HeadMismatch,
    #[error("audit row {seq} is in row format {v}, which this build cannot hash")]
    UnknownFormat { seq: u64, v: u8 },
    #[error(
        "audit row {} records the {field} {value:?}, which this client does not know; upgrade it to verify this chain",
        seq.map_or_else(|| "?".to_owned(), |s| s.to_string())
    )]
    UnknownValue {
        seq: Option<u64>,
        field: &'static str,
        value: String,
    },
}

/// blake3 in derive-key mode, context [`ROW_CONTEXT`].
fn row_hash(input: &[u8]) -> Hash32 {
    let mut h = blake3::Hasher::new_derive_key(ROW_CONTEXT);
    h.update(input);
    Hash32(*h.finalize().as_bytes())
}

fn opt(out: &mut Vec<u8>, bytes: Option<&[u8]>) {
    match bytes {
        None => out.push(0),
        Some(b) => {
            out.push(1);
            out.extend_from_slice(b);
        }
    }
}

impl AuditRow {
    /// Build a row, in the current format, from an event and compute its hash.
    pub fn from_event(seq: u64, ts: i64, prev: Hash32, e: AuditEvent) -> AuditRow {
        let mut row = AuditRow::stored(ROW_FORMAT, seq, ts, prev, GENESIS, e);
        let mut input = vec![ROW_FORMAT];
        row.hash_fields(&mut input);
        row.hash = row_hash(&input);
        row
    }

    /// A row exactly as it was stored: its format, position, event and the
    /// hash recorded for it (which a verifier recomputes).
    pub fn stored(v: u8, seq: u64, ts: i64, prev: Hash32, hash: Hash32, e: AuditEvent) -> AuditRow {
        AuditRow {
            v,
            seq,
            ts,
            actor: e.actor,
            action: e.action,
            name_hmac: e.name_hmac,
            subject: e.subject,
            result: e.result,
            version: e.version,
            ct_hash: e.ct_hash,
            prev,
            hash,
        }
    }

    /// The event this row records.
    pub fn event(&self) -> AuditEvent {
        AuditEvent {
            actor: self.actor,
            action: self.action,
            name_hmac: self.name_hmac,
            subject: self.subject,
            result: self.result,
            version: self.version,
            ct_hash: self.ct_hash,
        }
    }

    /// The exact bytes the row hash covers (`docs/spec/audit.md#2`), `hash`
    /// excluded:
    ///
    /// ```text
    /// v(1) ‖ seq(8) ‖ ts(8) ‖ opt(actor token id) ‖ action(2)
    /// ‖ opt(name index) ‖ result(1) ‖ opt(subject) ‖ version(8) ‖ opt(ct_hash) ‖ prev(32)
    /// ```
    ///
    /// `None` for a row format this build does not know.
    pub fn hash_input(&self) -> Option<Vec<u8>> {
        let mut out = Vec::with_capacity(1 + 8 + 8 + 17 + 2 + 33 + 1 + 17 + 8 + 33 + 32);
        match self.v {
            ROW_FORMAT => out.push(ROW_FORMAT),
            _ => return None,
        }
        self.hash_fields(&mut out);
        Some(out)
    }

    /// Every field after the format byte, as [`AuditRow::hash_input`] lays
    /// them out.
    fn hash_fields(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_be_bytes());
        out.extend_from_slice(&self.ts.to_be_bytes());
        match self.actor {
            Actor::Owner => opt(out, None),
            Actor::Token(id) => opt(out, Some(&id.0)),
        }
        out.extend_from_slice(&self.action.code().to_be_bytes());
        opt(out, self.name_hmac.as_ref().map(|n| &n.0[..]));
        out.push(self.result.code());
        opt(out, self.subject.as_ref().map(|s| &s.0[..]));
        out.extend_from_slice(&self.version.to_be_bytes());
        opt(out, self.ct_hash.as_ref().map(|c| &c.0[..]));
        out.extend_from_slice(&self.prev.0);
    }

    /// blake3 in derive-key mode, context [`ROW_CONTEXT`], over
    /// [`AuditRow::hash_input`]. `None` for a row format this build does not
    /// know.
    pub fn expected_hash(&self) -> Option<Hash32> {
        Some(row_hash(&self.hash_input()?))
    }

    pub fn head(&self) -> ChainHead {
        ChainHead {
            seq: self.seq,
            hash: self.hash,
        }
    }
}

/// Read a page's rows as served (`docs/spec/audit.md#4`): every row up to
/// the first one this build cannot verify, and where it stopped. A row in a
/// newer format stops the page; so does a row in a known format naming an
/// action or actor this build does not know. Anything else that does not
/// parse is malformed.
pub fn read_rows(
    values: Vec<serde_json::Value>,
) -> Result<(Vec<AuditRow>, Option<RowStop>), String> {
    let mut rows = Vec::with_capacity(values.len());
    for value in values {
        let seq = value.get("seq").and_then(serde_json::Value::as_u64);
        let v = value
            .get("v")
            .ok_or_else(|| "an audit row has no format `v`".to_owned())?
            .as_u64()
            .ok_or_else(|| "an audit row's format `v` is not a number".to_owned())?;
        if v > u64::from(ROW_FORMAT) {
            return Ok((rows, Some(RowStop::NewerFormat { seq, v })));
        }
        match serde_json::from_value::<AuditRow>(value.clone()) {
            Ok(row) if ROW_FORMATS.contains(&row.v) => rows.push(row),
            Ok(row) => return Err(format!("audit row format {} does not exist", row.v)),
            Err(e) => {
                let name = |field: &str| -> Option<String> {
                    let v = value.get(field)?;
                    v.as_str()
                        .or_else(|| v.get("kind").and_then(|k| k.as_str()))
                        .map(str::to_owned)
                };
                if let Some(action) = name("action").filter(|a| !AuditAction::knows(a)) {
                    let stop = RowStop::UnknownValue {
                        seq,
                        field: "action",
                        value: action,
                    };
                    return Ok((rows, Some(stop)));
                }
                if let Some(actor) = name("actor").filter(|a| !Actor::knows(a)) {
                    let stop = RowStop::UnknownValue {
                        seq,
                        field: "actor",
                        value: actor,
                    };
                    return Ok((rows, Some(stop)));
                }
                return Err(format!("an audit row is malformed: {e}"));
            }
        }
    }
    Ok((rows, None))
}

/// Verify `rows` (ascending) as the continuation of `known`, or of the
/// genesis if `known` is `None`. Returns the new head.
pub fn verify_chain(
    known: Option<&ChainHead>,
    rows: &[AuditRow],
) -> Result<Option<ChainHead>, ChainError> {
    // A chain ends at seq u64::MAX at the latest: no row follows a row, or a
    // kept head, there. (The server numbers the rows, so the served seq is
    // untrusted; found by fuzzing.)
    let mut expected_seq = match known {
        None => Some(1),
        Some(h) => h.seq.checked_add(1),
    };
    let mut expected_prev = known.map_or(GENESIS, |h| h.hash);
    let mut head = known.copied();
    for row in rows {
        if Some(row.seq) != expected_seq {
            return Err(ChainError::Gap {
                // Past the end of the seq space, nothing is expected; the
                // error names the last seq there is.
                expected: expected_seq.unwrap_or(u64::MAX),
                got: row.seq,
            });
        }
        if row.prev != expected_prev {
            return Err(ChainError::BrokenLink { seq: row.seq });
        }
        let expected = row.expected_hash().ok_or(ChainError::UnknownFormat {
            seq: row.seq,
            v: row.v,
        })?;
        if row.hash != expected {
            return Err(ChainError::BadHash { seq: row.seq });
        }
        expected_seq = row.seq.checked_add(1);
        expected_prev = row.hash;
        head = Some(row.head());
    }
    Ok(head)
}

/// Compare the head a client verified earlier with the head the server
/// reports now. A server that is merely ahead is fine: fetch and verify the
/// rows after `known`.
pub fn check_server_head(known: &ChainHead, server: Option<&ChainHead>) -> Result<(), ChainError> {
    match server {
        None => Err(ChainError::Rollback {
            known: known.seq,
            server: 0,
        }),
        Some(s) if s.seq < known.seq => Err(ChainError::Rollback {
            known: known.seq,
            server: s.seq,
        }),
        Some(s) if s.seq == known.seq && s.hash != known.hash => {
            Err(ChainError::Fork { seq: known.seq })
        }
        Some(_) => Ok(()),
    }
}

/// What [`verify_rows`] established.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Verified {
    /// The last verified row's head (or `known` if no row followed it).
    /// Keep it: it is where the next verification starts.
    pub head: Option<ChainHead>,
    /// How many rows after the starting point verified.
    pub rows: usize,
    /// Set when the served rows reached one in a newer row format: every row
    /// from it on is unverifiable, and `head` stops before it.
    pub unverifiable: Option<RowStop>,
}

/// The verification algorithm (`docs/spec/audit.md#5`), over every row a
/// server served after `known` (all its pages, in order), the head it
/// reported last, and where reading the rows stopped, if it did:
///
/// 1. with a known head, the server's head must not be behind it or differ
///    at its position (rollback, fork);
/// 2. with no known head, verification starts at the first row served,
///    taking its `seq - 1` and `prev` as the base;
/// 3. every row must follow the one before it, by position and by hash, and
///    hash to its own `hash`;
/// 4. unless reading stopped early, the last verified row must be the
///    server's head;
/// 5. a row naming an action or actor this build does not know refuses the
///    verification; a row in a newer format ends it, and the rows before it
///    stand as verified.
pub fn verify_rows(
    known: Option<&ChainHead>,
    rows: &[AuditRow],
    server_head: Option<&ChainHead>,
    stop: Option<&RowStop>,
) -> Result<Verified, ChainError> {
    if let Some(k) = known {
        check_server_head(k, server_head)?;
    }
    let base = known.copied().or_else(|| {
        rows.first()
            .filter(|r| r.seq > 1)
            .map(|r| ChainHead::new(r.seq - 1, r.prev))
    });
    let head = verify_chain(base.as_ref(), rows)?;
    match stop {
        None if head.as_ref() != server_head => Err(ChainError::HeadMismatch),
        None => Ok(Verified {
            head,
            rows: rows.len(),
            unverifiable: None,
        }),
        Some(RowStop::UnknownValue { seq, field, value }) => Err(ChainError::UnknownValue {
            seq: *seq,
            field,
            value: value.clone(),
        }),
        Some(newer @ RowStop::NewerFormat { .. }) => Ok(Verified {
            head,
            rows: rows.len(),
            unverifiable: Some(newer.clone()),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain(n: u64) -> Vec<AuditRow> {
        let mut rows = Vec::new();
        let mut prev = GENESIS;
        for seq in 1..=n {
            let actor = if seq % 2 == 0 {
                Actor::Token(TokenId([seq as u8; 16]))
            } else {
                Actor::Owner
            };
            let row = AuditRow::from_event(
                seq,
                1_700_000_000 + seq as i64,
                prev,
                AuditEvent {
                    version: seq,
                    ct_hash: Some(Hash32([seq as u8; 32])),
                    ..AuditEvent::simple(
                        actor,
                        AuditAction::SecretPut,
                        Some(NameHmac([seq as u8; 32])),
                        AuditResult::Ok,
                    )
                },
            );
            prev = row.hash;
            rows.push(row);
        }
        rows
    }

    #[test]
    fn a_clean_chain_verifies() {
        let rows = chain(5);
        let head = verify_chain(None, &rows).unwrap().unwrap();
        assert_eq!(head, rows[4].head());
        // Continuation from a remembered head.
        let mid = rows[1].head();
        assert_eq!(verify_chain(Some(&mid), &rows[2..]).unwrap(), Some(head));
    }

    #[test]
    fn tampering_is_detected_including_versions_and_ciphertext_hashes() {
        for tamper in [
            (|r: &mut AuditRow| r.result = AuditResult::Refused) as fn(&mut AuditRow),
            |r| r.version += 1,
            |r| r.ct_hash = Some(Hash32([0xee; 32])),
            |r| r.ct_hash = None,
        ] {
            let mut rows = chain(4);
            tamper(&mut rows[2]);
            assert_eq!(
                verify_chain(None, &rows),
                Err(ChainError::BadHash { seq: 3 })
            );
        }

        let mut rows = chain(4);
        rows.remove(1);
        assert_eq!(
            verify_chain(None, &rows),
            Err(ChainError::Gap {
                expected: 2,
                got: 3
            })
        );

        // A rehashed row still fails to link to its predecessor's real hash.
        let mut rows = chain(4);
        rows[1] = AuditRow::from_event(
            2,
            0,
            rows[0].hash,
            AuditEvent::simple(Actor::Owner, AuditAction::SecretRead, None, AuditResult::Ok),
        );
        assert_eq!(
            verify_chain(None, &rows),
            Err(ChainError::BrokenLink { seq: 3 })
        );
    }

    #[test]
    fn rollback_and_fork_against_a_remembered_head() {
        let rows = chain(5);
        let known = rows[3].head();
        assert!(check_server_head(&known, Some(&rows[4].head())).is_ok());
        assert_eq!(
            check_server_head(&known, Some(&rows[2].head())),
            Err(ChainError::Rollback {
                known: 4,
                server: 3
            })
        );
        let forged = ChainHead {
            seq: 4,
            hash: Hash32([9; 32]),
        };
        assert_eq!(
            check_server_head(&known, Some(&forged)),
            Err(ChainError::Fork { seq: 4 })
        );
        assert!(matches!(
            check_server_head(&known, None),
            Err(ChainError::Rollback { .. })
        ));
    }

    #[test]
    fn rows_roundtrip_through_json_and_codes_are_stable() {
        let row = chain(2).pop().unwrap();
        let json = serde_json::to_string(&row).unwrap();
        assert!(json.starts_with("{\"v\":1,"), "{json}");
        assert!(json.contains("\"action\":\"secret_put\""));
        assert!(json.contains("\"kind\":\"token\""));
        assert!(json.contains("\"version\":2"));
        assert_eq!(serde_json::from_str::<AuditRow>(&json).unwrap(), row);
        for a in AuditAction::ALL {
            assert_eq!(AuditAction::from_code(a.code()), Some(a));
            assert_ne!(a.code(), 3, "code 3 stays retired");
            assert_eq!(serde_json::to_string(&a).unwrap(), format!("\"{a}\""));
            assert_eq!(AuditAction::parse(a.as_str()), Some(a));
        }
    }

    /// A row without a format marker is malformed, and a row in a format
    /// this build does not know has no hash input.
    #[test]
    fn rows_without_a_known_format_do_not_verify() {
        let rows = chain(2);
        let mut unmarked = serde_json::to_value(&rows[1]).unwrap();
        unmarked.as_object_mut().unwrap().remove("v");
        let err = read_rows(vec![serde_json::to_value(&rows[0]).unwrap(), unmarked]).unwrap_err();
        assert!(err.contains("format"), "{err}");
        let mut other = rows[1].clone();
        other.v = 0;
        assert_eq!(other.hash_input(), None);
        assert_eq!(rows[1].hash_input().unwrap()[0], ROW_FORMAT);
    }

    fn page(rows: &[AuditRow], extra: Vec<serde_json::Value>) -> Vec<serde_json::Value> {
        rows.iter()
            .map(|r| serde_json::to_value(r).unwrap())
            .chain(extra)
            .collect()
    }

    #[test]
    fn a_newer_row_format_is_unverifiable_never_tampered() {
        let rows = chain(3);
        let mut newer = serde_json::to_value(&chain(4)[3]).unwrap();
        newer["v"] = 4.into();
        newer["witness"] = "added in format 4".into();
        let (read, stop) = read_rows(page(&rows, vec![newer.clone(), newer])).unwrap();
        assert_eq!(read, rows);
        assert_eq!(stop, Some(RowStop::NewerFormat { seq: Some(4), v: 4 }));
        let verified = verify_rows(None, &read, Some(&chain(4)[3].head()), stop.as_ref()).unwrap();
        assert_eq!(
            verified.head,
            Some(rows[2].head()),
            "the head stops before it"
        );
        assert_eq!(verified.rows, 3);
        assert!(matches!(
            verified.unverifiable,
            Some(RowStop::NewerFormat { .. })
        ));
    }

    #[test]
    fn an_unknown_action_refuses_verification() {
        let rows = chain(2);
        let mut odd = serde_json::to_value(&chain(3)[2]).unwrap();
        odd["action"] = "vault_teleport".into();
        let (read, stop) = read_rows(page(&rows, vec![odd])).unwrap();
        assert_eq!(read.len(), 2);
        let err = verify_rows(None, &read, None, stop.as_ref()).unwrap_err();
        assert!(matches!(
            err,
            ChainError::UnknownValue {
                field: "action",
                ..
            }
        ));
        assert!(err.to_string().contains("vault_teleport"));
        // A known action that does not parse is malformed, not unknown.
        let mut broken = serde_json::to_value(&chain(1)[0]).unwrap();
        broken["seq"] = "one".into();
        assert!(read_rows(vec![broken]).is_err());
    }

    #[test]
    fn the_algorithm_checks_the_server_head() {
        let rows = chain(4);
        let v = verify_rows(None, &rows, Some(&rows[3].head()), None).unwrap();
        assert_eq!((v.head, v.rows), (Some(rows[3].head()), 4));
        assert_eq!(
            verify_rows(None, &rows[..3], Some(&rows[3].head()), None),
            Err(ChainError::HeadMismatch)
        );
        let known = rows[1].head();
        let v = verify_rows(Some(&known), &rows[2..], Some(&rows[3].head()), None).unwrap();
        assert_eq!(v.rows, 2);
        // With no head known, the first row served is the base.
        let v = verify_rows(None, &rows[2..], Some(&rows[3].head()), None).unwrap();
        assert_eq!(v.head, Some(rows[3].head()));
    }

    /// Found by fuzzing: a served row at seq u64::MAX overflowed the next
    /// expected seq, a panic in a debug build.
    #[test]
    fn a_chain_may_end_at_the_last_seq_and_nothing_follows_it() {
        let event =
            || AuditEvent::simple(Actor::Owner, AuditAction::SecretRead, None, AuditResult::Ok);
        let base = ChainHead::new(u64::MAX - 1, Hash32([9; 32]));
        let last = AuditRow::from_event(u64::MAX, 1, base.hash, event());
        let only = std::slice::from_ref(&last);
        assert_eq!(verify_chain(Some(&base), only), Ok(Some(last.head())));
        let v = verify_rows(None, only, Some(&last.head()), None).unwrap();
        assert_eq!(v.head, Some(last.head()));
        // Nothing follows it: not after the row, and not after a kept head.
        let after = AuditRow::from_event(0, 2, last.hash, event());
        let both = [last.clone(), after.clone()];
        assert!(matches!(
            verify_chain(Some(&base), &both),
            Err(ChainError::Gap { got: 0, .. })
        ));
        assert_eq!(verify_chain(Some(&last.head()), &[]), Ok(Some(last.head())));
        assert!(matches!(
            verify_chain(Some(&last.head()), &[after]),
            Err(ChainError::Gap { .. })
        ));
    }
}
