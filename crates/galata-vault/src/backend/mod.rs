//! Storage for the server: the [`Store`] interface, and a SQLite (WAL)
//! implementation of it.
//!
//! **Implementation detail of galata-vault.** No semver guarantee beyond the
//! workspace version: applications depend on the `galata-vault` crate. The
//! formats this crate implements are specified in the repository's
//! `docs/spec/`, and their stability promise lives there, not in this API.
//!
//! Nothing stored here can be decrypted by anything that can read it: rows
//! hold ciphertext, signatures, hashes, public keys and metadata. There is no
//! project, path or plaintext name anywhere in the schema, and no client
//! address.
//!
//! `galata-vault-server` reaches SQLite only through this crate, so a Postgres
//! implementation is a second implementation of the interface rather than a
//! change to the server.
//!
//! The store does not verify signatures: the server does, before it calls
//! in, against the descriptor of the vault's current generation. The store
//! re-checks everything a concurrent change could invalidate (generation,
//! revision, preconditions, the version a writer signed) inside its
//! transaction.
//!
//! Two rules shape every write:
//!
//! * **Refusals are audited.** A write refused by a precondition, generation,
//!   version or quota check commits an audit row with result `refused`, and
//!   nothing else.
//! * **Critical operations are journaled before they commit.** Revocation,
//!   rotation and vault deletion call a [`CommitHook`] with the journal
//!   record while their transaction is still open. If the hook fails (the
//!   Object-Lock PUT did not land), the transaction rolls back.

mod journal;
mod schema;
mod sqlite;

pub use journal::{CommitHook, JournalOp, JournalRecord};
pub use sqlite::{SqliteStore, StoreConfig};

use crate::proto::api::{Limits, RotationRequest, Scope, SignedBundle};
use crate::proto::audit::{Actor, AuditEvent, AuditRow, ChainHead};
use crate::proto::children::ChildrenBlob;
use crate::proto::descriptor::SignedDescriptor;
use crate::proto::ids::{Hash32, Key32, NameHmac, Sig64, TokenId, VaultId};

pub type VaultPk = i64;

/// Who is acting, and when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ctx {
    pub actor: Actor,
    pub now: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultRow {
    pub pk: VaultPk,
    pub vault_id: VaultId,
    pub owner_sign_pub: Key32,
    pub owner_box_pub: Key32,
    pub owner_bundle: SignedBundle,
    pub generation: u32,
    pub revision: u64,
    pub created_at: i64,
    pub last_active_at: i64,
    pub bytes_used: u64,
    /// The current generation's owner-signed descriptor.
    pub descriptor: SignedDescriptor,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewVault {
    pub vault_id: VaultId,
    pub owner_sign_pub: Key32,
    pub owner_box_pub: Key32,
    /// Generation 1's descriptor, verified by the server.
    pub descriptor: SignedDescriptor,
    pub owner_bundle: SignedBundle,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenRow {
    pub token_id: TokenId,
    pub vault_pk: VaultPk,
    /// Verifies the token's request signatures.
    pub auth_pub: Key32,
    pub box_pub: Key32,
    pub scope: Scope,
    pub created_at: i64,
    pub expires_at: i64,
    pub bundle: SignedBundle,
    pub generation: u32,
    pub allow_list: Option<Vec<NameHmac>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewToken {
    pub token_id: TokenId,
    pub auth_pub: Key32,
    pub box_pub: Key32,
    pub scope: Scope,
    pub expires_at: i64,
    pub bundle: SignedBundle,
    pub generation: u32,
    pub allow_list: Option<Vec<NameHmac>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRow {
    pub name_hmac: NameHmac,
    pub version: u64,
    pub name_ct: Vec<u8>,
    /// `None` for a tombstone.
    pub value_ct: Option<Vec<u8>>,
    pub generation: u32,
    /// The write time the writer signed.
    pub written_at: i64,
    pub written_by: Actor,
    pub tombstone: bool,
    /// The generation's writer key's signature over the record context.
    pub sig: Sig64,
}

/// A name's current version, as listed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeadRow {
    pub name_hmac: NameHmac,
    pub name_ct: Vec<u8>,
    pub version: u64,
    pub written_at: i64,
    pub size: u32,
    pub tombstone: bool,
    pub generation: u32,
    /// SHA-256 of the value ciphertext (of an empty value for a tombstone):
    /// what the record signature binds.
    pub value_ct_hash: Hash32,
    pub sig: Sig64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Precondition {
    /// `If-None-Match: *`: create, or revive a deleted name.
    IfNoneMatch,
    /// `If-Match: v`: update version `v` and nothing else.
    IfMatch(u64),
}

/// A signed record write. `value_ct = None` is a tombstone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordWrite {
    pub name_ct: Vec<u8>,
    pub value_ct: Option<Vec<u8>>,
    pub generation: u32,
    /// The version the writer signed; it must be the one the store assigns.
    pub version: u64,
    pub written_at: i64,
    pub sig: Sig64,
}

/// Which record table a call addresses. Secrets and configs live in separate
/// tables, so a query for one kind can never return the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordKind {
    Secret,
    Config,
}

impl RecordKind {
    /// The wire record kind: what signatures bind.
    pub fn wire(self) -> crate::proto::record::RecordKind {
        match self {
            RecordKind::Secret => crate::proto::record::RecordKind::Secret,
            RecordKind::Config => crate::proto::record::RecordKind::Config,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quota {
    Names,
    ValueSize,
    VaultBytes,
    Tokens,
    Configs,
    ConfigSize,
}

/// Single-use identifiers, remembered until they expire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpentKind {
    /// A proof-of-work challenge id.
    Challenge = 1,
    /// A request-signature nonce (vault id ‖ nonce), owner or token.
    Nonce = 2,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StoreError {
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    Exists,
    #[error("precondition failed; the current version is {current:?}")]
    PreconditionFailed { current: Option<u64> },
    #[error("the write signs version {signed}, but this write would create version {assigned}")]
    VersionMismatch { signed: u64, assigned: u64 },
    #[error("the write is for a stale key generation")]
    StaleGeneration,
    #[error("the vault changed since this batch was built")]
    Conflict,
    #[error("the rotation batch is incomplete: {0}")]
    IncompleteRotation(&'static str),
    #[error("quota exceeded: {0:?}")]
    Quota(Quota),
    #[error("already used")]
    Spent,
    #[error("the journal write failed, so nothing was applied: {0}")]
    Journal(String),
    #[error("the database is not in WAL mode (it is in {0} mode)")]
    NotWal(String),
    #[error("database error: {0}")]
    Database(String),
    #[error(
        "the database has schema version {found}, newer than this gv-server knows ({known}); run the newer binary"
    )]
    NewerSchema { found: i64, known: i64 },
}

impl From<rusqlite::Error> for StoreError {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::SqliteFailure(f, _)
                if f.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                StoreError::Exists
            }
            other => StoreError::Database(other.to_string()),
        }
    }
}

/// The server's storage. Every method is synchronous; the server calls them
/// from a blocking pool.
pub trait Store: Send + Sync {
    // ------------------------------------------------------------ vaults
    fn create_vault(&self, vault: &NewVault, now: i64) -> Result<VaultRow, StoreError>;
    fn vault_by_id(&self, id: &VaultId) -> Result<Option<VaultRow>, StoreError>;
    fn vault_by_pk(&self, pk: VaultPk) -> Result<Option<VaultRow>, StoreError>;
    /// Record activity, at most once a minute per vault.
    fn touch(&self, pk: VaultPk, now: i64) -> Result<(), StoreError>;
    /// The descriptor chain after `after`, ascending.
    fn descriptors(&self, pk: VaultPk, after: u32) -> Result<Vec<SignedDescriptor>, StoreError>;

    // ------------------------------------------------------------ tokens
    fn register_token(
        &self,
        pk: VaultPk,
        token: &NewToken,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<TokenRow, StoreError>;
    fn token_by_id(&self, id: &TokenId) -> Result<Option<TokenRow>, StoreError>;
    fn tokens(&self, pk: VaultPk) -> Result<Vec<TokenRow>, StoreError>;
    /// Critical: journaled before commit.
    fn revoke_tokens(
        &self,
        pk: VaultPk,
        ids: &[TokenId],
        reported: bool,
        ctx: Ctx,
        hook: CommitHook<'_>,
    ) -> Result<Vec<TokenId>, StoreError>;

    // ------------------------------------------------------------ records
    // One implementation for both kinds; the secret methods below are the
    // same calls with `RecordKind::Secret`.
    fn list_records(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        after: Option<&NameHmac>,
        limit: usize,
    ) -> Result<Vec<HeadRow>, StoreError>;
    fn latest_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
    ) -> Result<Option<VersionRow>, StoreError>;
    fn record_version(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        version: u64,
    ) -> Result<Option<VersionRow>, StoreError>;
    /// Every retained version of one name, oldest first.
    fn record_versions(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
    ) -> Result<Vec<VersionRow>, StoreError>;
    /// Every retained version of one kind: what a rotating client re-encrypts.
    fn all_record_versions(
        &self,
        pk: VaultPk,
        kind: RecordKind,
    ) -> Result<Vec<VersionRow>, StoreError>;
    /// Write a record; `write.value_ct` must be `Some`.
    #[allow(clippy::too_many_arguments)]
    fn put_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        pre: Precondition,
        write: &RecordWrite,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError>;
    /// Write a signed tombstone as `if_match + 1`; `write.value_ct` must be `None`.
    #[allow(clippy::too_many_arguments)]
    fn delete_record(
        &self,
        pk: VaultPk,
        kind: RecordKind,
        name: &NameHmac,
        if_match: u64,
        write: &RecordWrite,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError>;
    /// How many live (not deleted) records of one kind the vault holds.
    fn live_records(&self, pk: VaultPk, kind: RecordKind) -> Result<u32, StoreError>;

    // ------------------------------------------------------------ children
    /// The owner-only children record, if written.
    fn children(&self, pk: VaultPk) -> Result<Option<ChildrenBlob>, StoreError>;
    /// Write the children record. `blob.version` must be the version the
    /// precondition assigns.
    fn put_children(
        &self,
        pk: VaultPk,
        pre: Precondition,
        blob: &ChildrenBlob,
        ctx: Ctx,
        limits: &Limits,
    ) -> Result<u64, StoreError>;

    // ------------------------------------------------------------ audit
    /// Append an audit row on its own: value reads, and attempts refused
    /// before reaching a write (scope, allow-list, signature).
    fn record(&self, pk: VaultPk, event: AuditEvent, now: i64) -> Result<(), StoreError>;
    fn audit_after(
        &self,
        pk: VaultPk,
        after: u64,
        limit: usize,
    ) -> Result<(Vec<AuditRow>, Option<ChainHead>), StoreError>;

    // ------------------------------------------------------------ critical
    fn apply_rotation(
        &self,
        pk: VaultPk,
        request: &RotationRequest,
        ctx: Ctx,
        hook: CommitHook<'_>,
    ) -> Result<u32, StoreError>;
    fn delete_vault(&self, pk: VaultPk, now: i64, hook: CommitHook<'_>) -> Result<(), StoreError>;

    // ------------------------------------------------------------ housekeeping
    /// Remember a single-use id until `expires_at`; `Spent` if already seen.
    fn spend(
        &self,
        kind: SpentKind,
        id: &[u8],
        expires_at: i64,
        now: i64,
    ) -> Result<(), StoreError>;

    // ------------------------------------------------------------ journal
    /// The highest journal sequence this database reflects.
    fn journal_applied(&self) -> Result<u64, StoreError>;
    /// Re-apply one journal record after a restore. Idempotent: returns
    /// whether it changed anything.
    fn replay(&self, record: &JournalRecord) -> Result<bool, StoreError>;
}
