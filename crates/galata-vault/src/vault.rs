//! One vault, opened by its owner key or by a token: every
//! server operation the token client and the owner API need, with
//! verification, encryption and decryption on this side, over
//! [`galata_vault_client::Api`].
//!
//! Opening a vault verifies it from a vault id the client pins itself
//!: the owner derives it from the node
//! key, a token carries it in its string. The owner signing key must hash to
//! it, the descriptor must be signed by that key, and the bundle must be
//! owner-signed for this holder and hold exactly the keys the descriptor
//! names. From then on the handle encrypts only to the descriptor's keys and
//! accepts only records signed by its writer keys.
//!
//! The verified generation (descriptor and keys) is one [`View`], swapped
//! whole by [`Handle::refresh`], so a long-lived handle recovers from a
//! rotation without being rebuilt.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock};

use galata_vault_client::{Answer, Api, ApiError, Auth, Pre, Progress, now};
use galata_vault_keys::{
    Bundle, ConfigSecret, FullBundle, NodeKey, OwnerKeys, TokenKeys, VaultSecret, WriterKey,
    seal_child_key, seal_for_scope, seal_owner_bundle,
};
use galata_vault_proto::api::{
    ChallengePurpose, CreateVaultRequest, ErrorCode, RegisterTokenRequest, RegisterTokenResponse,
    ReportTokenRequest, RevokeResponse, Scope, SecretVersion, TokenSelf, VaultStatus, VersionMeta,
};
use galata_vault_proto::audit::{AuditRow, ChainHead, RowStop, verify_chain, verify_rows};
use galata_vault_proto::children::{ChildEntry, ChildMode, ChildrenRecord};
use galata_vault_proto::descriptor::{Descriptor, SignedDescriptor};
use galata_vault_proto::ids::{B64, Hash32, Key32, NameHmac, TokenId, VaultId};
use galata_vault_proto::integrity::IntegrityError;
use galata_vault_proto::path::Segment;
use galata_vault_proto::pow;
use galata_vault_proto::record::RecordKind;
use galata_vault_seal::{
    ConfigFormat, Opened, OpenedConfig, OpenedRecord, Writer, WrittenRecord, build_rotation,
    open_config_record, open_name, open_secret, verify_listed, verify_meta,
};
use serde::{Deserialize, Serialize};

use crate::error::Error;

pub(crate) const DAY: i64 = 86_400;

/// A response announcing a vault expiry closer than this is reported to the
/// handle's [`crate::Events`] (once per handle).
pub const EXPIRY_WARNING_SECS: i64 = 14 * DAY;

/// The descriptor generation a client saw, and its hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DescriptorPin {
    /// The generation.
    pub generation: u32,
    /// The descriptor's hash.
    pub hash: Hash32,
}

/// What a client remembers to detect rollback: the descriptor it last
/// verified, and the latest
/// version it saw of each record. A caller that persists these across runs
/// gets regression detection across runs.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pins {
    /// The descriptor last verified.
    #[serde(default)]
    pub descriptor: Option<DescriptorPin>,
    /// Secret index → the latest version seen.
    #[serde(default)]
    pub secrets: BTreeMap<NameHmac, u64>,
    /// Config index → the latest version seen.
    #[serde(default)]
    pub configs: BTreeMap<NameHmac, u64>,
}

impl Pins {
    fn versions(&mut self, kind: RecordKind) -> &mut BTreeMap<NameHmac, u64> {
        match kind {
            RecordKind::Secret => &mut self.secrets,
            RecordKind::Config => &mut self.configs,
            // A handle only ever reads the two kinds it has keys for.
            _ => unreachable!("record kind {} has no pins in this client", kind.code()),
        }
    }
}

pub(crate) enum Holder {
    Owner(Box<OwnerKeys>),
    Token(Box<TokenKeys>),
}

/// A verified, decrypted record name and its latest version's metadata.
#[derive(Debug, Clone)]
pub(crate) struct Item {
    pub name: String,
    pub hmac: NameHmac,
    pub version: u64,
    /// When the latest version was written (the time its writer signed).
    pub updated_at: i64,
    /// The latest version's ciphertext size in bytes.
    pub size: u32,
    pub tombstone: bool,
}

/// The verified generation: its descriptor and the keys this holder has for
/// it.
pub(crate) struct View {
    pub descriptor: Descriptor,
    pub bundle: Bundle,
    /// Token-opened vaults only.
    pub scope: Option<Scope>,
    /// A read token's allow-list.
    pub allow_list: Option<Vec<NameHmac>>,
    /// Token-opened vaults only.
    pub token_expires_at: Option<i64>,
    /// Owner-opened vaults only: the status the vault was opened with.
    pub status: Option<VaultStatus>,
}

/// A verified audit chain.
pub(crate) struct RawAudit {
    /// Oldest first: the earlier rows asked for, then every row after the
    /// known head.
    pub rows: Vec<AuditRow>,
    /// How many rows came after the known head.
    pub new_rows: usize,
    /// The head now verified.
    pub head: Option<ChainHead>,
    /// Record names this credential could decrypt, by index.
    pub names: HashMap<NameHmac, String>,
    /// Where the served rows became ones this client cannot verify.
    pub unverifiable: Option<RowStop>,
}

fn noun(kind: RecordKind) -> &'static str {
    match kind {
        RecordKind::Secret => "secret",
        RecordKind::Config => "config",
        _ => "record",
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

pub(crate) fn short(h: &NameHmac) -> String {
    h.to_hex()[..8].to_owned()
}

pub(crate) struct Handle {
    api: Api,
    holder: Holder,
    /// The environment path, or a description in token mode.
    pub label: String,
    /// The pinned vault id.
    pub vault_id: VaultId,
    /// Verified against the pinned vault id; never changes.
    pub owner_sign_pub: Key32,
    view: RwLock<Arc<View>>,
    warned: AtomicBool,
    /// `i64::MIN` until a response carries one.
    last_expires_at: AtomicI64,
    pins: Mutex<Pins>,
}

/// An owner's request failed. The server answers `unauthorized` both for a
/// vault that does not exist and for one that expired.
fn owner_error(e: ApiError, label: &str) -> Error {
    if e.code() == Some(ErrorCode::Unauthorized) {
        Error::VaultNotFound {
            label: label.to_owned(),
            message: format!(
                "{label}: the server does not know this vault (it expired, was deleted, or was re-rooted)"
            ),
        }
    } else {
        Error::api(e, Some(label))
    }
}

/// The server refused a token when opening its vault.
fn token_refused(e: ApiError) -> Error {
    let message = match e.code() {
        Some(ErrorCode::Unauthorized) => {
            "the token was not accepted: it is unknown, revoked, or its vault has expired"
        }
        Some(ErrorCode::TokenExpired) => "the token has expired",
        _ => return Error::api(e, None),
    };
    Error::Auth {
        code: e.stable_code(),
        message: message.to_owned(),
    }
}

/// Verify a served descriptor for the pinned vault: the owner signing key
/// hashes to the pinned id, the owner's signature
/// over the descriptor verifies, and the descriptor names that vault. Every
/// public key this SDK encrypts to or verifies a record against comes from a
/// descriptor that passed here, so this is the check that refuses a key the
/// server substituted. The one place it happens, so the plant below can
/// remove it for the adversarial suite's self-test.
fn verify_descriptor(
    signed: &SignedDescriptor,
    vault_id: &VaultId,
    owner_sign_pub: &Key32,
) -> Result<Descriptor, IntegrityError> {
    #[cfg(all(feature = "adversary-plant", debug_assertions))]
    if plant::skips_descriptor_signature() {
        return plant::descriptor_without_signature(signed, vault_id, owner_sign_pub);
    }
    signed.verify_for(vault_id, owner_sign_pub)
}

// The adversarial suite's plant (`scripts/adversary-plant.sh`). It exists
// so the suite can be shown to fail when a
// key-substitution check is gone; it must never be in anything shipped.
// Three latches: the non-default `adversary-plant` feature, which nothing in
// the workspace enables; debug assertions, which no release profile has
// (without them the feature refuses to compile); and GV_ADVERSARY_PLANT at
// run time.
#[cfg(all(feature = "adversary-plant", not(debug_assertions)))]
compile_error!(
    "galata-vault's `adversary-plant` feature weakens verification for the adversarial \
     suite's self-test and cannot be built without debug assertions (a release build)"
);

#[cfg(all(feature = "adversary-plant", debug_assertions))]
mod plant {
    use galata_vault_proto::descriptor::{Descriptor, SignedDescriptor};
    use galata_vault_proto::ids::{Key32, VaultId};
    use galata_vault_proto::integrity::IntegrityError;

    /// The variable, and the one weakening it selects.
    pub(super) const VAR: &str = "GV_ADVERSARY_PLANT";
    pub(super) const SKIP_DESCRIPTOR_SIGNATURE: &str = "skip-descriptor-signature";

    pub(super) fn skips_descriptor_signature() -> bool {
        std::env::var(VAR).is_ok_and(|v| v == SKIP_DESCRIPTOR_SIGNATURE)
    }

    /// Everything `SignedDescriptor::verify_for` checks except the owner's
    /// signature: a descriptor with a substituted public key now passes.
    pub(super) fn descriptor_without_signature(
        signed: &SignedDescriptor,
        vault_id: &VaultId,
        owner_sign_pub: &Key32,
    ) -> Result<Descriptor, IntegrityError> {
        if VaultId::from_owner_sign_pub(owner_sign_pub) != *vault_id {
            return Err(IntegrityError::KeyMismatch("owner signing key"));
        }
        let descriptor = signed.decode_unverified()?;
        if descriptor.vault_id != *vault_id {
            return Err(IntegrityError::KeyMismatch("descriptor's vault id"));
        }
        Ok(descriptor)
    }
}

/// Design D3 for the owner: the status names this owner's keys, the
/// descriptor verifies from the derived vault id, and the owner bundle is
/// owner-signed and holds exactly the descriptor's keys.
fn owner_view(owner: &OwnerKeys, status: VaultStatus, label: &str) -> Result<View, Error> {
    let fail = |e| Error::integrity(label, e);
    if status.vault_id != owner.vault_id() {
        return Err(fail(IntegrityError::KeyMismatch("vault id")));
    }
    if status.owner_sign_pub != owner.sign_pub() {
        return Err(fail(IntegrityError::KeyMismatch("owner signing key")));
    }
    if status.owner_box_pub != owner.box_pub() {
        return Err(fail(IntegrityError::KeyMismatch("owner box key")));
    }
    let descriptor = verify_descriptor(&status.descriptor, &owner.vault_id(), &owner.sign_pub())
        .map_err(fail)?;
    if descriptor.generation != status.generation {
        return Err(fail(IntegrityError::BindingMismatch("generation")));
    }
    let Some(signed) = status.owner_bundle.as_ref() else {
        return Err(Error::other("the server sent no owner bundle"));
    };
    let full = owner
        .open_own_bundle(signed, descriptor.generation)
        .map_err(|e| Error::key(e, format!("{label}: the owner bundle")))?;
    if !full.matches(&descriptor) {
        return Err(fail(IntegrityError::KeyMismatch("owner bundle")));
    }
    Ok(View {
        descriptor,
        bundle: Bundle::Full(full),
        scope: None,
        allow_list: None,
        token_expires_at: None,
        status: Some(status),
    })
}

/// Design D3 for a token: the answer is for this token and vault, the
/// descriptor verifies from the vault id in the token string, and the bundle
/// is owner-signed for this token and holds exactly the descriptor's keys.
fn token_view(token: &TokenKeys, me: TokenSelf, label: &str) -> Result<(View, Key32), Error> {
    if me.vault_id != token.vault_id() {
        return Err(Error::integrity(
            label,
            IntegrityError::KeyMismatch("vault id"),
        ));
    }
    if me.token_id != token.id() {
        return Err(Error::integrity(
            label,
            IntegrityError::KeyMismatch("token id"),
        ));
    }
    // The bundle's kind is checked against the scope: a scope this client
    // does not know cannot be checked, so the vault is not opened.
    let scope = me.scope.get().ok_or_else(|| {
        Error::unsupported(format!(
            "{label}: this token has scope {:?}, which this client does not know",
            me.scope.unknown().unwrap_or("?")
        ))
    })?;
    let descriptor = verify_descriptor(&me.descriptor, &token.vault_id(), &me.owner_sign_pub)
        .map_err(|e| Error::integrity(label, e))?;
    let bundle = token
        .open_bundle(&me.bundle, &me.owner_sign_pub, scope, descriptor.generation)
        .map_err(|e| Error::key(e, format!("{label}: the token's bundle")))?;
    if !bundle.matches(&descriptor) {
        return Err(Error::integrity(
            label,
            IntegrityError::KeyMismatch("token bundle"),
        ));
    }
    Ok((
        View {
            descriptor,
            bundle,
            scope: Some(scope),
            allow_list: me.allow_list,
            token_expires_at: Some(me.expires_at),
            status: None,
        },
        me.owner_sign_pub,
    ))
}

/// The head just before the first row served.
fn head_before(rows: &[AuditRow]) -> Option<ChainHead> {
    rows.first()
        .filter(|r| r.seq > 1)
        .map(|r| ChainHead::new(r.seq - 1, r.prev))
}

fn children_error(e: impl std::fmt::Display) -> Error {
    Error::other(e.to_string())
}

/// Audit rows as served, the server's head, and where the rows stopped
/// being ones this client can verify, if they did.
type AuditRows = (Vec<AuditRow>, Option<ChainHead>, Option<RowStop>);

impl Handle {
    fn new(api: &Api, holder: Holder, label: &str, view: View, owner_sign_pub: Key32) -> Handle {
        let pins = Pins {
            descriptor: Some(DescriptorPin {
                generation: view.descriptor.generation,
                hash: view.descriptor.hash(),
            }),
            ..Pins::default()
        };
        Handle {
            api: api.clone(),
            holder,
            label: label.to_owned(),
            vault_id: view.descriptor.vault_id,
            owner_sign_pub,
            view: RwLock::new(Arc::new(view)),
            warned: AtomicBool::new(false),
            last_expires_at: AtomicI64::new(i64::MIN),
            pins: Mutex::new(pins),
        }
    }

    /// Open a vault as its owner: one signed status request (which also
    /// keeps the vault alive), then the verification chain from the vault id
    /// the node key derives.
    pub fn open_owner(api: &Api, key: &NodeKey, label: &str) -> Result<Handle, Error> {
        api.require_protocol()
            .map_err(|e| Error::api(e, Some(label)))?;
        let owner = key.owner();
        let answer = api
            .status(Auth::Owner(&owner))
            .map_err(|e| owner_error(e, label))?;
        let view = owner_view(&owner, answer.value, label)?;
        let sign_pub = owner.sign_pub();
        let handle = Handle::new(api, Holder::Owner(Box::new(owner)), label, view, sign_pub);
        handle.note_expiry(answer.expires_at);
        Ok(handle)
    }

    /// Open the vault a token belongs to, verifying it from the vault id in
    /// the token string.
    pub fn open_token(api: &Api, token: TokenKeys, label: &str) -> Result<Handle, Error> {
        api.require_protocol()
            .map_err(|e| Error::api(e, Some(label)))?;
        let answer = api.token_self(&token).map_err(token_refused)?;
        let (view, sign_pub) = token_view(&token, answer.value, label)?;
        let handle = Handle::new(api, Holder::Token(Box::new(token)), label, view, sign_pub);
        handle.note_expiry(answer.expires_at);
        Ok(handle)
    }

    /// Create the vault for `key` (a proof of work when the server asks for
    /// one, signed creation, fresh generation keys) with an empty children
    /// record. `Ok(false)` if it already exists.
    pub fn create(api: &Api, key: &NodeKey, label: &str) -> Result<bool, Error> {
        Handle::create_with_keys(api, key, label, &FullBundle::generate(1))
    }

    /// As [`Handle::create`], with generation 1's keys given. Idempotent: an
    /// existing vault is `Ok(false)`.
    pub fn create_with_keys(
        api: &Api,
        key: &NodeKey,
        label: &str,
        full: &FullBundle,
    ) -> Result<bool, Error> {
        if full.generation != 1 {
            return Err(Error::other(format!(
                "{label}: a new vault starts at generation 1"
            )));
        }
        let owner = key.owner();
        // A challenge only for a server that asks for one. One older than the
        // capabilities document always did.
        let wants_proof = api
            .capabilities()
            .map_err(|e| Error::api(e, None))?
            .is_none_or(|c| c.proof_of_work.is_some());
        // Before the signed creation request: a server that does not speak
        // protocol 2 is refused (the capabilities are cached by now).
        api.require_protocol()
            .map_err(|e| Error::api(e, Some(label)))?;
        let (challenge, nonce) = if wants_proof {
            let c = api
                .challenge(ChallengePurpose::CreateVault)
                .map_err(|e| Error::api(e, None))?
                .value;
            if c.difficulty > 16 {
                api.events().progress(&Progress::ProofOfWork {
                    label: label.to_owned(),
                    difficulty: c.difficulty,
                });
            }
            let nonce = pow::solve(&c.challenge, c.difficulty).map_err(|e| {
                Error::other(format!(
                    "{label}: the server's proof-of-work challenge (difficulty {}): {e}",
                    c.difficulty
                ))
            })?;
            (Some(c.challenge), Some(nonce))
        } else {
            (None, None)
        };
        let descriptor = full.descriptor(owner.vault_id(), Hash32([0; 32]), now());
        let owner_bundle = seal_owner_bundle(&owner, full)
            .map_err(|e| Error::key(e, format!("{label}: the owner bundle")))?;
        let request = CreateVaultRequest::new(
            owner.vault_id(),
            owner.sign_pub(),
            owner.box_pub(),
            owner.sign_descriptor(&descriptor),
            owner_bundle,
        )
        .with_proof(challenge, nonce);
        match api.create_vault(&owner, &request) {
            Ok(_) => {}
            Err(e) if e.code() == Some(ErrorCode::Conflict) => return Ok(false),
            Err(e) => {
                return Err(Error::api(e, None).context(format!("creating the vault for {label}")));
            }
        }
        let vault = Handle::open_owner(api, key, label)?;
        match vault.put_children(&ChildrenRecord::new(), Pre::Create) {
            Ok(_) | Err(Error::Conflict { .. }) => Ok(true),
            Err(e) => Err(e.context(format!("{label}: the children record"))),
        }
    }

    /// Report a leaked token by proving possession. The token
    /// string itself is never sent.
    pub fn report_token(api: &Api, token: &TokenKeys) -> Result<RevokeResponse, Error> {
        let ts = now();
        let request = ReportTokenRequest::new(token.id(), ts, token.sign_report(ts));
        Ok(api
            .report_token(&request)
            .map_err(|e| Error::api(e, None))?
            .value)
    }

    pub fn api(&self) -> &Api {
        &self.api
    }

    /// The current verified generation.
    pub fn view(&self) -> Arc<View> {
        self.view.read().unwrap_or_else(|p| p.into_inner()).clone()
    }

    fn auth(&self) -> Auth<'_> {
        match &self.holder {
            Holder::Owner(o) => Auth::Owner(o),
            Holder::Token(t) => Auth::Token(t),
        }
    }

    pub fn owner(&self) -> Result<&OwnerKeys, Error> {
        match &self.holder {
            Holder::Owner(o) => Ok(o.as_ref()),
            Holder::Token(_) => Err(Error::forbidden(format!(
                "{}: this needs the owner key, not a token",
                self.label
            ))),
        }
    }

    /// The token's scope, or `None` when opened by the owner key.
    pub fn scope(&self) -> Option<Scope> {
        self.view().scope
    }

    /// The status an owner-opened vault was opened (or last refreshed) with.
    pub fn status(&self) -> Option<VaultStatus> {
        self.view().status.clone()
    }

    /// The expiry the server reported on the latest response.
    pub fn last_expires_at(&self) -> Option<i64> {
        let at = self.last_expires_at.load(Ordering::Relaxed);
        (at != i64::MIN).then_some(at)
    }

    /// When the token expires; `None` when opened by the owner key.
    pub fn token_expires_at(&self) -> Option<i64> {
        self.view().token_expires_at
    }

    fn note_expiry(&self, expires_at: Option<i64>) {
        let Some(at) = expires_at else { return };
        self.last_expires_at.store(at, Ordering::Relaxed);
        if at - now() < EXPIRY_WARNING_SECS && !self.warned.swap(true, Ordering::Relaxed) {
            self.api.events().expiry(&self.label, at);
        }
    }

    fn take<T>(&self, answer: Answer<T>) -> T {
        self.note_expiry(answer.expires_at);
        answer.value
    }

    /// A server refusal, labelled, with its code kept.
    fn server_err(&self, e: ApiError) -> Error {
        Error::api(e, Some(&self.label))
    }

    fn integrity(&self, e: IntegrityError) -> Error {
        Error::integrity(&self.label, e)
    }

    /// Whether this credential may read the value of `name`.
    pub fn may_read(&self, v: &View, name: &NameHmac) -> bool {
        v.allow_list.as_ref().is_none_or(|l| l.contains(name))
    }

    /// The index of secret `name` (what an allow-list holds).
    pub fn hmac(&self, name: &str) -> NameHmac {
        self.view().bundle.name_key().hmac(name)
    }

    #[cfg(feature = "test-util")]
    pub fn name_key(&self) -> galata_vault_keys::NameKey {
        self.view().bundle.name_key().clone()
    }

    /// Every key of the generation: the owner's, or an admin token's.
    pub fn full<'v>(&self, v: &'v View) -> Result<&'v FullBundle, Error> {
        match &v.bundle {
            Bundle::Full(f) => Ok(f),
            _ => Err(Error::forbidden(format!(
                "{}: this needs every key of the vault (the owner, or an admin token)",
                self.label
            ))),
        }
    }

    /// The key that opens secrets, if this credential holds it.
    pub fn vault_secret<'v>(&self, v: &'v View) -> Result<&'v VaultSecret, Error> {
        v.bundle.vault_secret().ok_or_else(|| {
            Error::forbidden(format!(
                "{}: this credential can list names but cannot decrypt secrets",
                self.label
            ))
        })
    }

    /// The key that opens configs, if this credential holds it.
    pub fn config_secret<'v>(&self, v: &'v View) -> Result<&'v ConfigSecret, Error> {
        v.bundle.config_secret().ok_or_else(|| {
            Error::forbidden(format!(
                "{}: this credential cannot read configs",
                self.label
            ))
        })
    }

    fn writer<'v>(&self, v: &'v View, kind: RecordKind) -> Result<&'v WriterKey, Error> {
        match kind {
            RecordKind::Secret => v.bundle.secret_writer(),
            RecordKind::Config => v.bundle.config_writer(),
            _ => {
                return Err(Error::unsupported(format!(
                    "{}: record kind {} is not one this client knows",
                    self.label,
                    kind.code()
                )));
            }
        }
        .ok_or_else(|| {
            Error::forbidden(format!(
                "{}: this credential may not write {}s",
                self.label,
                noun(kind)
            ))
        })
    }

    // ------------------------------------------------------------ pins

    /// What this handle has seen: the current descriptor and every record
    /// version it has read or written.
    pub fn pins(&self) -> Pins {
        lock(&self.pins).clone()
    }

    /// Adopt pins a caller kept. The descriptor pin is checked against the
    /// verified descriptor now: an older or different generation is refused,
    /// and a newer one must follow the pinned one by an unbroken chain of
    /// owner-signed descriptors.
    pub fn set_pins(&self, pins: Pins) -> Result<(), Error> {
        if let Some(pin) = &pins.descriptor {
            self.check_descriptor_pin(pin, &self.view().descriptor)?;
        }
        let mut mine = lock(&self.pins);
        let current = mine.descriptor;
        *mine = pins;
        mine.descriptor = current;
        Ok(())
    }

    fn check_descriptor_pin(&self, pin: &DescriptorPin, d: &Descriptor) -> Result<(), Error> {
        let rollback = || {
            self.integrity(IntegrityError::GenerationRollback {
                known: pin.generation,
                got: d.generation,
            })
        };
        if d.generation < pin.generation {
            return Err(rollback());
        }
        if d.generation == pin.generation {
            return if d.hash() == pin.hash {
                Ok(())
            } else {
                Err(rollback())
            };
        }
        let (mut generation, mut hash) = (pin.generation, pin.hash);
        for next in self.descriptors_after(pin.generation)? {
            if next.generation > d.generation {
                break;
            }
            if next.generation != generation + 1 || next.prev_hash != hash {
                return Err(self.integrity(IntegrityError::BindingMismatch("descriptor chain")));
            }
            (generation, hash) = (next.generation, next.hash());
        }
        if generation != d.generation || hash != d.hash() {
            return Err(self.integrity(IntegrityError::BindingMismatch("descriptor chain")));
        }
        Ok(())
    }

    /// Refuse a latest version older than one this handle saw; remember it.
    fn check_version(&self, kind: RecordKind, index: &NameHmac, got: u64) -> Result<(), Error> {
        let mut pins = lock(&self.pins);
        let map = pins.versions(kind);
        match map.get(index) {
            Some(&known) if got < known => {
                Err(self.integrity(IntegrityError::VersionRollback { known, got }))
            }
            _ => {
                map.insert(*index, got);
                Ok(())
            }
        }
    }

    /// Every owner-signed descriptor after generation `after`, verified.
    pub fn descriptors_after(&self, after: u32) -> Result<Vec<Descriptor>, Error> {
        let list = self
            .api
            .descriptors(self.auth(), after)
            .map_err(|e| self.server_err(e))?;
        self.take(list)
            .descriptors
            .iter()
            .map(|s| {
                verify_descriptor(s, &self.vault_id, &self.owner_sign_pub)
                    .map_err(|e| self.integrity(e))
            })
            .collect()
    }

    /// Fetch the vault's current generation again: the owner's status or the
    /// token's bundle, and the descriptor, verified from the pinned vault id.
    /// A newer generation must follow the pinned one by an unbroken chain of
    /// owner-signed descriptors; an older one is a rollback.
    pub fn refresh(&self) -> Result<(), Error> {
        let (view, expires_at) = match &self.holder {
            Holder::Owner(owner) => {
                let answer = self
                    .api
                    .status(Auth::Owner(owner))
                    .map_err(|e| owner_error(e, &self.label))?;
                (
                    owner_view(owner, answer.value, &self.label)?,
                    answer.expires_at,
                )
            }
            Holder::Token(token) => {
                let answer = self.api.token_self(token).map_err(token_refused)?;
                let (view, sign_pub) = token_view(token, answer.value, &self.label)?;
                if sign_pub != self.owner_sign_pub {
                    return Err(self.integrity(IntegrityError::KeyMismatch("owner signing key")));
                }
                (view, answer.expires_at)
            }
        };
        let pinned = lock(&self.pins).descriptor;
        if let Some(pin) = pinned {
            self.check_descriptor_pin(&pin, &view.descriptor)?;
        }
        let pin = DescriptorPin {
            generation: view.descriptor.generation,
            hash: view.descriptor.hash(),
        };
        *self.view.write().unwrap_or_else(|p| p.into_inner()) = Arc::new(view);
        lock(&self.pins).descriptor = Some(pin);
        self.note_expiry(expires_at);
        Ok(())
    }

    // ------------------------------------------------------------ records

    fn list_kind(&self, v: &View, kind: RecordKind) -> Result<Vec<Item>, Error> {
        let mut out = Vec::new();
        let mut after: Option<NameHmac> = None;
        loop {
            let page = self
                .api
                .list(self.auth(), kind, after.as_ref())
                .map_err(|e| self.server_err(e))?;
            let page = self.take(page);
            for it in page.items {
                let what = || format!("{}: {} #{}", self.label, noun(kind), short(&it.name_hmac));
                verify_listed(&v.descriptor, kind, &it).map_err(|e| Error::seal(e, what()))?;
                let name = open_name(
                    &v.descriptor,
                    v.bundle.name_key(),
                    kind,
                    &it.name_hmac,
                    &it.name_ct.0,
                )
                .map_err(|e| Error::seal(e, what()))?;
                self.check_version(kind, &it.name_hmac, it.version)?;
                out.push(Item {
                    name,
                    hmac: it.name_hmac,
                    version: it.version,
                    updated_at: it.written_at,
                    size: it.size,
                    tombstone: it.tombstone,
                });
            }
            match page.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn versions_kind(
        &self,
        v: &View,
        kind: RecordKind,
        name: &str,
    ) -> Result<Vec<VersionMeta>, Error> {
        let index = v.bundle.name_key().index(kind, name);
        let list = match self.api.versions(self.auth(), kind, &index) {
            Ok(a) => self.take(a),
            Err(e) if e.code() == Some(ErrorCode::NotFound) => return Ok(Vec::new()),
            Err(e) => return Err(self.server_err(e)),
        };
        for m in &list.versions {
            verify_meta(&v.descriptor, kind, &index, m).map_err(|e| {
                Error::seal(
                    e,
                    format!(
                        "{}: version {} of {} {name}",
                        self.label,
                        m.version,
                        noun(kind)
                    ),
                )
            })?;
        }
        Ok(list.versions)
    }

    fn fetch(
        &self,
        v: &View,
        kind: RecordKind,
        name: &str,
        version: Option<u64>,
    ) -> Result<SecretVersion, Error> {
        let index = v.bundle.name_key().index(kind, name);
        let record = match self.api.record(self.auth(), kind, &index, version) {
            Ok(a) => self.take(a),
            Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                return Err(Error::not_found(match version {
                    Some(n) => format!("{}: {} {name} has no version {n}", self.label, noun(kind)),
                    None => format!("{}: no {} named {name}", self.label, noun(kind)),
                }));
            }
            Err(e) if e.code() == Some(ErrorCode::Forbidden) => {
                return Err(Error::forbidden(format!(
                    "{}: this credential may not read {} {name}",
                    self.label,
                    noun(kind)
                )));
            }
            Err(e) => return Err(self.server_err(e)),
        };
        if record.name_hmac != index {
            return Err(self.integrity(IntegrityError::BindingMismatch("record index")));
        }
        match version {
            Some(want) if record.version != want => {
                return Err(self.integrity(IntegrityError::BindingMismatch("record version")));
            }
            Some(_) => {}
            None => {
                // Verify before the pin moves: a forged answer must be
                // refused without leaving its version behind, or one bad
                // response would lock the genuine record out.
                galata_vault_seal::verify_version(&v.descriptor, kind, &record).map_err(|e| {
                    Error::seal(
                        e,
                        // By index, never by name: the error names what the
                        // server served, not what the caller asked for.
                        format!(
                            "{}: version {} of {} #{}",
                            self.label,
                            record.version,
                            noun(kind),
                            short(&record.name_hmac)
                        ),
                    )
                })?;
                self.check_version(kind, &index, record.version)?;
            }
        }
        Ok(record)
    }

    /// Verify and decrypt a record this handle fetched.
    fn open_record(
        &self,
        v: &View,
        kind: RecordKind,
        record: &SecretVersion,
    ) -> Result<OpenedRecord, Error> {
        let what = || {
            format!(
                "{}: version {} of {} #{}",
                self.label,
                record.version,
                noun(kind),
                short(&record.name_hmac)
            )
        };
        match kind {
            RecordKind::Secret => open_secret(
                &v.descriptor,
                v.bundle.name_key(),
                self.vault_secret(v)?,
                record,
            )
            .map_err(|e| Error::seal(e, what())),
            RecordKind::Config => open_config_record(
                &v.descriptor,
                v.bundle.name_key(),
                self.config_secret(v)?,
                record,
            )
            .map_err(|e| Error::seal(e, what())),
            _ => Err(Error::unsupported(format!(
                "{}: record kind {} is not one this client knows",
                self.label,
                kind.code()
            ))),
        }
    }

    fn send_write(&self, v: &View, name: &str, rec: WrittenRecord, pre: Pre) -> Result<u64, Error> {
        let kind = rec.kind;
        let deleting = rec.value_ct.is_none();
        let answer = match (rec.put_request(), rec.delete_request()) {
            (Some(put), _) => self.api.put(self.auth(), kind, &rec.name_hmac, &put, pre),
            (None, Some(delete)) => {
                self.api
                    .delete(self.auth(), kind, &rec.name_hmac, &delete, pre)
            }
            (None, None) => {
                return Err(Error::other(format!(
                    "{}: {name} has neither a value nor a tombstone",
                    self.label
                )));
            }
        };
        match answer {
            Ok(a) => {
                let version = self.take(a).version;
                // Pin the version this client signed, never an unsigned
                // number from the server; a server that reports another
                // one is lying about what it stored.
                if version != rec.version {
                    return Err(self.integrity(IntegrityError::BindingMismatch("written version")));
                }
                self.check_version(kind, &rec.name_hmac, rec.version)?;
                Ok(rec.version)
            }
            Err(e)
                if matches!(
                    e.code(),
                    Some(ErrorCode::PreconditionFailed | ErrorCode::VersionMismatch)
                ) =>
            {
                Err(self.conflict(v, kind, name, pre, deleting))
            }
            Err(e) if e.code() == Some(ErrorCode::Forbidden) => Err(Error::forbidden(format!(
                "{}: this credential may not write {} {name}",
                self.label,
                noun(kind)
            ))),
            Err(e) if e.code() == Some(ErrorCode::StaleGeneration) => Err(Error::stale(
                &self.label,
                format!(
                    "{}: the vault was rotated while writing {name}; open it again (or refresh the handle) and retry",
                    self.label
                ),
            )),
            Err(e) => Err(self.server_err(e)),
        }
    }

    /// Seal, sign and send a value as the version `pre` implies.
    #[allow(clippy::too_many_arguments)]
    fn write_value(
        &self,
        v: &View,
        kind: RecordKind,
        name: &str,
        format: Option<ConfigFormat>,
        body: &[u8],
        pre: Pre,
        written_at: i64,
    ) -> Result<u64, Error> {
        let w = Writer {
            descriptor: &v.descriptor,
            name_key: v.bundle.name_key(),
            writer: self.writer(v, kind)?,
        };
        let version = pre.next_version();
        let rec = match (kind, format) {
            (RecordKind::Secret, _) => w.secret(name, body, version, written_at),
            (RecordKind::Config, Some(f)) => w.config(name, f, body, version, written_at),
            (RecordKind::Config, None) => {
                w.config(name, ConfigFormat::Text, body, version, written_at)
            }
            (other, _) => Err(galata_vault_seal::SealError::UnsupportedByClient(format!(
                "record kind {} is not one this client knows",
                other.code()
            ))),
        }
        .map_err(|e| {
            Error::seal(
                e,
                format!("{}: encrypting {} {name}", self.label, noun(kind)),
            )
        })?;
        self.send_write(v, name, rec, pre)
    }

    /// Sign and send a tombstone as the version `pre` implies.
    fn write_tombstone(
        &self,
        v: &View,
        kind: RecordKind,
        name: &str,
        pre: Pre,
        written_at: i64,
    ) -> Result<u64, Error> {
        let w = Writer {
            descriptor: &v.descriptor,
            name_key: v.bundle.name_key(),
            writer: self.writer(v, kind)?,
        };
        let rec = w
            .tombstone(kind, name, pre.next_version(), written_at)
            .map_err(|e| {
                Error::seal(e, format!("{}: deleting {} {name}", self.label, noun(kind)))
            })?;
        self.send_write(v, name, rec, pre)
    }

    fn conflict(
        &self,
        v: &View,
        kind: RecordKind,
        name: &str,
        expected: Pre,
        deleting: bool,
    ) -> Error {
        match self.versions_kind(v, kind, name) {
            Ok(versions) => {
                Error::conflict(name, expected, versions.last().map(|m| m.version), deleting)
            }
            Err(e) => e,
        }
    }

    // ------------------------------------------------------------ secrets

    /// Every secret's latest version, verified, names decrypted. Tombstones
    /// included.
    pub fn list(&self) -> Result<Vec<Item>, Error> {
        self.list_kind(&self.view(), RecordKind::Secret)
    }

    /// Verified history metadata; empty if the secret never existed.
    pub fn versions(&self, name: &str) -> Result<Vec<VersionMeta>, Error> {
        self.versions_kind(&self.view(), RecordKind::Secret, name)
    }

    /// The precondition for writing `name` now.
    pub fn current(&self, name: &str) -> Result<Pre, Error> {
        Ok(Pre::after(self.versions(name)?.last()))
    }

    /// Verify and decrypt a secret. Errors name the path, the version and
    /// the failure kind, never key or plaintext bytes.
    pub fn get(&self, name: &str, version: Option<u64>) -> Result<(u64, Opened), Error> {
        let v = self.view();
        self.vault_secret(&v)?;
        let record = self.fetch(&v, RecordKind::Secret, name, version)?;
        let rec = self.open_record(&v, RecordKind::Secret, &record)?;
        let Some(value) = rec.value else {
            return Err(Error::not_found(format!(
                "{}: {name} was deleted at version {}",
                self.label, record.version
            )));
        };
        Ok((
            record.version,
            Opened {
                name: rec.name,
                value,
                written_at: rec.written_at,
            },
        ))
    }

    pub fn put(&self, name: &str, value: &[u8], pre: Pre) -> Result<u64, Error> {
        let v = self.view();
        self.write_value(&v, RecordKind::Secret, name, None, value, pre, now())
    }

    /// Delete `name` at live `version`: a signed tombstone as the next version.
    pub fn delete(&self, name: &str, version: u64) -> Result<u64, Error> {
        let v = self.view();
        self.write_tombstone(&v, RecordKind::Secret, name, Pre::Update(version), now())
    }

    // ------------------------------------------------------------ configs

    /// Every config's latest version, verified, names decrypted. Tombstones
    /// included.
    pub fn list_configs(&self) -> Result<Vec<Item>, Error> {
        self.list_kind(&self.view(), RecordKind::Config)
    }

    /// A config's verified history metadata; empty if it never existed.
    pub fn config_versions(&self, name: &str) -> Result<Vec<VersionMeta>, Error> {
        self.versions_kind(&self.view(), RecordKind::Config, name)
    }

    /// The precondition for writing config `name` now.
    pub fn config_current(&self, name: &str) -> Result<Pre, Error> {
        Ok(Pre::after(self.config_versions(name)?.last()))
    }

    /// Verify and decrypt a config document.
    pub fn get_config(
        &self,
        name: &str,
        version: Option<u64>,
    ) -> Result<(u64, OpenedConfig), Error> {
        let v = self.view();
        self.config_secret(&v)?;
        let record = self.fetch(&v, RecordKind::Config, name, version)?;
        let rec = self.open_record(&v, RecordKind::Config, &record)?;
        let (Some(body), Some(format)) = (rec.value, rec.format) else {
            return Err(Error::not_found(format!(
                "{}: config {name} was deleted at version {}",
                self.label, record.version
            )));
        };
        Ok((
            record.version,
            OpenedConfig {
                name: rec.name,
                format,
                body,
                written_at: rec.written_at,
            },
        ))
    }

    /// Write a config document, sealed to the descriptor's config key and
    /// signed with the config writer key.
    pub fn put_config(
        &self,
        name: &str,
        format: ConfigFormat,
        body: &[u8],
        pre: Pre,
    ) -> Result<u64, Error> {
        let v = self.view();
        self.write_value(&v, RecordKind::Config, name, Some(format), body, pre, now())
    }

    /// Delete config `name` at live `version`: a signed tombstone.
    pub fn delete_config(&self, name: &str, version: u64) -> Result<u64, Error> {
        let v = self.view();
        self.write_tombstone(&v, RecordKind::Config, name, Pre::Update(version), now())
    }

    // ------------------------------------------------------------ children

    /// The node's owner-only children record, verified, and the
    /// precondition to replace it.
    pub fn children(&self) -> Result<(ChildrenRecord, Pre), Error> {
        let owner = self.owner()?;
        match self.api.children_get(owner) {
            Ok(a) => {
                let blob = self.take(a);
                let record = owner
                    .open_children(&blob)
                    .map_err(|e| Error::key(e, format!("{}: the children record", self.label)))?;
                Ok((record, Pre::Update(blob.version)))
            }
            Err(e) if e.code() == Some(ErrorCode::NotFound) => {
                Ok((ChildrenRecord::new(), Pre::Create))
            }
            Err(e) => Err(self.server_err(e)),
        }
    }

    /// Seal, sign and write the children record as the version `pre` implies.
    pub fn put_children(&self, record: &ChildrenRecord, pre: Pre) -> Result<u64, Error> {
        let owner = self.owner()?;
        let version = pre.next_version();
        let blob = owner
            .seal_children(version, record)
            .map_err(|e| Error::key(e, "the children record".to_owned()))?;
        match self.api.children_put(owner, &blob, pre) {
            Ok(a) => {
                self.take(a);
                Ok(version)
            }
            Err(e)
                if matches!(
                    e.code(),
                    Some(ErrorCode::PreconditionFailed | ErrorCode::VersionMismatch)
                ) =>
            {
                Err(Error::conflict(
                    &format!("{}'s children record", self.label),
                    pre,
                    None,
                    false,
                ))
            }
            Err(e) => Err(self.server_err(e)),
        }
    }

    /// Read-modify-write the children record, retrying if another client wins.
    pub fn update_children(
        &self,
        mut change: impl FnMut(&mut ChildrenRecord) -> Result<(), Error>,
    ) -> Result<(), Error> {
        for _ in 0..5 {
            let (mut record, pre) = self.children()?;
            change(&mut record)?;
            match self.put_children(&record, pre) {
                Ok(_) => return Ok(()),
                Err(Error::Conflict { .. }) => continue,
                Err(e) => return Err(e),
            }
        }
        Err(Error::other(format!(
            "{}: the children record kept changing; try again",
            self.label
        )))
    }

    /// Point this node's children entry for `seg` at `key`, sealed to this
    /// vault's owner box key.
    pub fn seal_child(&self, seg: &Segment, key: &NodeKey) -> Result<(), Error> {
        let to = self.owner()?.box_pub();
        let key_ct = seal_child_key(&to, &self.vault_id, key)
            .map_err(|e| Error::key(e, format!("the sealed key for {seg}")))?;
        self.update_children(|r| {
            let mode = ChildMode::Sealed {
                key_ct: B64(key_ct.clone()),
            };
            if r.set_mode(seg, mode.clone()).is_err() {
                r.insert(ChildEntry::new(seg.clone(), now(), mode))
                    .map_err(children_error)?;
            }
            Ok(())
        })
    }

    // ------------------------------------------------------------ vault

    /// The vault's status, its descriptor verified against the pinned id.
    pub fn refresh_status(&self) -> Result<VaultStatus, Error> {
        let answer = self
            .api
            .status(self.auth())
            .map_err(|e| self.server_err(e))?;
        let status = self.take(answer);
        if status.owner_sign_pub != self.owner_sign_pub || status.vault_id != self.vault_id {
            return Err(self.integrity(IntegrityError::KeyMismatch("owner signing key")));
        }
        verify_descriptor(&status.descriptor, &self.vault_id, &self.owner_sign_pub)
            .map_err(|e| self.integrity(e))?;
        Ok(status)
    }

    fn audit_page(&self, after: u64) -> Result<galata_vault_proto::api::AuditPage, Error> {
        match self.api.audit(self.auth(), after) {
            Ok(a) => Ok(self.take(a)),
            Err(e) if e.code() == Some(ErrorCode::Forbidden) => Err(Error::forbidden(format!(
                "{}: this credential may not read the audit log",
                self.label
            ))),
            Err(e) => Err(self.server_err(e)),
        }
    }

    /// Rows after `after` (stopping once `until` is reached, if given), the
    /// server's head, and where the rows stopped being ones this client can
    /// verify, if they did (no page after that one is fetched).
    fn audit_rows(&self, mut after: u64, until: Option<u64>) -> Result<AuditRows, Error> {
        let mut rows = Vec::new();
        loop {
            let page = self.audit_page(after)?;
            let n = page.rows.len();
            if let Some(last) = page.rows.last() {
                after = last.seq;
            }
            rows.extend(page.rows);
            if page.stop.is_some() {
                return Ok((rows, page.head, page.stop));
            }
            if n < galata_vault_client::AUDIT_PAGE || until.is_some_and(|u| after >= u) {
                return Ok((rows, page.head, None));
            }
        }
    }

    /// Fetch and verify the vault's audit chain against `known`, the head
    /// this client verified last time. With `earlier > 0`, up to that many
    /// rows at or below `known` are fetched as well, for display, and must
    /// lead exactly to it. Every scope may verify.
    pub fn verify_audit(
        &self,
        known: Option<ChainHead>,
        earlier: usize,
    ) -> Result<RawAudit, Error> {
        let failed = format!("{}: audit verification FAILED", self.label);
        let (rows, server_head, stop) = self.audit_rows(known.map_or(0, |h| h.seq), None)?;
        // `docs/spec/audit.md#5`: the server head against `known`, every row
        // by position and hash (from the first row served when no head is
        // known: older rows may already be in the archive), and the head
        // again. A newer row format ends what is verified; an unknown action
        // or actor refuses.
        let verified = verify_rows(known.as_ref(), &rows, server_head.as_ref(), stop.as_ref())
            .map_err(|e| Error::audit_chain(e, &failed))?;
        let head = verified.head;

        let mut shown = Vec::new();
        if let Some(k) = known.filter(|k| earlier > 0 && k.seq > 0) {
            let (mut before, _, _) =
                self.audit_rows(k.seq.saturating_sub(earlier as u64), Some(k.seq))?;
            before.retain(|r| r.seq <= k.seq);
            if !before.is_empty() {
                let reached = verify_chain(head_before(&before).as_ref(), &before)
                    .map_err(|e| Error::audit_chain(e, &failed))?;
                if reached != Some(k) {
                    return Err(self
                        .integrity(IntegrityError::BindingMismatch("audit rows"))
                        .context(&failed));
                }
                shown = before;
            }
        }
        let new_rows = rows.len();
        shown.extend(rows);

        let mut names = HashMap::new();
        for item in self.list().unwrap_or_default() {
            names.insert(item.hmac, item.name);
        }
        for item in self.list_configs().unwrap_or_default() {
            names.insert(item.hmac, item.name);
        }
        Ok(RawAudit {
            rows: shown,
            new_rows,
            head,
            names,
            unverifiable: verified.unverifiable,
        })
    }

    /// Every retained version of every record of `kind`, for a rotation.
    fn all_versions(&self, v: &View, kind: RecordKind) -> Result<Vec<SecretVersion>, Error> {
        let mut out = Vec::new();
        for item in self.list_kind(v, kind)? {
            for meta in self.versions_kind(v, kind, &item.name)? {
                out.push(self.fetch(v, kind, &item.name, Some(meta.version))?);
            }
        }
        Ok(out)
    }

    /// Move the vault to a new generation, dropping `revoke` in the same
    /// transaction. Owner-only. Returns the new generation;
    /// [`Handle::refresh`] adopts it.
    pub fn rotate(&self, revoke: &[TokenId]) -> Result<u32, Error> {
        let owner = self.owner()?;
        let v = self.view();
        let full = self.full(&v)?;
        for _ in 0..3 {
            let status = self.refresh_status()?;
            if status.generation != v.descriptor.generation {
                return Err(Error::stale(
                    &self.label,
                    format!(
                        "{}: the vault moved to generation {} since it was opened; open it again",
                        self.label, status.generation
                    ),
                ));
            }
            let secrets = self.all_versions(&v, RecordKind::Secret)?;
            let configs = self.all_versions(&v, RecordKind::Config)?;
            let rotation = build_rotation(
                owner,
                &status,
                &v.descriptor,
                full,
                &secrets,
                &configs,
                revoke,
                now(),
            )
            .map_err(|e| Error::seal(e, format!("{}: preparing the rotation", self.label)))?;
            match self.api.rotate(owner, &rotation.request) {
                Ok(a) => return Ok(self.take(a).generation),
                // Someone wrote meanwhile: rebuild from the new revision.
                Err(e) if e.code() == Some(ErrorCode::Conflict) => continue,
                Err(e) => return Err(self.server_err(e)),
            }
        }
        Err(Error::other(format!(
            "{}: the vault kept changing during rotation; try again",
            self.label
        )))
    }

    /// Mint a token (owner-only): fresh keys, an owner-signed
    /// bundle holding exactly what `scope` allows.
    pub fn mint(
        &self,
        scope: Scope,
        ttl_secs: u64,
        allow_list: Option<Vec<NameHmac>>,
    ) -> Result<(TokenKeys, RegisterTokenResponse), Error> {
        let owner = self.owner()?;
        let v = self.view();
        let full = self.full(&v)?;
        let token = TokenKeys::generate(self.vault_id);
        let bundle = seal_for_scope(owner, &token.box_pub(), &token.id(), scope, full)
            .map_err(|e| Error::key(e, format!("{}: minting a {scope} token", self.label)))?;
        let request = RegisterTokenRequest::new(
            token.id(),
            token.auth_pub(),
            token.box_pub(),
            scope,
            ttl_secs,
            allow_list,
            full.generation,
            bundle,
        );
        let answer = self
            .api
            .register_token(owner, &request)
            .map_err(|e| self.server_err(e))?;
        Ok((token, self.take(answer)))
    }

    /// Revoke without rotating (owner or admin). Forward-only.
    pub fn revoke(&self, id: &TokenId) -> Result<RevokeResponse, Error> {
        let answer = self
            .api
            .revoke(self.auth(), id)
            .map_err(|e| self.server_err(e))?;
        Ok(self.take(answer))
    }

    pub fn delete_vault(&self) -> Result<(), Error> {
        let owner = self.owner()?;
        let answer = self
            .api
            .delete_vault(owner)
            .map_err(|e| self.server_err(e))?;
        self.take(answer);
        Ok(())
    }

    /// Copy every retained record of `old` into this (new, owner-opened)
    /// vault, verified and decrypted with `old`'s keys, re-encrypted and
    /// re-signed with this vault's. Write times are kept;
    /// versions are renumbered from 1, since a new vault's history starts
    /// there, and a leading tombstone has nothing to delete and is skipped.
    /// Idempotent: versions already copied are skipped, so an interrupted
    /// copy resumes. Returns how many versions it wrote.
    pub fn copy_from(&self, old: &Handle) -> Result<usize, Error> {
        let v = self.view();
        let ov = old.view();
        self.full(&v)?;
        old.full(&ov)?;
        let mut copied = 0;
        for kind in [RecordKind::Secret, RecordKind::Config] {
            for item in old.list_kind(&ov, kind)? {
                let mut source = Vec::new();
                for meta in old.versions_kind(&ov, kind, &item.name)? {
                    if source.is_empty() && meta.tombstone {
                        continue;
                    }
                    source.push(meta.version);
                }
                let target = self.versions_kind(&v, kind, &item.name)?;
                let mut pre = Pre::after(target.last());
                for &n in source.iter().skip(target.len()) {
                    let raw = old.fetch(&ov, kind, &item.name, Some(n))?;
                    let rec = old.open_record(&ov, kind, &raw)?;
                    let written = match &rec.value {
                        Some(body) => self.write_value(
                            &v,
                            kind,
                            &item.name,
                            rec.format,
                            body,
                            pre,
                            rec.written_at,
                        )?,
                        None => self.write_tombstone(&v, kind, &item.name, pre, rec.written_at)?,
                    };
                    pre = if rec.value.is_some() {
                        Pre::Update(written)
                    } else {
                        Pre::Revive(written)
                    };
                    copied += 1;
                }
            }
        }
        Ok(copied)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(version: u64, tombstone: bool) -> VersionMeta {
        VersionMeta::new(
            version,
            0,
            galata_vault_proto::audit::Actor::Owner,
            0,
            tombstone,
            1,
            Hash32([0; 32]),
            Hash32([0; 32]),
            galata_vault_proto::ids::Sig64([0; 64]),
        )
    }

    #[test]
    fn preconditions_follow_the_latest_version() {
        assert_eq!(Pre::after(None), Pre::Create);
        assert_eq!(Pre::after(Some(&meta(3, true))), Pre::Revive(3));
        assert_eq!(Pre::after(Some(&meta(3, false))), Pre::Update(3));
    }

    #[test]
    fn pins_roundtrip_through_json_and_toml() {
        let mut pins = Pins {
            descriptor: Some(DescriptorPin {
                generation: 2,
                hash: Hash32([7; 32]),
            }),
            ..Pins::default()
        };
        pins.secrets.insert(NameHmac([1; 32]), 4);
        pins.configs.insert(NameHmac([2; 32]), 9);
        let json = serde_json::to_string(&pins).unwrap();
        assert_eq!(serde_json::from_str::<Pins>(&json).unwrap(), pins);
        let text = toml::to_string(&pins).unwrap();
        assert_eq!(toml::from_str::<Pins>(&text).unwrap(), pins);
    }
}
