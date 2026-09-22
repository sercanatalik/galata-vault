//! Request and response bodies for every `/v1` endpoint, the token scopes
//! and their policy, the capabilities document, and the stable error codes
//! (`docs/spec/http-api.md`).
//!
//! The server knows nothing of projects or paths: every call addresses
//! exactly one vault, chosen by the caller's credential. Everything a client
//! must trust arrives signed:
//! - descriptors and bundles by the owner (`descriptor`, [`SignedBundle`]);
//! - records by the generation's writer keys (`record`);
//! - the children record by the owner (`children`).
//!
//! **Requests are strict, responses tolerant** (`docs/spec/http-api.md#7`).
//! Every request body refuses a field it does not know. No response body
//! does: a newer server may add fields, and an older client ignores them.
//! Response fields holding an enum a newer server may extend (a token's
//! scope, an error code, a record's writer) are [`Tolerant`], so a value
//! this build does not know is kept for display and never acted on.
//!
//! Every body and enum here is `#[non_exhaustive]`, so a later release can
//! add a field or a variant without breaking a dependent crate. Crates that
//! build a body use its `new` constructor.

use serde::{Deserialize, Serialize};

use crate::proto::audit::{Actor, AuditRow, ChainHead, RowStop};
use crate::proto::descriptor::SignedDescriptor;
use crate::proto::frame::{frame, label};
use crate::proto::ids::{B64, Hash32, Key32, NameHmac, Sig64, TokenId, VaultId};
use crate::proto::integrity::{IntegrityError, verify_ed25519};
use crate::proto::tolerant::{Tolerant, Vocabulary};

const DAY: u64 = 86_400;

/// The protocol version this build speaks, as capabilities list it.
pub const PROTOCOL: &str = "1";

/// The bundle plaintext's version byte (`docs/spec/records.md#2`).
pub const BUNDLE_VERSION: u8 = 1;

// ---------------------------------------------------------------- scopes

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Scope {
    /// List, history metadata, audit, status.
    Meta,
    /// List, create and update secrets and configs; never read them.
    Append,
    /// List and read secrets and configs.
    Read,
    /// Read and write secrets and configs, list tokens, revoke without
    /// rotating. Minting, rotation, rekey and deletion are owner-only.
    Admin,
    /// List, history metadata, audit, status, and read configs. Its bundle
    /// has no field for the vault key: it cannot decrypt a secret.
    Config,
    /// Everything `Config` may, and create, update and delete configs. Its
    /// bundle holds the config writer key and no secret writer key: it
    /// cannot write a secret, by cryptography.
    #[serde(rename = "config-write")]
    ConfigWrite,
}

impl Scope {
    pub const ALL: [Scope; 6] = [
        Scope::Meta,
        Scope::Append,
        Scope::Read,
        Scope::Admin,
        Scope::Config,
        Scope::ConfigWrite,
    ];

    /// Read secret values.
    pub fn can_read_values(self) -> bool {
        matches!(self, Scope::Read | Scope::Admin)
    }

    /// Create, update and delete secrets.
    pub fn can_write_values(self) -> bool {
        matches!(self, Scope::Append | Scope::Admin)
    }

    pub fn can_read_configs(self) -> bool {
        matches!(
            self,
            Scope::Read | Scope::Admin | Scope::Config | Scope::ConfigWrite
        )
    }

    pub fn can_write_configs(self) -> bool {
        matches!(self, Scope::Append | Scope::Admin | Scope::ConfigWrite)
    }

    /// List every token and revoke without rotating. Minting and rotation
    /// need the owner signature.
    pub fn can_manage(self) -> bool {
        self == Scope::Admin
    }

    /// Every scope may fetch and verify its vault's audit.
    pub fn can_read_audit(self) -> bool {
        true
    }

    /// Whether this scope's bundle carries the vault private key.
    pub fn bundle_holds_vault_key(self) -> bool {
        matches!(self, Scope::Read | Scope::Admin)
    }

    /// Whether this scope's bundle carries the config private key.
    pub fn bundle_holds_config_key(self) -> bool {
        matches!(
            self,
            Scope::Read | Scope::Admin | Scope::Config | Scope::ConfigWrite
        )
    }

    /// Whether this scope's bundle carries the secret writer key.
    pub fn bundle_holds_secret_writer(self) -> bool {
        matches!(self, Scope::Append | Scope::Admin)
    }

    /// Whether this scope's bundle carries the config writer key.
    pub fn bundle_holds_config_writer(self) -> bool {
        matches!(self, Scope::Append | Scope::Admin | Scope::ConfigWrite)
    }

    /// The byte a bundle signature binds. 0 is the owner's own bundle.
    pub fn code(self) -> u8 {
        match self {
            Scope::Meta => 1,
            Scope::Append => 2,
            Scope::Read => 3,
            Scope::Admin => 4,
            Scope::Config => 5,
            Scope::ConfigWrite => 6,
        }
    }

    pub fn default_ttl_secs(self) -> u64 {
        match self {
            Scope::Admin => DAY,
            _ => 90 * DAY,
        }
    }

    pub fn max_ttl_secs(self) -> u64 {
        match self {
            Scope::Admin => 30 * DAY,
            _ => 365 * DAY,
        }
    }

    /// The wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Scope::Meta => "meta",
            Scope::Append => "append",
            Scope::Read => "read",
            Scope::Admin => "admin",
            Scope::Config => "config",
            Scope::ConfigWrite => "config-write",
        }
    }

    /// The inverse of `Display`.
    pub fn parse(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.as_str() == s)
    }
}

impl std::fmt::Display for Scope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Vocabulary for Scope {
    fn knows(name: &str) -> bool {
        Scope::parse(name).is_some()
    }
}

/// The scope byte of the owner's own bundle.
pub const OWNER_SCOPE_CODE: u8 = 0;
/// The token id of the owner's own bundle.
pub const OWNER_TOKEN_ID: TokenId = TokenId([0; 16]);

// ---------------------------------------------------------------- bundles

/// A bundle as it travels: sealed to its holder's box key, signed by the
/// owner. The server can verify the signature; only the holder
/// can open the seal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SignedBundle {
    pub sealed: B64,
    pub sig: Sig64,
}

/// What the owner signs for a bundle:
/// `frame("gv/v1/bundle", vault_id ‖ token_id ‖ scope(1) ‖ generation(4) ‖ SHA-256(sealed))`.
/// The owner's own bundle uses [`OWNER_TOKEN_ID`] and [`OWNER_SCOPE_CODE`].
pub fn bundle_signing_input(
    vault_id: &VaultId,
    token_id: &TokenId,
    scope_code: u8,
    generation: u32,
    sealed: &[u8],
) -> Vec<u8> {
    frame(
        label::BUNDLE,
        &[
            &vault_id.0,
            &token_id.0,
            &[scope_code],
            &generation.to_be_bytes(),
            &Hash32::sha256(sealed).0,
        ],
    )
}

impl SignedBundle {
    pub fn new(sealed: B64, sig: Sig64) -> SignedBundle {
        SignedBundle { sealed, sig }
    }

    /// Check the owner's signature for this binding.
    pub fn verify(
        &self,
        owner_sign_pub: &Key32,
        vault_id: &VaultId,
        token_id: &TokenId,
        scope_code: u8,
        generation: u32,
    ) -> Result<(), IntegrityError> {
        verify_ed25519(
            owner_sign_pub,
            &bundle_signing_input(vault_id, token_id, scope_code, generation, &self.sealed.0),
            &self.sig,
            "bundle",
        )
    }
}

// ---------------------------------------------------------------- vaults

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ChallengePurpose {
    CreateVault,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChallengeRequest {
    pub purpose: ChallengePurpose,
}

impl ChallengeRequest {
    pub fn new(purpose: ChallengePurpose) -> ChallengeRequest {
        ChallengeRequest { purpose }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChallengeResponse {
    pub challenge: String,
    pub difficulty: u8,
    pub expires_at: i64,
}

impl ChallengeResponse {
    pub fn new(challenge: String, difficulty: u8, expires_at: i64) -> ChallengeResponse {
        ChallengeResponse {
            challenge,
            difficulty,
            expires_at,
        }
    }
}

/// `POST /v1/vaults`, owner-signed. The first descriptor names every public
/// key of generation 1; the server checks its signature and that it is a
/// first generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CreateVaultRequest {
    /// A solved challenge from `POST /v1/challenges`, sent only to a server
    /// whose capabilities ask for proof of work. A server that asks for none
    /// does not check one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub challenge: Option<String>,
    /// The nonce that solves `challenge`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<u64>,
    pub vault_id: VaultId,
    pub owner_sign_pub: Key32,
    pub owner_box_pub: Key32,
    pub descriptor: SignedDescriptor,
    pub owner_bundle: SignedBundle,
}

impl CreateVaultRequest {
    /// A creation with no proof of work.
    pub fn new(
        vault_id: VaultId,
        owner_sign_pub: Key32,
        owner_box_pub: Key32,
        descriptor: SignedDescriptor,
        owner_bundle: SignedBundle,
    ) -> CreateVaultRequest {
        CreateVaultRequest {
            challenge: None,
            nonce: None,
            vault_id,
            owner_sign_pub,
            owner_box_pub,
            descriptor,
            owner_bundle,
        }
    }

    /// The same creation, carrying a solved challenge.
    pub fn with_proof(mut self, challenge: Option<String>, nonce: Option<u64>) -> Self {
        self.challenge = challenge;
        self.nonce = nonce;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct CreateVaultResponse {
    pub vault_id: VaultId,
    pub generation: u32,
    /// `None` when the server expires no vault for inactivity.
    #[serde(default)]
    pub expires_at: Option<i64>,
}

impl CreateVaultResponse {
    pub fn new(vault_id: VaultId, generation: u32, expires_at: Option<i64>) -> Self {
        CreateVaultResponse {
            vault_id,
            generation,
            expires_at,
        }
    }
}

// ---------------------------------------------------------------- capabilities

/// The optional behaviours a server can advertise in its capabilities
/// (`docs/spec/http-api.md#6`). A client ignores a name it does not know.
pub mod feature {
    /// `POST /v1/tokens/report` is served: a leaked token can be revoked by
    /// whoever holds it.
    pub const TOKEN_REPORT: &str = "token_report";
    /// A request budget is enforced per token and per vault, so any
    /// authenticated request may be answered 429 with `Retry-After`.
    pub const RATE_LIMITS: &str = "rate_limits";
}

/// `GET /v1/capabilities`, unauthenticated: what a server asks of a client
/// before the client acts (`docs/spec/http-api.md#6`). Identical for every
/// caller, with no per-vault data.
///
/// `proof_of_work`, `idle_expiry_days` and `limits` are the fields of
/// split-hosted-server and keep their names and meaning. A client requests a
/// challenge only when `proof_of_work` is set, and keeps vaults alive only
/// when `idle_expiry_days` is. A document without `protocols` comes from a
/// server that predates the field, and speaks protocol 2 only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Capabilities {
    /// The protocol versions served, as strings: `["1"]`.
    #[serde(default = "protocols_before_the_field")]
    pub protocols: Vec<String>,
    /// The version of each format this build implements; absent from a
    /// server that predates the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub formats: Option<Formats>,
    /// What vault creation needs; `None` (`null`) when it needs no challenge.
    #[serde(default)]
    pub proof_of_work: Option<ProofOfWork>,
    /// Days without an authenticated request before a vault expires; `None`
    /// (`null`) when no vault ever expires for inactivity.
    #[serde(default)]
    pub idle_expiry_days: Option<u32>,
    /// The per-vault quotas.
    #[serde(default)]
    pub limits: Limits,
    /// Optional behaviours in force, from [`feature`].
    #[serde(default)]
    pub features: Vec<String>,
    /// The server's name and version. Absent unless the operator turns it
    /// on (`advertise_version`), to limit fingerprinting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
}

fn protocols_before_the_field() -> Vec<String> {
    vec![PROTOCOL.to_owned()]
}

impl Capabilities {
    /// A protocol 2 document with this policy, the formats of this build,
    /// no features and no server version.
    pub fn new(
        proof_of_work: Option<ProofOfWork>,
        idle_expiry_days: Option<u32>,
        limits: Limits,
    ) -> Capabilities {
        Capabilities {
            protocols: vec![PROTOCOL.to_owned()],
            formats: Some(Formats::CURRENT),
            proof_of_work,
            idle_expiry_days,
            limits,
            features: Vec::new(),
            server: None,
        }
    }

    /// The same document, advertising `features`.
    pub fn with_features(mut self, features: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.features = features.into_iter().map(Into::into).collect();
        self
    }

    /// The same document, naming the server.
    pub fn with_server(mut self, server: Option<String>) -> Self {
        self.server = server;
        self
    }

    /// Whether the server speaks `protocol` (`"1"`).
    pub fn speaks(&self, protocol: &str) -> bool {
        self.protocols.iter().any(|p| p == protocol)
    }
}

/// The version of each stored or signed format, as a build implements it
/// (`docs/spec/stability.md#2`). 0 is "not advertised".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Formats {
    /// The generation descriptor's version byte.
    pub descriptor: u32,
    /// The bundle plaintext's version byte.
    pub bundle: u32,
    /// The record envelope's version byte.
    pub envelope: u32,
    /// The children record's `v`.
    pub children: u32,
    /// The audit row format a server writes.
    pub audit_row: u32,
    /// The `GV-Sig` version, `v=`.
    pub request_signature: u32,
}

impl Formats {
    /// What this build writes.
    pub const CURRENT: Formats = Formats {
        descriptor: crate::proto::descriptor::DESCRIPTOR_VERSION as u32,
        bundle: BUNDLE_VERSION as u32,
        envelope: crate::proto::record::ENVELOPE_VERSION as u32,
        children: crate::proto::children::CHILDREN_RECORD_VERSION,
        audit_row: crate::proto::audit::ROW_FORMAT as u32,
        request_signature: 1,
    };
}

/// The proof of work vault creation needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProofOfWork {
    /// Leading zero bits of `blake3(challenge ‖ nonce)`.
    pub difficulty: u8,
}

impl ProofOfWork {
    pub fn new(difficulty: u8) -> ProofOfWork {
        ProofOfWork { difficulty }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct Limits {
    pub max_names: u32,
    pub max_value_bytes: u32,
    pub max_versions: u32,
    /// Secrets and configs together.
    pub max_vault_bytes: u64,
    pub max_tokens: u32,
    pub max_configs: u32,
    pub max_config_bytes: u32,
    pub max_config_versions: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_names: 200,
            max_value_bytes: 16 * 1024,
            max_versions: 20,
            max_vault_bytes: 4 * 1024 * 1024,
            max_tokens: 128,
            max_configs: 64,
            max_config_bytes: 256 * 1024,
            max_config_versions: 20,
        }
    }
}

impl Limits {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        max_names: u32,
        max_value_bytes: u32,
        max_versions: u32,
        max_vault_bytes: u64,
        max_tokens: u32,
        max_configs: u32,
        max_config_bytes: u32,
        max_config_versions: u32,
    ) -> Limits {
        Limits {
            max_names,
            max_value_bytes,
            max_versions,
            max_vault_bytes,
            max_tokens,
            max_configs,
            max_config_bytes,
            max_config_versions,
        }
    }

    /// The largest [`RotationRequest`] body, in bytes, that a vault at these
    /// quotas can produce. A server's body limit must be at least this, or
    /// the rotation that cuts off a revoked key fails on a full vault.
    ///
    /// Counted:
    /// - the stored ciphertext `max_vault_bytes` covers (names and values),
    ///   as unpadded base64;
    /// - per retained secret and config version: two hex name indexes, the
    ///   version and write time, a longest-name ciphertext, the record
    ///   signature and the JSON framing;
    /// - a signed, resealed bundle and a revoke entry for every permitted token;
    /// - the signed descriptor, the signed owner bundle and a fixed margin.
    pub fn max_rotation_body(&self) -> usize {
        fn b64(n: u64) -> u64 {
            (n * 4).div_ceil(3)
        }
        const INDEX_HEX: u64 = 64; // a NameHmac
        const TOKEN_HEX: u64 = 32; // a TokenId
        const DIGITS: u64 = 20; // a u64 or i64 in decimal
        const NAME_CT: u64 = 24 + 256 + 16; // nonce, longest name, tag
        const SIG: u64 = 86; // a Sig64, unpadded base64
        const BUNDLE: u64 = 48 + 198; // sealed-box overhead, largest bundle plaintext
        const DESCRIPTOR: u64 = 189;
        // {"old_name_hmac":"","version":,"name_hmac":"","name_ct":"","value_ct":"","written_at":,"sig":""},
        // is 97 bytes; the rest covers per-item base64 rounding.
        const VERSION_FRAME: u64 = 104;
        // {"token_id":"","bundle":{"sealed":"","sig":""}},
        const TOKEN_FRAME: u64 = 56;
        const MARGIN: u64 = 4096;

        let versions = u64::from(self.max_names) * u64::from(self.max_versions)
            + u64::from(self.max_configs) * u64::from(self.max_config_versions);
        let tokens = u64::from(self.max_tokens);
        let total = b64(self.max_vault_bytes)
            + versions * (2 * INDEX_HEX + 2 * DIGITS + b64(NAME_CT) + SIG + VERSION_FRAME)
            + tokens * (TOKEN_HEX + b64(BUNDLE) + SIG + TOKEN_FRAME)
            + tokens * (TOKEN_HEX + 3)
            + b64(DESCRIPTOR)
            + SIG
            + b64(BUNDLE)
            + SIG
            + 2 * DIGITS
            + MARGIN;
        usize::try_from(total).unwrap_or(usize::MAX)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenSummary {
    pub token_id: TokenId,
    /// A scope a newer server may name and this build not know.
    pub scope: Tolerant<Scope>,
    pub created_at: i64,
    pub expires_at: i64,
    /// Needed by a rotating owner to reseal this token's bundle.
    pub box_pub: Key32,
    pub allow_list: Option<Vec<NameHmac>>,
}

impl TokenSummary {
    pub fn new(
        token_id: TokenId,
        scope: impl Into<Tolerant<Scope>>,
        created_at: i64,
        expires_at: i64,
        box_pub: Key32,
        allow_list: Option<Vec<NameHmac>>,
    ) -> TokenSummary {
        TokenSummary {
            token_id,
            scope: scope.into(),
            created_at,
            expires_at,
            box_pub,
            allow_list,
        }
    }
}

/// `GET /v1/vault`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VaultStatus {
    pub vault_id: VaultId,
    pub generation: u32,
    /// Increments on every state change; a rotation names the revision it
    /// was built from, so a concurrent write makes it fail rather than lose data.
    pub revision: u64,
    /// Checked by every client: it must hash to the pinned vault id.
    pub owner_sign_pub: Key32,
    pub owner_box_pub: Key32,
    /// The current generation's owner-signed descriptor.
    pub descriptor: SignedDescriptor,
    #[serde(default)]
    pub config_count: u32,
    pub created_at: i64,
    pub last_active_at: i64,
    /// When the vault expires if nothing touches it; `None` when the server
    /// expires no vault for inactivity.
    #[serde(default)]
    pub expires_at: Option<i64>,
    pub bytes_used: u64,
    pub limits: Limits,
    /// Present only for owner-signed and admin requests.
    pub tokens: Option<Vec<TokenSummary>>,
    /// Present only for owner-signed requests.
    pub owner_bundle: Option<SignedBundle>,
}

impl VaultStatus {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_id: VaultId,
        generation: u32,
        revision: u64,
        owner_sign_pub: Key32,
        owner_box_pub: Key32,
        descriptor: SignedDescriptor,
        config_count: u32,
        created_at: i64,
        last_active_at: i64,
        expires_at: Option<i64>,
        bytes_used: u64,
        limits: Limits,
        tokens: Option<Vec<TokenSummary>>,
        owner_bundle: Option<SignedBundle>,
    ) -> VaultStatus {
        VaultStatus {
            vault_id,
            generation,
            revision,
            owner_sign_pub,
            owner_box_pub,
            descriptor,
            config_count,
            created_at,
            last_active_at,
            expires_at,
            bytes_used,
            limits,
            tokens,
            owner_bundle,
        }
    }
}

/// `GET /v1/vault/descriptors?after={generation}`: the chain, ascending.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DescriptorList {
    pub descriptors: Vec<SignedDescriptor>,
}

impl DescriptorList {
    pub fn new(descriptors: Vec<SignedDescriptor>) -> DescriptorList {
        DescriptorList { descriptors }
    }
}

/// `POST /v1/vault/rotations`, owner-signed: one atomic batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RotationRequest {
    pub from_generation: u32,
    pub from_revision: u64,
    /// The next generation's descriptor, linked by `prev_hash`.
    pub descriptor: SignedDescriptor,
    pub owner_bundle: SignedBundle,
    pub secrets: Vec<RotatedVersion>,
    /// Every retained config version, re-encrypted and re-signed.
    pub configs: Vec<RotatedVersion>,
    pub tokens: Vec<ResealedBundle>,
    pub revoke: Vec<TokenId>,
}

impl RotationRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        from_generation: u32,
        from_revision: u64,
        descriptor: SignedDescriptor,
        owner_bundle: SignedBundle,
        secrets: Vec<RotatedVersion>,
        configs: Vec<RotatedVersion>,
        tokens: Vec<ResealedBundle>,
        revoke: Vec<TokenId>,
    ) -> RotationRequest {
        RotationRequest {
            from_generation,
            from_revision,
            descriptor,
            owner_bundle,
            secrets,
            configs,
            tokens,
            revoke,
        }
    }
}

/// One retained version, re-encrypted to the new keys and re-signed with the
/// new writer key, keeping its number and write time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RotatedVersion {
    pub old_name_hmac: NameHmac,
    pub version: u64,
    pub name_hmac: NameHmac,
    pub name_ct: B64,
    /// `None` for a tombstone version.
    pub value_ct: Option<B64>,
    pub written_at: i64,
    pub sig: Sig64,
}

impl RotatedVersion {
    pub fn new(
        old_name_hmac: NameHmac,
        version: u64,
        name_hmac: NameHmac,
        name_ct: B64,
        value_ct: Option<B64>,
        written_at: i64,
        sig: Sig64,
    ) -> RotatedVersion {
        RotatedVersion {
            old_name_hmac,
            version,
            name_hmac,
            name_ct,
            value_ct,
            written_at,
            sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ResealedBundle {
    pub token_id: TokenId,
    pub bundle: SignedBundle,
}

impl ResealedBundle {
    pub fn new(token_id: TokenId, bundle: SignedBundle) -> ResealedBundle {
        ResealedBundle { token_id, bundle }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RotationResponse {
    pub generation: u32,
}

impl RotationResponse {
    pub fn new(generation: u32) -> RotationResponse {
        RotationResponse { generation }
    }
}

/// `DELETE /v1/vault`, owner-signed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct DeleteVaultResponse {
    pub vault_id: VaultId,
}

impl DeleteVaultResponse {
    pub fn new(vault_id: VaultId) -> DeleteVaultResponse {
        DeleteVaultResponse { vault_id }
    }
}

/// `DELETE /v1/tokens/{id}` and `POST /v1/tokens/report`. Revocation is
/// forward-only: key material a holder already unwrapped is not recalled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RevokeResponse {
    pub revoked: Vec<TokenId>,
}

impl RevokeResponse {
    pub fn new(revoked: Vec<TokenId>) -> RevokeResponse {
        RevokeResponse { revoked }
    }
}

// ---------------------------------------------------------------- tokens

/// `POST /v1/tokens`, owner-signed: register a client-minted token. The
/// server stores the two public keys; nothing it stores derives the box key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RegisterTokenRequest {
    pub token_id: TokenId,
    /// Verifies the token's request signatures.
    pub auth_pub: Key32,
    /// The token's bundle is sealed to this.
    pub box_pub: Key32,
    /// A request is strict: a scope the server does not know is refused.
    pub scope: Scope,
    pub ttl_secs: u64,
    pub allow_list: Option<Vec<NameHmac>>,
    pub generation: u32,
    pub bundle: SignedBundle,
}

impl RegisterTokenRequest {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: TokenId,
        auth_pub: Key32,
        box_pub: Key32,
        scope: Scope,
        ttl_secs: u64,
        allow_list: Option<Vec<NameHmac>>,
        generation: u32,
        bundle: SignedBundle,
    ) -> RegisterTokenRequest {
        RegisterTokenRequest {
            token_id,
            auth_pub,
            box_pub,
            scope,
            ttl_secs,
            allow_list,
            generation,
            bundle,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct RegisterTokenResponse {
    pub token_id: TokenId,
    pub expires_at: i64,
}

impl RegisterTokenResponse {
    pub fn new(token_id: TokenId, expires_at: i64) -> RegisterTokenResponse {
        RegisterTokenResponse {
            token_id,
            expires_at,
        }
    }
}

/// `GET /v1/tokens/self`: everything a token holder needs to verify its
/// vault from the vault id in its token string.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct TokenSelf {
    pub token_id: TokenId,
    pub vault_id: VaultId,
    /// A scope a newer server may name and this build not know: such a
    /// token's bundle cannot be checked, so the client refuses to open it.
    pub scope: Tolerant<Scope>,
    pub expires_at: i64,
    pub allow_list: Option<Vec<NameHmac>>,
    pub owner_sign_pub: Key32,
    pub descriptor: SignedDescriptor,
    pub bundle: SignedBundle,
}

impl TokenSelf {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        token_id: TokenId,
        vault_id: VaultId,
        scope: impl Into<Tolerant<Scope>>,
        expires_at: i64,
        allow_list: Option<Vec<NameHmac>>,
        owner_sign_pub: Key32,
        descriptor: SignedDescriptor,
        bundle: SignedBundle,
    ) -> TokenSelf {
        TokenSelf {
            token_id,
            vault_id,
            scope: scope.into(),
            expires_at,
            allow_list,
            owner_sign_pub,
            descriptor,
            bundle,
        }
    }
}

/// `POST /v1/tokens/report`: a leaked token proves possession with its
/// token-auth key. The token string itself is never sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ReportTokenRequest {
    pub token_id: TokenId,
    pub ts: i64,
    pub sig: Sig64,
}

impl ReportTokenRequest {
    pub fn new(token_id: TokenId, ts: i64, sig: Sig64) -> ReportTokenRequest {
        ReportTokenRequest { token_id, ts, sig }
    }
}

/// What a token-auth key signs to report its token:
/// `frame("gv/v1/report", token_id(16) ‖ ts(8))`.
pub fn report_signing_input(token_id: &TokenId, ts: i64) -> Vec<u8> {
    frame(label::REPORT, &[&token_id.0, &ts.to_be_bytes()])
}

// ---------------------------------------------------------------- records

/// One live record in a listing. The hashes let a holder that cannot decrypt
/// verify the record signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretListItem {
    pub name_hmac: NameHmac,
    pub name_ct: B64,
    pub version: u64,
    pub written_at: i64,
    pub size: u32,
    pub tombstone: bool,
    pub generation: u32,
    pub value_ct_hash: Hash32,
    pub sig: Sig64,
}

impl SecretListItem {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_hmac: NameHmac,
        name_ct: B64,
        version: u64,
        written_at: i64,
        size: u32,
        tombstone: bool,
        generation: u32,
        value_ct_hash: Hash32,
        sig: Sig64,
    ) -> SecretListItem {
        SecretListItem {
            name_hmac,
            name_ct,
            version,
            written_at,
            size,
            tombstone,
            generation,
            value_ct_hash,
            sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretList {
    pub items: Vec<SecretListItem>,
    pub next_cursor: Option<NameHmac>,
}

impl SecretList {
    pub fn new(items: Vec<SecretListItem>, next_cursor: Option<NameHmac>) -> SecretList {
        SecretList { items, next_cursor }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SecretVersion {
    pub name_hmac: NameHmac,
    pub version: u64,
    pub name_ct: B64,
    /// `None` for a tombstone.
    pub value_ct: Option<B64>,
    pub generation: u32,
    pub written_at: i64,
    /// Who the server says wrote it: an actor kind a newer server may name
    /// and this build not know. Display only; the writer signature is what
    /// a client trusts.
    pub written_by: Tolerant<Actor>,
    pub tombstone: bool,
    pub sig: Sig64,
}

impl SecretVersion {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        name_hmac: NameHmac,
        version: u64,
        name_ct: B64,
        value_ct: Option<B64>,
        generation: u32,
        written_at: i64,
        written_by: impl Into<Tolerant<Actor>>,
        tombstone: bool,
        sig: Sig64,
    ) -> SecretVersion {
        SecretVersion {
            name_hmac,
            version,
            name_ct,
            value_ct,
            generation,
            written_at,
            written_by: written_by.into(),
            tombstone,
            sig,
        }
    }
}

/// `PUT /v1/secrets/{name_hmac}` or `/v1/configs/{name_hmac}`, with
/// `If-None-Match: *` (version 1) or `If-Match: v` (version v + 1). The
/// signature binds the version the writer intends to create.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct PutSecretRequest {
    pub name_ct: B64,
    pub value_ct: B64,
    pub generation: u32,
    pub version: u64,
    pub written_at: i64,
    pub sig: Sig64,
}

impl PutSecretRequest {
    pub fn new(
        name_ct: B64,
        value_ct: B64,
        generation: u32,
        version: u64,
        written_at: i64,
        sig: Sig64,
    ) -> PutSecretRequest {
        PutSecretRequest {
            name_ct,
            value_ct,
            generation,
            version,
            written_at,
            sig,
        }
    }
}

/// `DELETE /v1/secrets/{name_hmac}` or `/v1/configs/{name_hmac}` with
/// `If-Match: v`: a signed tombstone as version v + 1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct DeleteRecordRequest {
    pub name_ct: B64,
    pub generation: u32,
    pub version: u64,
    pub written_at: i64,
    pub sig: Sig64,
}

impl DeleteRecordRequest {
    pub fn new(
        name_ct: B64,
        generation: u32,
        version: u64,
        written_at: i64,
        sig: Sig64,
    ) -> DeleteRecordRequest {
        DeleteRecordRequest {
            name_ct,
            generation,
            version,
            written_at,
            sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct PutSecretResponse {
    pub version: u64,
}

impl PutSecretResponse {
    pub fn new(version: u64) -> PutSecretResponse {
        PutSecretResponse { version }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionMeta {
    pub version: u64,
    pub written_at: i64,
    /// Display only, as in [`SecretVersion`].
    pub written_by: Tolerant<Actor>,
    pub size: u32,
    pub tombstone: bool,
    pub generation: u32,
    pub value_ct_hash: Hash32,
    pub name_ct_hash: Hash32,
    pub sig: Sig64,
}

impl VersionMeta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u64,
        written_at: i64,
        written_by: impl Into<Tolerant<Actor>>,
        size: u32,
        tombstone: bool,
        generation: u32,
        value_ct_hash: Hash32,
        name_ct_hash: Hash32,
        sig: Sig64,
    ) -> VersionMeta {
        VersionMeta {
            version,
            written_at,
            written_by: written_by.into(),
            size,
            tombstone,
            generation,
            value_ct_hash,
            name_ct_hash,
            sig,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct VersionList {
    pub versions: Vec<VersionMeta>,
}

impl VersionList {
    pub fn new(versions: Vec<VersionMeta>) -> VersionList {
        VersionList { versions }
    }
}

/// `GET /v1/audit?after={seq}`.
///
/// Read tolerantly (`docs/spec/audit.md#4`): `rows` holds the rows up to the
/// first one this build cannot verify, and `stop` says where and why. A row
/// in a newer row format, or one naming an action or actor this build does
/// not know, ends the rows a client can check; the ones after it are not
/// kept. A server never sets `stop`, and it is not serialized.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct AuditPage {
    pub rows: Vec<AuditRow>,
    pub head: Option<ChainHead>,
    #[serde(skip)]
    pub stop: Option<RowStop>,
}

impl AuditPage {
    pub fn new(rows: Vec<AuditRow>, head: Option<ChainHead>) -> AuditPage {
        AuditPage {
            rows,
            head,
            stop: None,
        }
    }
}

impl<'de> Deserialize<'de> for AuditPage {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        /// The page as sent. Unknown page fields are ignored, like any
        /// response's.
        #[derive(Deserialize)]
        struct Raw {
            rows: Vec<serde_json::Value>,
            head: Option<ChainHead>,
        }
        let raw = Raw::deserialize(d)?;
        let (rows, stop) =
            crate::proto::audit::read_rows(raw.rows).map_err(serde::de::Error::custom)?;
        Ok(AuditPage {
            rows,
            head: raw.head,
            stop,
        })
    }
}

/// The age v1 header every value ciphertext must begin with.
pub const AGE_HEADER: &[u8] = b"age-encryption.org/v1\n";

// ---------------------------------------------------------------- errors

/// The stable error codes (`docs/spec/http-api.md#5`). Codes are only ever
/// added: none is renamed, removed while a supported client may receive it,
/// or reused with a different meaning. A client reads an [`ErrorBody`]'s code
/// as a [`Tolerant`], so a code added later keeps its string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ErrorCode {
    /// The one body for every authentication failure: unknown token, revoked
    /// token, expired vault, bad or replayed signature, a bearer or v1
    /// credential.
    Unauthorized,
    TokenExpired,
    Forbidden,
    NotFound,
    Conflict,
    StaleGeneration,
    ChallengeReused,
    PreconditionFailed,
    ValueTooLarge,
    InvalidRequest,
    CredentialInQuery,
    ChallengeExpired,
    InvalidProofOfWork,
    VaultIdMismatch,
    NotAgeCiphertext,
    IncompleteRotation,
    TtlTooLong,
    VaultQuotaExceeded,
    NameQuotaExceeded,
    TokenQuotaExceeded,
    ConfigTooLarge,
    ConfigQuotaExceeded,
    PreconditionRequired,
    RateLimited,
    Unavailable,
    Internal,
    /// A descriptor, bundle, record or children signature does not verify.
    BadSignature,
    /// A record's signed version is not the version the server would assign.
    VersionMismatch,
    /// A key does not match the vault's descriptor or pinned id.
    KeyMismatch,
    /// The server shows an older record version than the client saw.
    VersionRollback,
    /// The server shows an older or different generation than the client saw.
    GenerationRollback,
}

/// Whether a request refused with a code may be sent again
/// (`docs/spec/http-api.md#5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Retry {
    /// Nothing changed; the same operation, signed afresh, may succeed later
    /// (after `Retry-After`, where given).
    Yes,
    /// Nothing changed; it may succeed once rebuilt from fresh state (a new
    /// version, generation, revision or challenge).
    Refresh,
    /// It fails again as sent: the request, the credential or the vault
    /// must change.
    No,
}

impl Retry {
    /// The error table's word for it.
    pub fn as_str(self) -> &'static str {
        match self {
            Retry::Yes => "yes",
            Retry::Refresh => "refresh",
            Retry::No => "no",
        }
    }
}

impl ErrorCode {
    pub const ALL: [ErrorCode; 31] = [
        ErrorCode::Unauthorized,
        ErrorCode::TokenExpired,
        ErrorCode::Forbidden,
        ErrorCode::NotFound,
        ErrorCode::Conflict,
        ErrorCode::StaleGeneration,
        ErrorCode::ChallengeReused,
        ErrorCode::PreconditionFailed,
        ErrorCode::ValueTooLarge,
        ErrorCode::InvalidRequest,
        ErrorCode::CredentialInQuery,
        ErrorCode::ChallengeExpired,
        ErrorCode::InvalidProofOfWork,
        ErrorCode::VaultIdMismatch,
        ErrorCode::NotAgeCiphertext,
        ErrorCode::IncompleteRotation,
        ErrorCode::TtlTooLong,
        ErrorCode::VaultQuotaExceeded,
        ErrorCode::NameQuotaExceeded,
        ErrorCode::TokenQuotaExceeded,
        ErrorCode::ConfigTooLarge,
        ErrorCode::ConfigQuotaExceeded,
        ErrorCode::PreconditionRequired,
        ErrorCode::RateLimited,
        ErrorCode::Unavailable,
        ErrorCode::Internal,
        ErrorCode::BadSignature,
        ErrorCode::VersionMismatch,
        ErrorCode::KeyMismatch,
        ErrorCode::VersionRollback,
        ErrorCode::GenerationRollback,
    ];

    pub fn status(self) -> u16 {
        use ErrorCode::*;
        match self {
            InvalidRequest | CredentialInQuery | ChallengeExpired | InvalidProofOfWork => 400,
            Unauthorized | TokenExpired => 401,
            Forbidden => 403,
            NotFound => 404,
            Conflict | StaleGeneration | ChallengeReused | VersionMismatch | VersionRollback
            | GenerationRollback => 409,
            PreconditionFailed => 412,
            ValueTooLarge | ConfigTooLarge => 413,
            VaultIdMismatch | NotAgeCiphertext | IncompleteRotation | TtlTooLong
            | VaultQuotaExceeded | NameQuotaExceeded | TokenQuotaExceeded | ConfigQuotaExceeded
            | BadSignature | KeyMismatch => 422,
            PreconditionRequired => 428,
            RateLimited => 429,
            Internal => 500,
            Unavailable => 503,
        }
    }

    /// Whether a request refused with this code may be sent again.
    pub fn retry(self) -> Retry {
        use ErrorCode::*;
        match self {
            RateLimited | Unavailable | Internal => Retry::Yes,
            Conflict | StaleGeneration | ChallengeReused | ChallengeExpired
            | PreconditionFailed | VersionMismatch => Retry::Refresh,
            _ => Retry::No,
        }
    }

    /// The wire string.
    pub fn as_str(self) -> &'static str {
        use ErrorCode::*;
        match self {
            Unauthorized => "unauthorized",
            TokenExpired => "token_expired",
            Forbidden => "forbidden",
            NotFound => "not_found",
            Conflict => "conflict",
            StaleGeneration => "stale_generation",
            ChallengeReused => "challenge_reused",
            PreconditionFailed => "precondition_failed",
            ValueTooLarge => "value_too_large",
            InvalidRequest => "invalid_request",
            CredentialInQuery => "credential_in_query",
            ChallengeExpired => "challenge_expired",
            InvalidProofOfWork => "invalid_proof_of_work",
            VaultIdMismatch => "vault_id_mismatch",
            NotAgeCiphertext => "not_age_ciphertext",
            IncompleteRotation => "incomplete_rotation",
            TtlTooLong => "ttl_too_long",
            VaultQuotaExceeded => "vault_quota_exceeded",
            NameQuotaExceeded => "name_quota_exceeded",
            TokenQuotaExceeded => "token_quota_exceeded",
            ConfigTooLarge => "config_too_large",
            ConfigQuotaExceeded => "config_quota_exceeded",
            PreconditionRequired => "precondition_required",
            RateLimited => "rate_limited",
            Unavailable => "unavailable",
            Internal => "internal",
            BadSignature => "bad_signature",
            VersionMismatch => "version_mismatch",
            KeyMismatch => "key_mismatch",
            VersionRollback => "version_rollback",
            GenerationRollback => "generation_rollback",
        }
    }

    /// The inverse of [`ErrorCode::as_str`].
    pub fn parse(s: &str) -> Option<ErrorCode> {
        ErrorCode::ALL.into_iter().find(|c| c.as_str() == s)
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Vocabulary for ErrorCode {
    fn knows(name: &str) -> bool {
        ErrorCode::parse(name).is_some()
    }
}

/// Every error response. Never contains ciphertext, token material or a
/// client address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ErrorBody {
    /// A code a newer server may add and this build not know.
    pub error: Tolerant<ErrorCode>,
    pub message: String,
}

impl ErrorBody {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> ErrorBody {
        ErrorBody {
            error: Tolerant::Known(code),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::audit::{AuditAction, AuditEvent, AuditResult, GENESIS};

    /// The bound covers a worst-case batch serialized for real, and is not
    /// much looser than it.
    #[test]
    fn the_rotation_bound_covers_a_real_worst_case_batch() {
        let limits = Limits {
            max_names: 3,
            max_value_bytes: 4096,
            max_versions: 2,
            max_vault_bytes: 10_000,
            max_tokens: 4,
            max_configs: 2,
            max_config_bytes: 4096,
            max_config_versions: 2,
        };
        let versions = (limits.max_names * limits.max_versions
            + limits.max_configs * limits.max_config_versions) as usize;
        let value_len = limits.max_vault_bytes as usize / versions;
        let version = |_| RotatedVersion {
            old_name_hmac: NameHmac([0xff; 32]),
            version: u64::MAX,
            name_hmac: NameHmac([0xee; 32]),
            name_ct: B64(vec![0xab; 24 + 256 + 16]),
            value_ct: Some(B64(vec![0xcd; value_len])),
            written_at: i64::MIN,
            sig: Sig64([0x11; 64]),
        };
        let bundle = || SignedBundle {
            sealed: B64(vec![2; 48 + 198]),
            sig: Sig64([0x22; 64]),
        };
        let secret_count = (limits.max_names * limits.max_versions) as usize;
        let config_count = (limits.max_configs * limits.max_config_versions) as usize;
        let request = RotationRequest {
            from_generation: u32::MAX,
            from_revision: u64::MAX,
            descriptor: SignedDescriptor {
                descriptor: B64(vec![3; 189]),
                sig: Sig64([0x33; 64]),
            },
            owner_bundle: bundle(),
            secrets: (0..secret_count).map(version).collect(),
            configs: (0..config_count).map(version).collect(),
            tokens: (0..limits.max_tokens)
                .map(|_| ResealedBundle {
                    token_id: TokenId([0xaa; 16]),
                    bundle: bundle(),
                })
                .collect(),
            revoke: vec![TokenId([0xbb; 16]); limits.max_tokens as usize],
        };
        let len = serde_json::to_vec(&request).unwrap().len();
        let bound = limits.max_rotation_body();
        assert!(len <= bound, "{len} > {bound}");
        assert!(bound < len + 8 * 1024, "{bound} is loose against {len}");
    }

    #[test]
    fn scope_policy_matches_the_spec() {
        use Scope::*;
        // Order: meta, append, read, admin, config, config-write.
        assert_eq!(
            Scope::ALL.map(Scope::bundle_holds_vault_key),
            [false, false, true, true, false, false]
        );
        assert_eq!(
            Scope::ALL.map(Scope::bundle_holds_config_key),
            [false, false, true, true, true, true]
        );
        assert_eq!(
            Scope::ALL.map(Scope::bundle_holds_secret_writer),
            [false, true, false, true, false, false]
        );
        assert_eq!(
            Scope::ALL.map(Scope::bundle_holds_config_writer),
            [false, true, false, true, false, true]
        );
        // Server permissions agree with the key material.
        for s in Scope::ALL {
            assert_eq!(s.can_read_values(), s.bundle_holds_vault_key(), "{s}");
            assert_eq!(s.can_read_configs(), s.bundle_holds_config_key(), "{s}");
            assert_eq!(s.can_write_values(), s.bundle_holds_secret_writer(), "{s}");
            assert_eq!(s.can_write_configs(), s.bundle_holds_config_writer(), "{s}");
            assert!(s.can_read_audit(), "{s}");
        }
        assert_eq!(
            Scope::ALL.map(Scope::can_manage),
            [false, false, false, true, false, false]
        );
        let codes: std::collections::BTreeSet<u8> = Scope::ALL.map(Scope::code).into();
        assert_eq!(codes.len(), 6);
        assert!(!codes.contains(&OWNER_SCOPE_CODE));
        for s in Scope::ALL {
            assert_eq!(Scope::parse(&s.to_string()), Some(s));
            assert_eq!(serde_json::to_string(&s).unwrap(), format!("\"{s}\""));
        }
        assert_eq!(Admin.default_ttl_secs(), DAY);
        assert_eq!(Admin.max_ttl_secs(), 30 * DAY);
        for s in [Meta, Append, Read, Config, ConfigWrite] {
            assert_eq!(s.default_ttl_secs(), 90 * DAY);
            assert_eq!(s.max_ttl_secs(), 365 * DAY);
        }
    }

    #[test]
    fn error_codes_are_snake_case_with_stable_statuses() {
        let body = ErrorBody::new(ErrorCode::VaultQuotaExceeded, "m");
        assert_eq!(
            serde_json::to_string(&body).unwrap(),
            r#"{"error":"vault_quota_exceeded","message":"m"}"#
        );
        assert_eq!(ErrorCode::Unauthorized.status(), 401);
        assert_eq!(ErrorCode::PreconditionRequired.status(), 428);
        assert_eq!(ErrorCode::PreconditionFailed.status(), 412);
        assert_eq!(ErrorCode::Unavailable.status(), 503);
        assert_eq!(ErrorCode::VersionMismatch.status(), 409);
        assert_eq!(ErrorCode::BadSignature.status(), 422);
        assert_eq!(
            serde_json::to_string(&ErrorCode::GenerationRollback).unwrap(),
            "\"generation_rollback\""
        );
        // `as_str` is exactly what serde writes, for every code, and codes
        // are unique.
        let mut seen = std::collections::BTreeSet::new();
        for c in ErrorCode::ALL {
            assert_eq!(serde_json::to_string(&c).unwrap(), format!("\"{c}\""));
            assert_eq!(ErrorCode::parse(c.as_str()), Some(c));
            assert!(seen.insert(c.as_str()), "{c} twice");
        }
    }

    #[test]
    fn an_error_body_keeps_a_code_this_build_does_not_know() {
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":"future_conflict","message":"later"}"#).unwrap();
        assert_eq!(body.error.unknown(), Some("future_conflict"));
        assert_eq!(body.message, "later");
        let body: ErrorBody =
            serde_json::from_str(r#"{"error":"conflict","message":"now","hint":1}"#).unwrap();
        assert_eq!(body.error, ErrorCode::Conflict);
    }

    #[test]
    fn requests_refuse_unknown_fields() {
        let json = format!(
            r#"{{"name_ct":"AA","value_ct":"AA","generation":1,"version":1,"written_at":0,"sig":"{}","plaintext":"x"}}"#,
            B64::encode_str(&[0; 64])
        );
        assert!(serde_json::from_str::<PutSecretRequest>(&json).is_err());
        let ok = json.replace(r#","plaintext":"x""#, "");
        assert!(serde_json::from_str::<PutSecretRequest>(&ok).is_ok());
        // And a scope a server does not know is a refusal, not a guess.
        let register = serde_json::to_value(RegisterTokenRequest::new(
            TokenId([1; 16]),
            Key32([2; 32]),
            Key32([3; 32]),
            Scope::Read,
            0,
            None,
            1,
            SignedBundle::new(B64(vec![1]), Sig64([0; 64])),
        ))
        .unwrap();
        let mut future = register.clone();
        future["scope"] = "future".into();
        assert!(serde_json::from_value::<RegisterTokenRequest>(register).is_ok());
        assert!(serde_json::from_value::<RegisterTokenRequest>(future).is_err());
    }

    #[test]
    fn bundle_and_report_inputs_are_framed_and_binding() {
        let base = bundle_signing_input(&VaultId([1; 16]), &TokenId([2; 16]), 3, 4, b"sealed");
        assert!(base.starts_with(b"gv/v1/bundle\0"));
        for other in [
            bundle_signing_input(&VaultId([9; 16]), &TokenId([2; 16]), 3, 4, b"sealed"),
            bundle_signing_input(&VaultId([1; 16]), &TokenId([9; 16]), 3, 4, b"sealed"),
            bundle_signing_input(&VaultId([1; 16]), &TokenId([2; 16]), 4, 4, b"sealed"),
            bundle_signing_input(&VaultId([1; 16]), &TokenId([2; 16]), 3, 5, b"sealed"),
            bundle_signing_input(&VaultId([1; 16]), &TokenId([2; 16]), 3, 4, b"sealeD"),
        ] {
            assert_ne!(other, base);
        }
        let report = report_signing_input(&TokenId([1; 16]), 42);
        assert!(report.starts_with(b"gv/v1/report\0"));
        assert_ne!(report, report_signing_input(&TokenId([1; 16]), 43));
    }

    #[test]
    fn capabilities_extend_split_hosted_servers_document() {
        // A document from before `protocols`, `formats` and `features`.
        let old: Capabilities = serde_json::from_str(
            r#"{"proof_of_work":{"difficulty":8},"idle_expiry_days":null,"limits":{}}"#,
        )
        .unwrap();
        assert!(old.speaks(PROTOCOL));
        assert_eq!(old.formats, None);
        assert!(old.features.is_empty() && old.server.is_none());
        assert_eq!(old.proof_of_work, Some(ProofOfWork::new(8)));

        let now =
            Capabilities::new(None, None, Limits::default()).with_features([feature::TOKEN_REPORT]);
        let json = serde_json::to_value(&now).unwrap();
        assert_eq!(json["protocols"], serde_json::json!(["1"]));
        assert!(json["proof_of_work"].is_null() && json["idle_expiry_days"].is_null());
        assert_eq!(json["formats"]["audit_row"], 1);
        assert_eq!(json["formats"]["envelope"], 1);
        assert!(json.get("server").is_none(), "the version is opt-in");
        let newer: Capabilities =
            serde_json::from_str(r#"{"protocols":["2"],"limits":{},"quantum":true}"#).unwrap();
        assert!(!newer.speaks(PROTOCOL));
    }

    /// Every response body parses with an unknown field added at every level
    /// (`docs/spec/http-api.md#7`); only the audit row, whose fields are all
    /// hashed, refuses one, and the page still reads up to it.
    #[test]
    fn every_response_tolerates_an_unknown_field() {
        fn inject(v: &mut serde_json::Value) {
            match v {
                serde_json::Value::Object(m) => {
                    for (_, child) in m.iter_mut() {
                        inject(child);
                    }
                    m.insert("zz_added_later".into(), serde_json::json!({"x": [1, 2]}));
                }
                serde_json::Value::Array(items) => items.iter_mut().for_each(inject),
                _ => {}
            }
        }
        fn check<T: Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug>(
            value: T,
        ) {
            let mut json = serde_json::to_value(&value).unwrap();
            inject(&mut json);
            let back: T =
                serde_json::from_value(json.clone()).unwrap_or_else(|e| panic!("{e}: {json}"));
            assert_eq!(back, value);
        }
        let sig = Sig64([7; 64]);
        let descriptor = SignedDescriptor::from_parts(B64(vec![2; 189]), sig);
        let bundle = SignedBundle::new(B64(vec![5; 80]), sig);
        let token = TokenSummary::new(TokenId([1; 16]), Scope::Read, 1, 2, Key32([3; 32]), None);
        let status = VaultStatus::new(
            VaultId([1; 16]),
            1,
            2,
            Key32([1; 32]),
            Key32([2; 32]),
            descriptor.clone(),
            0,
            1,
            2,
            None,
            3,
            Limits::default(),
            Some(vec![token.clone()]),
            Some(bundle.clone()),
        );
        check(ChallengeResponse::new("c".into(), 8, 9));
        check(CreateVaultResponse::new(VaultId([1; 16]), 1, None));
        check(Capabilities::new(None, Some(90), Limits::default()));
        check(status);
        check(DescriptorList::new(vec![descriptor.clone()]));
        check(RotationResponse::new(2));
        check(DeleteVaultResponse::new(VaultId([4; 16])));
        check(RevokeResponse::new(vec![TokenId([4; 16])]));
        check(RegisterTokenResponse::new(TokenId([4; 16]), 5));
        check(TokenSelf::new(
            TokenId([1; 16]),
            VaultId([2; 16]),
            Scope::Meta,
            3,
            None,
            Key32([4; 32]),
            descriptor.clone(),
            bundle.clone(),
        ));
        let item = SecretListItem::new(
            NameHmac([1; 32]),
            B64(vec![1]),
            1,
            2,
            3,
            false,
            1,
            Hash32([2; 32]),
            sig,
        );
        check(SecretList::new(vec![item], None));
        check(SecretVersion::new(
            NameHmac([1; 32]),
            1,
            B64(vec![1]),
            Some(B64(vec![2])),
            1,
            2,
            Actor::Token(TokenId([9; 16])),
            false,
            sig,
        ));
        check(PutSecretResponse::new(3));
        check(VersionList::new(vec![VersionMeta::new(
            1,
            2,
            Actor::Owner,
            3,
            false,
            1,
            Hash32([1; 32]),
            Hash32([2; 32]),
            sig,
        )]));
        check(crate::proto::children::ChildrenBlob::new(
            1,
            B64(vec![1]),
            sig,
        ));
        check(ErrorBody::new(ErrorCode::Forbidden, "m"));

        // The audit page: fields added to the page and its head are fine. A
        // row in a known format with an added field is malformed: a new row
        // field comes with a new row format (`docs/spec/audit.md#4`).
        let row = crate::proto::audit::AuditRow::from_event(
            1,
            5,
            GENESIS,
            AuditEvent::simple(
                Actor::Owner,
                AuditAction::VaultCreate,
                None,
                AuditResult::Ok,
            ),
        );
        let page = AuditPage::new(vec![row.clone()], Some(row.head()));
        let mut json = serde_json::to_value(&page).unwrap();
        json["zz_added_later"] = 1.into();
        json["head"]["zz_added_later"] = 1.into();
        assert_eq!(
            serde_json::from_value::<AuditPage>(json.clone()).unwrap(),
            page
        );
        json["rows"][0]["zz_added_later"] = 1.into();
        assert!(serde_json::from_value::<AuditPage>(json).is_err());
    }
}
