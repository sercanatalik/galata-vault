//! Integrity failures a client or server detects, and the one Ed25519
//! verification every signature goes through.
//!
//! Verification only: this crate never holds a signing key, and nothing here
//! can decrypt. The server links it to check descriptors, bundles, records
//! and requests without any key that opens a value.

use ed25519_dalek::{Signature, VerifyingKey};

use crate::ids::{Key32, Sig64};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum IntegrityError {
    /// A descriptor, bundle, record, children record or request signature
    /// does not verify.
    #[error("the {0} signature does not verify")]
    BadSignature(&'static str),
    /// A key or identity does not match what the client pinned.
    #[error("the {0} does not match the pinned vault")]
    KeyMismatch(&'static str),
    /// A signed or encrypted binding disagrees with what the server reports.
    #[error("the {0} does not match what was signed")]
    BindingMismatch(&'static str),
    /// The server now shows an older version of a record than this client saw.
    #[error("version rollback: this client saw version {known}, the server now shows {got}")]
    VersionRollback { known: u64, got: u64 },
    /// The server now shows an older, or a different, generation.
    #[error("generation rollback: this client saw generation {known}, the server now shows {got}")]
    GenerationRollback { known: u32, got: u32 },
    #[error("the {0} is malformed")]
    Malformed(&'static str),
}

/// `verify_strict` of `sig` over `message` with `public`. `what` names the
/// object in the error.
pub fn verify_ed25519(
    public: &Key32,
    message: &[u8],
    sig: &Sig64,
    what: &'static str,
) -> Result<(), IntegrityError> {
    let key =
        VerifyingKey::from_bytes(&public.0).map_err(|_| IntegrityError::BadSignature(what))?;
    key.verify_strict(message, &Signature::from_bytes(&sig.0))
        .map_err(|_| IntegrityError::BadSignature(what))
}
