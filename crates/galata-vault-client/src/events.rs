//! Where a client's notices go. Nothing here prints: `gv` prints them to
//! stderr, `gv ui` to its terminal feed, the Python package turns expiry
//! into a warning, and the default drops them.

use std::sync::Arc;

/// Something a long operation is doing, for a caller that shows progress.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Progress {
    /// A proof-of-work is being solved before creating `label`'s vault; it
    /// takes a few seconds at this difficulty.
    ProofOfWork {
        /// The environment path or description.
        label: String,
        /// The difficulty the server asked for, in bits.
        difficulty: u8,
    },
    /// An environment's vault was deleted (removal goes deepest first).
    Deleted {
        /// The environment path.
        path: String,
    },
    /// A child whose entry predated a rekey opened with the key held here,
    /// and its parent's children record points at it again.
    Relinked {
        /// The child.
        path: String,
        /// Its parent.
        parent: String,
    },
    /// A rekey's plan is recorded and its keys are stored; nothing on the
    /// server has changed yet.
    RekeyPlanned {
        /// The re-rooted node.
        path: String,
        /// How many environments move to fresh vaults.
        nodes: usize,
        /// How many tokens die with the old vaults.
        tokens: usize,
        /// Where the caller stored the new kit.
        kit: String,
    },
    /// A rekey finished one of its steps (`created`, `migrated`, `linked`,
    /// `retired`).
    RekeyStep {
        /// The re-rooted node.
        path: String,
        /// The step just completed.
        step: &'static str,
    },
}

/// Something the caller should know about, that did not stop the
/// operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Warning {
    /// Keeping an ancestor vault alive failed.
    KeepAliveFailed {
        /// The ancestor.
        path: String,
        /// Why, as an allow-listed message.
        message: String,
    },
    /// A node could not be opened (during rediscovery or removal). It is
    /// kept in the known tree so it can be repaired.
    Unreachable {
        /// The node.
        path: String,
        /// Why, as an allow-listed message (it names the node).
        message: String,
        /// The server does not know the vault (it expired, was deleted, or
        /// was re-rooted); an expired one can be repaired at the same id.
        vault_missing: bool,
    },
    /// A children record lists a child too deep to be a path.
    ChildTooDeep {
        /// The parent whose record lists it.
        parent: String,
        /// Why.
        message: String,
    },
    /// A child's sealed key does not open with its parent's owner key.
    SealedKeyUnopenable {
        /// The child.
        path: String,
        /// Why.
        message: String,
    },
    /// A child opens with its stored key, but pointing its parent's
    /// children record at it again failed.
    RelinkFailed {
        /// The child.
        path: String,
        /// Its parent.
        parent: String,
        /// Why.
        message: String,
    },
    /// A re-rooted node is detached: the key of its parent is not held
    /// here, so the parent's owner no longer reaches it. The caller is now
    /// its only owner.
    Detached {
        /// The re-rooted node.
        path: String,
        /// Its parent.
        parent: String,
    },
    /// A token was revoked without rotating: the keys it held (listed in
    /// `held`) still open what its holder copied, and records it signed
    /// still verify, until the vault rotates.
    ForwardOnlyRevocation {
        /// The environment.
        path: String,
        /// The token id, hex.
        token: String,
        /// The token's scope.
        scope: String,
        /// The keys its bundle held, as a phrase ("the secret key, …").
        held: String,
    },
}

/// Observes a handle's notices. Every method has a no-op default, so an
/// implementation overrides only what it shows. Notices reach only the
/// observer of the handle that made the request; nothing is global.
pub trait Events: Send + Sync {
    /// A step of a long operation.
    fn progress(&self, event: &Progress) {
        let _ = event;
    }

    /// The vault `label` expires at `expires_at` (Unix seconds) unless it is
    /// used before then. Sent at most once per handle, when a response
    /// announces an expiry within the warning window.
    fn expiry(&self, label: &str, expires_at: i64) {
        let _ = (label, expires_at);
    }

    /// Something the caller should know about.
    fn warning(&self, warning: &Warning) {
        let _ = warning;
    }
}

/// Drops every notice. The default observer.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoEvents;

impl Events for NoEvents {}

impl<E: Events + ?Sized> Events for Arc<E> {
    fn progress(&self, event: &Progress) {
        (**self).progress(event);
    }

    fn expiry(&self, label: &str, expires_at: i64) {
        (**self).expiry(label, expires_at);
    }

    fn warning(&self, warning: &Warning) {
        (**self).warning(warning);
    }
}
