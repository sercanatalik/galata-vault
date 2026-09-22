//! What a deployment asks of its callers beyond the protocol: admission of
//! vault creations and of authenticated requests, an idle-expiry window, and
//! the quotas.
//!
//! The default policy asks for nothing: no proof of work, no request budget,
//! no expiry. Quotas apply in every policy; they bound a rotation batch to
//! one transaction, and are not an abuse control. `gv-server` and the
//! embedded backend both run the default policy; the [`Admission`] seam is
//! where another implementation would put proof of work or a request budget.

use std::sync::Arc;

use crate::proto::api::{
    Capabilities, ChallengeResponse, CreateVaultRequest, Limits, ProofOfWork, feature,
};

use crate::server_core::auth::Caller;
use crate::server_core::error::CoreError;

/// Admits vault creations and authenticated requests. Every method has a
/// default that admits everything and issues no challenge.
pub trait Admission: Send + Sync {
    /// The proof-of-work difficulty a creation needs, as the capabilities
    /// report it; `None` when it needs none.
    fn proof_of_work(&self) -> Option<u8> {
        None
    }

    /// `POST /v1/challenges`: a challenge to solve before creating a vault.
    /// Asked only when [`Admission::proof_of_work`] is set; otherwise the
    /// endpoint does not exist.
    fn challenge(&self, _now: i64) -> Result<ChallengeResponse, CoreError> {
        Err(CoreError::no_endpoint())
    }

    /// Checked before anything else about a creation request. A challenge it
    /// returns is spent once the creation's signature, descriptor and bundle
    /// verify, so each challenge admits one vault.
    fn admit_creation(
        &self,
        _request: &CreateVaultRequest,
        _now: i64,
    ) -> Result<Option<Admitted>, CoreError> {
        Ok(None)
    }

    /// Checked after a request authenticates and before it is served: a
    /// request budget for the caller's token or vault.
    fn admit_request(&self, _caller: &Caller, _now: i64) -> Result<(), CoreError> {
        Ok(())
    }

    /// The capabilities features this admission puts in force, from
    /// `crate::proto::api::feature` (`rate_limits` for a request budget).
    fn features(&self) -> Vec<&'static str> {
        Vec::new()
    }
}

/// A challenge that admitted a creation, to be spent with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Admitted {
    /// The challenge's random id.
    pub challenge_id: [u8; 16],
    /// How long the id must be remembered: the challenge's own expiry.
    pub expires_at: i64,
}

/// Admits everything and issues no challenge: the default admission.
#[derive(Debug, Clone, Copy, Default)]
pub struct AllowAll;

impl Admission for AllowAll {}

/// The policy a [`crate::server_core::Core`] enforces.
#[derive(Clone)]
pub struct Policy {
    /// Admits vault creations and authenticated requests.
    pub admission: Arc<dyn Admission>,
    /// Days without an authenticated request after which a vault stops
    /// authenticating. `None`, or `Some(0)`: never, which is what every
    /// server here sets; the field stays because the capabilities document
    /// reports it.
    pub idle_expiry_days: Option<u32>,
    /// The per-vault quotas.
    pub limits: Limits,
    /// The server name and version the capabilities advertise. `None`, the
    /// default, advertises none: it helps fingerprinting and a client needs
    /// nothing from it (`docs/spec/http-api.md#6`).
    pub server: Option<String>,
}

impl Default for Policy {
    /// No proof of work, no request budget, no expiry, the quotas of
    /// `Limits::default()`, and no advertised version.
    fn default() -> Policy {
        Policy {
            admission: Arc::new(AllowAll),
            idle_expiry_days: None,
            limits: Limits::default(),
            server: None,
        }
    }
}

impl std::fmt::Debug for Policy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Policy")
            .field("proof_of_work", &self.admission.proof_of_work())
            .field("idle_expiry_days", &self.idle_expiry_days)
            .field("limits", &self.limits)
            .field("server", &self.server)
            .finish()
    }
}

impl Policy {
    /// The idle window in seconds, or `None` when no vault expires. There is
    /// no zero-second window to misuse: a window of 0 would otherwise delete
    /// every vault at the next sweep.
    pub fn idle_secs(&self) -> Option<i64> {
        self.idle_expiry_days
            .filter(|days| *days > 0)
            .map(|days| i64::from(days) * 86_400)
    }

    /// What `GET /v1/capabilities` reports for this policy: the same
    /// document for every caller, with nothing about any vault.
    pub fn capabilities(&self) -> Capabilities {
        // Every core serves the leak report; the admission adds what it
        // enforces.
        let mut features = vec![feature::TOKEN_REPORT];
        features.extend(self.admission.features());
        Capabilities::new(
            self.admission.proof_of_work().map(ProofOfWork::new),
            self.idle_expiry_days.filter(|days| *days > 0),
            self.limits,
        )
        .with_features(features)
        .with_server(self.server.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_policy_asks_for_nothing() {
        let policy = Policy::default();
        assert_eq!(policy.idle_secs(), None);
        let caps = policy.capabilities();
        assert_eq!(caps.proof_of_work, None);
        assert_eq!(caps.idle_expiry_days, None);
        assert_eq!(caps.limits, Limits::default());
        let json = serde_json::to_value(&caps).unwrap();
        assert!(json["proof_of_work"].is_null() && json["idle_expiry_days"].is_null());
        assert_eq!(json["protocols"], serde_json::json!(["1"]));
        assert_eq!(json["features"], serde_json::json!(["token_report"]));
        assert!(json.get("server").is_none(), "no version unless asked");
    }

    #[test]
    fn the_version_is_advertised_only_when_asked() {
        let policy = Policy {
            server: Some("gv-server/9.9.9".into()),
            ..Policy::default()
        };
        let caps = policy.capabilities();
        assert_eq!(caps.server.as_deref(), Some("gv-server/9.9.9"));
        let default = Policy::default().capabilities();
        assert_eq!(caps.limits, default.limits);
        assert_eq!(caps.features, default.features);
    }

    #[test]
    fn zero_days_is_never() {
        let policy = Policy {
            idle_expiry_days: Some(0),
            ..Policy::default()
        };
        assert_eq!(policy.idle_secs(), None);
        assert_eq!(policy.capabilities().idle_expiry_days, None);
        let policy = Policy {
            idle_expiry_days: Some(30),
            ..Policy::default()
        };
        assert_eq!(policy.idle_secs(), Some(30 * 86_400));
        assert_eq!(policy.capabilities().idle_expiry_days, Some(30));
    }
}
