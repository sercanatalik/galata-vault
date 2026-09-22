//! The rotation batch: everything the server needs to move a
//! vault to a new generation in one transaction. Owner-only.
//!
//! Built entirely on the client, from what the server already stores:
//! 1. a fresh generation: vault and config keypairs, name key and both writer
//!    keys, named by a new descriptor linked to the current one by hash and
//!    signed by the owner;
//! 2. every retained secret and config version, **verified against the
//!    current descriptor first** (so a forged record is refused rather than
//!    laundered into the new generation), then re-encrypted and re-signed
//!    with its original version and write time;
//! 3. owner-signed bundles for the owner and every surviving token, each
//!    getting exactly what its scope allows;
//! 4. the tokens to revoke, dropped in the same transaction.
//!
//! The server applies all of it or none of it, and refuses a batch built from
//! a stale revision, missing any retained version, or failing any signature.

use crate::keys::{FullBundle, OwnerKeys, seal_for_scope, seal_owner_bundle};
use crate::proto::api::{
    ResealedBundle, RotatedVersion, RotationRequest, SecretVersion, VaultStatus,
};
use crate::proto::descriptor::Descriptor;
use crate::proto::ids::{B64, TokenId};
use crate::proto::record::RecordKind;

use crate::seal::SealError;
use crate::seal::record::{Writer, open_config_record, open_secret};

pub struct Rotation {
    pub request: RotationRequest,
    /// The new generation, for the caller to keep using once the server accepts.
    pub new_bundle: FullBundle,
    pub new_descriptor: Descriptor,
}

impl std::fmt::Debug for Rotation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Rotation")
            .field("to_generation", &self.new_bundle.generation)
            .field("secrets", &self.request.secrets.len())
            .field("configs", &self.request.configs.len())
            .field("tokens", &self.request.tokens.len())
            .field("revoke", &self.request.revoke.len())
            .finish()
    }
}

/// `secrets` and `configs` must be every retained version of each kind (the
/// server refuses an incomplete batch). `current` is the owner's bundle for
/// `descriptor`, which the caller has verified.
#[allow(clippy::too_many_arguments)]
pub fn build_rotation(
    owner: &OwnerKeys,
    status: &VaultStatus,
    descriptor: &Descriptor,
    current: &FullBundle,
    secrets: &[SecretVersion],
    configs: &[SecretVersion],
    revoke: &[TokenId],
    now: i64,
) -> Result<Rotation, SealError> {
    if current.generation != status.generation || descriptor.generation != status.generation {
        return Err(SealError::StaleGeneration {
            bundle: current.generation,
            vault: status.generation,
        });
    }
    let tokens = status.tokens.as_ref().ok_or(SealError::TokensNotVisible)?;
    // Every surviving token's bundle is resealed for its scope. A scope this
    // build does not know has no bundle kind here: refuse before anything is
    // built, rather than reseal it as something else or leave it out.
    if let Some(t) = tokens
        .iter()
        .filter(|t| !revoke.contains(&t.token_id))
        .find(|t| t.scope.known().is_none())
    {
        return Err(SealError::UnsupportedByClient(format!(
            "token {} has scope {:?}, which this client does not know, so it cannot reseal its bundle",
            t.token_id,
            t.scope.unknown().unwrap_or("?")
        )));
    }
    if let Some(unknown) = revoke
        .iter()
        .find(|id| !tokens.iter().any(|t| &t.token_id == *id))
    {
        return Err(SealError::UnknownToken(*unknown));
    }

    let next = FullBundle::generate(status.generation + 1);
    let next_descriptor = next.descriptor(owner.vault_id(), descriptor.hash(), now);

    let mut rotated_secrets = Vec::with_capacity(secrets.len());
    {
        let w = Writer {
            descriptor: &next_descriptor,
            name_key: &next.name_key,
            writer: &next.secret_writer,
        };
        for v in secrets {
            let opened = open_secret(descriptor, &current.name_key, &current.vault_secret, v)?;
            let rec = match &opened.value {
                Some(value) => w.secret(&opened.name, value, v.version, v.written_at)?,
                None => w.tombstone(RecordKind::Secret, &opened.name, v.version, v.written_at)?,
            };
            rotated_secrets.push(RotatedVersion::new(
                v.name_hmac,
                v.version,
                rec.name_hmac,
                B64(rec.name_ct),
                rec.value_ct.map(B64),
                v.written_at,
                rec.sig,
            ));
        }
    }

    let mut rotated_configs = Vec::with_capacity(configs.len());
    {
        let w = Writer {
            descriptor: &next_descriptor,
            name_key: &next.name_key,
            writer: &next.config_writer,
        };
        for v in configs {
            let opened =
                open_config_record(descriptor, &current.name_key, &current.config_secret, v)?;
            let rec = match (&opened.value, opened.format) {
                (Some(body), Some(format)) => {
                    w.config(&opened.name, format, body, v.version, v.written_at)?
                }
                _ => w.tombstone(RecordKind::Config, &opened.name, v.version, v.written_at)?,
            };
            rotated_configs.push(RotatedVersion::new(
                v.name_hmac,
                v.version,
                rec.name_hmac,
                B64(rec.name_ct),
                rec.value_ct.map(B64),
                v.written_at,
                rec.sig,
            ));
        }
    }

    let mut resealed = Vec::with_capacity(tokens.len());
    for t in tokens.iter().filter(|t| !revoke.contains(&t.token_id)) {
        let scope = t.scope.get().ok_or_else(|| {
            SealError::UnsupportedByClient(format!("token {} has an unknown scope", t.token_id))
        })?;
        let bundle = seal_for_scope(owner, &t.box_pub, &t.token_id, scope, &next)?;
        resealed.push(ResealedBundle::new(t.token_id, bundle));
    }

    Ok(Rotation {
        request: RotationRequest::new(
            status.generation,
            status.revision,
            owner.sign_descriptor(&next_descriptor),
            seal_owner_bundle(owner, &next)?,
            rotated_secrets,
            rotated_configs,
            resealed,
            revoke.to_vec(),
        ),
        new_bundle: next,
        new_descriptor: next_descriptor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{NodeKey, TokenKeys};
    use crate::proto::api::{Limits, Scope, TokenSummary};
    use crate::proto::audit::Actor;
    use crate::proto::ids::Hash32;
    use crate::seal::ConfigFormat;
    use crate::seal::record::{WrittenRecord, verify_version};

    struct Fixture {
        owner: OwnerKeys,
        status: VaultStatus,
        descriptor: Descriptor,
        current: FullBundle,
        secrets: Vec<SecretVersion>,
        configs: Vec<SecretVersion>,
        tokens: Vec<(Scope, TokenKeys)>,
    }

    fn as_version(w: WrittenRecord) -> SecretVersion {
        let tombstone = w.value_ct.is_none();
        SecretVersion::new(
            w.name_hmac,
            w.version,
            B64(w.name_ct),
            w.value_ct.map(B64),
            w.generation,
            w.written_at,
            Actor::Owner,
            tombstone,
            w.sig,
        )
    }

    fn fixture() -> Fixture {
        let owner = NodeKey::generate().owner();
        let current = FullBundle::generate(1);
        let descriptor = current.descriptor(owner.vault_id(), Hash32([0; 32]), 0);
        let sw = Writer {
            descriptor: &descriptor,
            name_key: &current.name_key,
            writer: &current.secret_writer,
        };
        let secrets = vec![
            as_version(sw.secret("DATABASE_URL", b"postgres://a", 1, 101).unwrap()),
            as_version(sw.secret("DATABASE_URL", b"postgres://b", 2, 102).unwrap()),
            as_version(sw.tombstone(RecordKind::Secret, "OLD_KEY", 1, 103).unwrap()),
        ];
        let cw = Writer {
            descriptor: &descriptor,
            name_key: &current.name_key,
            writer: &current.config_writer,
        };
        let configs = vec![
            as_version(
                cw.config("app", ConfigFormat::Toml, b"a = 1\r\n", 1, 201)
                    .unwrap(),
            ),
            as_version(
                cw.config("app", ConfigFormat::Toml, b"a = 2", 2, 202)
                    .unwrap(),
            ),
            as_version(cw.tombstone(RecordKind::Config, "gone", 1, 203).unwrap()),
        ];
        let tokens: Vec<(Scope, TokenKeys)> = Scope::ALL
            .into_iter()
            .map(|s| (s, TokenKeys::generate(owner.vault_id())))
            .collect();
        let status = VaultStatus::new(
            owner.vault_id(),
            1,
            9,
            owner.sign_pub(),
            owner.box_pub(),
            owner.sign_descriptor(&descriptor),
            1,
            0,
            0,
            None,
            0,
            Limits::default(),
            Some(
                tokens
                    .iter()
                    .map(|(scope, t)| TokenSummary::new(t.id(), *scope, 0, 0, t.box_pub(), None))
                    .collect(),
            ),
            None,
        );
        Fixture {
            owner,
            status,
            descriptor,
            current,
            secrets,
            configs,
            tokens,
        }
    }

    fn rotated_as_version(r: &RotatedVersion) -> SecretVersion {
        SecretVersion::new(
            r.name_hmac,
            r.version,
            r.name_ct.clone(),
            r.value_ct.clone(),
            2,
            r.written_at,
            Actor::Owner,
            r.value_ct.is_none(),
            r.sig,
        )
    }

    #[test]
    fn a_rotation_re_encrypts_re_signs_and_reseals() {
        let f = fixture();
        let revoked = f.tokens[2].1.id(); // the read token
        let r = build_rotation(
            &f.owner,
            &f.status,
            &f.descriptor,
            &f.current,
            &f.secrets,
            &f.configs,
            &[revoked],
            500,
        )
        .unwrap();
        let next = &r.new_bundle;
        let nd = &r.new_descriptor;
        assert_eq!(next.generation, 2);
        assert!(nd.follows(&f.descriptor), "linked by hash");
        assert_eq!(
            r.request
                .descriptor
                .verify_for(&f.owner.vault_id(), &f.owner.sign_pub())
                .unwrap(),
            *nd
        );
        assert!(next.matches(nd));

        for (old, new) in f.secrets.iter().zip(&r.request.secrets) {
            let v = rotated_as_version(new);
            verify_version(nd, RecordKind::Secret, &v).unwrap();
            let after = open_secret(nd, &next.name_key, &next.vault_secret, &v).unwrap();
            let before = open_secret(
                &f.descriptor,
                &f.current.name_key,
                &f.current.vault_secret,
                old,
            )
            .unwrap();
            assert_eq!(after.name, before.name);
            assert_eq!(after.version, before.version);
            assert_eq!(after.written_at, before.written_at);
            assert_eq!(
                after.value.as_deref().map(|v| v.to_vec()),
                before.value.as_deref().map(|v| v.to_vec())
            );
            // The old generation's keys neither verify nor open the new record.
            assert!(verify_version(&f.descriptor, RecordKind::Secret, &v).is_err());
        }
        for new in &r.request.configs {
            let v = rotated_as_version(new);
            verify_version(nd, RecordKind::Config, &v).unwrap();
            open_config_record(nd, &next.name_key, &next.config_secret, &v).unwrap();
        }

        let owner_full = f.owner.open_own_bundle(&r.request.owner_bundle, 2).unwrap();
        assert!(owner_full.matches(nd));
        assert_eq!(r.request.revoke, vec![revoked]);
        assert_eq!(r.request.tokens.len(), f.tokens.len() - 1);
        for resealed in &r.request.tokens {
            let (scope, keys) = f
                .tokens
                .iter()
                .find(|(_, t)| t.id() == resealed.token_id)
                .unwrap();
            let bundle = keys
                .open_bundle(&resealed.bundle, &f.owner.sign_pub(), *scope, 2)
                .unwrap();
            assert!(bundle.matches(nd), "{scope}");
        }
    }

    #[test]
    fn a_forged_record_is_refused_not_laundered() {
        let f = fixture();
        let mut forged = f.secrets.clone();
        forged[0].sig = crate::proto::ids::Sig64([0; 64]);
        assert!(
            build_rotation(
                &f.owner,
                &f.status,
                &f.descriptor,
                &f.current,
                &forged,
                &f.configs,
                &[],
                0
            )
            .is_err()
        );
    }

    #[test]
    fn stale_or_incomplete_inputs_are_refused() {
        let f = fixture();
        let old = FullBundle::generate(0);
        assert!(matches!(
            build_rotation(
                &f.owner,
                &f.status,
                &f.descriptor,
                &old,
                &f.secrets,
                &f.configs,
                &[],
                0
            ),
            Err(SealError::StaleGeneration { .. })
        ));
        let mut no_tokens = f.status.clone();
        no_tokens.tokens = None;
        assert!(matches!(
            build_rotation(
                &f.owner,
                &no_tokens,
                &f.descriptor,
                &f.current,
                &f.secrets,
                &f.configs,
                &[],
                0
            ),
            Err(SealError::TokensNotVisible)
        ));
        assert!(matches!(
            build_rotation(
                &f.owner,
                &f.status,
                &f.descriptor,
                &f.current,
                &f.secrets,
                &f.configs,
                &[TokenId([7; 16])],
                0
            ),
            Err(SealError::UnknownToken(_))
        ));
    }
}
