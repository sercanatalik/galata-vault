//! A node's owner keys: Ed25519 for signing requests, descriptors, bundles
//! and the children record; X25519 for opening the owner bundle, sealed child
//! keys and the children record.

use ed25519_dalek::{Signer, SigningKey};
use galata_vault_proto::api::{OWNER_SCOPE_CODE, OWNER_TOKEN_ID, bundle_signing_input};
use galata_vault_proto::children::{ChildrenBlob, ChildrenRecord, children_signing_input};
use galata_vault_proto::descriptor::{Descriptor, SignedDescriptor};
use galata_vault_proto::frame::label;
use galata_vault_proto::ids::{B64, Key32, Sig64, TokenId, VaultId};
use galata_vault_proto::sig::{SigActor, SigParams, SignedRequest, signing_input};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::bundle::{Binding, FullBundle, open_bundle, open_child_key, seal_bytes};
use crate::kdf::{derive32, info};
use crate::node::NodeKey;
use crate::random::random_bytes;

pub struct OwnerKeys {
    signing: SigningKey,
    boxing: crypto_box::SecretKey,
    sign_pub: Key32,
    box_pub: Key32,
    vault_id: VaultId,
}

impl std::fmt::Debug for OwnerKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OwnerKeys")
            .field("vault_id", &self.vault_id)
            .finish_non_exhaustive()
    }
}

impl OwnerKeys {
    pub(crate) fn from_node(node: &NodeKey) -> OwnerKeys {
        let sign_seed = derive32(node.as_bytes(), &info(label::OWNER_SIGN, &[]));
        let signing = SigningKey::from_bytes(&sign_seed);
        let box_secret = derive32(node.as_bytes(), &info(label::OWNER_BOX, &[]));
        let boxing = crypto_box::SecretKey::from_bytes(*box_secret);
        let sign_pub = Key32(signing.verifying_key().to_bytes());
        let box_pub = Key32(*boxing.public_key().as_bytes());
        OwnerKeys {
            vault_id: VaultId::from_owner_sign_pub(&sign_pub),
            signing,
            boxing,
            sign_pub,
            box_pub,
        }
    }

    pub fn vault_id(&self) -> VaultId {
        self.vault_id
    }

    pub fn sign_pub(&self) -> Key32 {
        self.sign_pub
    }

    pub fn box_pub(&self) -> Key32 {
        self.box_pub
    }

    pub(crate) fn sign(&self, message: &[u8]) -> Sig64 {
        Sig64(self.signing.sign(message).to_bytes())
    }

    /// Sign a request with a fresh random nonce. The caller puts
    /// `to_header_value()` in `Authorization`.
    pub fn sign_request(&self, request: &SignedRequest<'_>, ts: i64) -> SigParams {
        let nonce = *random_bytes::<16>();
        let input = signing_input(&SigActor::Owner, &self.vault_id, ts, &nonce, request);
        SigParams {
            actor: SigActor::Owner,
            vault_id: self.vault_id,
            ts,
            nonce,
            sig: self.sign(&input).0,
        }
    }

    /// Sign a generation descriptor. It must name this vault.
    pub fn sign_descriptor(&self, descriptor: &Descriptor) -> SignedDescriptor {
        assert_eq!(
            descriptor.vault_id, self.vault_id,
            "an owner signs only its own vault's descriptors"
        );
        SignedDescriptor::new(descriptor, self.sign(&descriptor.signing_input()))
    }

    /// Sign a sealed bundle's binding.
    pub fn sign_bundle(
        &self,
        token_id: &TokenId,
        scope_code: u8,
        generation: u32,
        sealed: &[u8],
    ) -> Sig64 {
        self.sign(&bundle_signing_input(
            &self.vault_id,
            token_id,
            scope_code,
            generation,
            sealed,
        ))
    }

    /// Open this vault's owner bundle for `generation`: the signature first,
    /// then the seal, then the binding.
    pub fn open_own_bundle(
        &self,
        signed: &galata_vault_proto::api::SignedBundle,
        generation: u32,
    ) -> Result<FullBundle, KeyError> {
        signed.verify(
            &self.sign_pub,
            &self.vault_id,
            &OWNER_TOKEN_ID,
            OWNER_SCOPE_CODE,
            generation,
        )?;
        open_bundle(
            &self.boxing,
            &signed.sealed.0,
            &Binding {
                vault_id: self.vault_id,
                token_id: OWNER_TOKEN_ID,
                generation,
            },
        )?
        .into_full()
    }

    /// Open a child key sealed to this owner by a re-root.
    pub fn open_child_key(&self, sealed: &[u8]) -> Result<NodeKey, KeyError> {
        open_child_key(&self.boxing, sealed, &self.vault_id)
    }

    /// Seal and sign the children record at `version`.
    pub fn seal_children(
        &self,
        version: u64,
        record: &ChildrenRecord,
    ) -> Result<ChildrenBlob, KeyError> {
        let plain = Zeroizing::new(record.to_bytes().map_err(KeyError::Children)?);
        let ct = seal_bytes(&self.box_pub, &plain)?;
        let sig = self.sign(&children_signing_input(&self.vault_id, version, &ct));
        Ok(ChildrenBlob::new(version, B64(ct), sig))
    }

    /// Verify the children record's signature, then open and parse it.
    pub fn open_children(&self, blob: &ChildrenBlob) -> Result<ChildrenRecord, KeyError> {
        blob.verify(&self.vault_id, &self.sign_pub)?;
        let plain = Zeroizing::new(
            self.boxing
                .unseal(&blob.ct.0)
                .map_err(|_| KeyError::Unseal)?,
        );
        ChildrenRecord::parse(&plain).map_err(KeyError::Children)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galata_vault_proto::children::{ChildEntry, ChildMode};
    use galata_vault_proto::ids::Hash32;
    use galata_vault_proto::path::Segment;

    #[test]
    fn vault_id_is_the_hash_of_the_signing_key() {
        let owner = NodeKey::generate().owner();
        assert_eq!(
            owner.vault_id(),
            VaultId::from_owner_sign_pub(&owner.sign_pub())
        );
    }

    #[test]
    fn owner_keys_are_deterministic_per_node() {
        let node = NodeKey::generate();
        let (a, b) = (node.owner(), node.owner());
        assert_eq!(a.sign_pub(), b.sign_pub());
        assert_eq!(a.box_pub(), b.box_pub());
        assert_ne!(a.sign_pub(), NodeKey::generate().owner().sign_pub());
    }

    #[test]
    fn request_signatures_verify_against_the_canonical_input() {
        let owner = NodeKey::generate().owner();
        let req = SignedRequest {
            if_match: Some("3"),
            ..SignedRequest::new("PUT", "/v1/secrets/ab", b"{}")
        };
        let params = owner.sign_request(&req, 1_757_500_000);
        assert_eq!(params.actor, SigActor::Owner);
        let sig = Sig64(params.sig);
        assert!(
            galata_vault_proto::integrity::verify_ed25519(
                &owner.sign_pub(),
                &params.signing_input(&req),
                &sig,
                "request"
            )
            .is_ok()
        );
        let tampered = SignedRequest {
            if_match: Some("4"),
            ..req
        };
        assert!(
            galata_vault_proto::integrity::verify_ed25519(
                &owner.sign_pub(),
                &params.signing_input(&tampered),
                &sig,
                "request"
            )
            .is_err()
        );
        // Two signatures of the same request carry different nonces.
        assert_ne!(owner.sign_request(&req, 1_757_500_000).nonce, params.nonce);
    }

    #[test]
    fn descriptors_verify_for_the_pinned_vault_only() {
        let owner = NodeKey::generate().owner();
        let d = FullBundle::generate(1).descriptor(owner.vault_id(), Hash32([0; 32]), 5);
        let signed = owner.sign_descriptor(&d);
        assert_eq!(
            signed
                .verify_for(&owner.vault_id(), &owner.sign_pub())
                .unwrap(),
            d
        );
        // Another owner's key does not hash to this vault id.
        let other = NodeKey::generate().owner();
        assert!(
            signed
                .verify_for(&owner.vault_id(), &other.sign_pub())
                .is_err()
        );
        // A descriptor for another vault, re-signed by that vault's owner, is
        // refused for this vault.
        let theirs = other.sign_descriptor(&FullBundle::generate(1).descriptor(
            other.vault_id(),
            Hash32([0; 32]),
            5,
        ));
        assert!(
            theirs
                .verify_for(&owner.vault_id(), &other.sign_pub())
                .is_err()
        );
    }

    #[test]
    fn the_children_record_is_sealed_signed_and_versioned() {
        let owner = NodeKey::generate().owner();
        let mut record = ChildrenRecord::new();
        record
            .insert(ChildEntry::new(
                Segment::new("prod").unwrap(),
                1,
                ChildMode::Derived,
            ))
            .unwrap();
        let blob = owner.seal_children(4, &record).unwrap();
        assert_eq!(owner.open_children(&blob).unwrap(), record);
        // A forged version, or a record signed by anyone else, is refused.
        let mut bumped = blob.clone();
        bumped.version = 5;
        assert!(owner.open_children(&bumped).is_err());
        let forger = NodeKey::generate().owner();
        let forged = ChildrenBlob::new(
            blob.version,
            blob.ct.clone(),
            forger.seal_children(4, &record).unwrap().sig,
        );
        assert!(owner.open_children(&forged).is_err());
    }
}
