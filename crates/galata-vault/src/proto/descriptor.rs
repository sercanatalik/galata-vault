//! The generation descriptor: the owner's signed statement of
//! every public key a vault generation uses.
//!
//! ```text
//! descriptor = v(1) = 2 ‖ vault_id(16) ‖ generation(4) ‖ vault_pub(32) ‖ config_pub(32)
//!              ‖ secret_writer_pub(32) ‖ config_writer_pub(32) ‖ prev_hash(32) ‖ created_at(8)
//! signature  = Ed25519(owner_sign, frame("gv/v1/descriptor", descriptor))
//! prev_hash  = SHA-256(previous generation's descriptor), zeros at generation 1
//! ```
//!
//! A client pins a vault id, checks that the owner signing key hashes to it,
//! verifies the descriptor, and only then encrypts to `vault_pub` or
//! `config_pub`, or accepts a record signed by a writer key.

use serde::{Deserialize, Serialize};

use crate::proto::frame::{frame, label};
use crate::proto::ids::{B64, Hash32, Key32, Sig64, VaultId};
use crate::proto::integrity::{IntegrityError, verify_ed25519};

pub const DESCRIPTOR_VERSION: u8 = 1;
/// Bytes in an encoded descriptor.
pub const DESCRIPTOR_LEN: usize = 1 + 16 + 4 + 32 * 4 + 32 + 8;

/// What [`IntegrityError::Malformed`] names for a descriptor of a version
/// this build does not know.
pub const MALFORMED_VERSION: &str = "descriptor version";
/// What [`IntegrityError::Malformed`] names for a descriptor of the wrong
/// length.
pub const MALFORMED_LENGTH: &str = "descriptor length";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Descriptor {
    pub vault_id: VaultId,
    pub generation: u32,
    /// Secret records are sealed to this.
    pub vault_pub: Key32,
    /// Config records are sealed to this.
    pub config_pub: Key32,
    /// Verifies secret records.
    pub secret_writer_pub: Key32,
    /// Verifies config records.
    pub config_writer_pub: Key32,
    /// SHA-256 of the previous generation's descriptor; zeros at generation 1.
    pub prev_hash: Hash32,
    pub created_at: i64,
}

fn take<const N: usize>(bytes: &[u8], at: &mut usize) -> Result<[u8; N], IntegrityError> {
    let out = bytes
        .get(*at..)
        .and_then(|rest| rest.first_chunk::<N>())
        .copied()
        .ok_or(IntegrityError::Malformed(MALFORMED_LENGTH))?;
    *at += N;
    Ok(out)
}

impl Descriptor {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DESCRIPTOR_LEN);
        out.push(DESCRIPTOR_VERSION);
        out.extend_from_slice(&self.vault_id.0);
        out.extend_from_slice(&self.generation.to_be_bytes());
        for key in [
            &self.vault_pub,
            &self.config_pub,
            &self.secret_writer_pub,
            &self.config_writer_pub,
        ] {
            out.extend_from_slice(&key.0);
        }
        out.extend_from_slice(&self.prev_hash.0);
        out.extend_from_slice(&self.created_at.to_be_bytes());
        out
    }

    /// Decode a descriptor. The version byte is checked first, so a reader
    /// refuses a descriptor version it does not know as such, whatever its
    /// length (`docs/spec/records.md#1`).
    pub fn decode(bytes: &[u8]) -> Result<Descriptor, IntegrityError> {
        match bytes.first() {
            Some(&DESCRIPTOR_VERSION) => {}
            Some(_) => return Err(IntegrityError::Malformed(MALFORMED_VERSION)),
            None => return Err(IntegrityError::Malformed(MALFORMED_LENGTH)),
        }
        if bytes.len() != DESCRIPTOR_LEN {
            return Err(IntegrityError::Malformed(MALFORMED_LENGTH));
        }
        let mut at = 1;
        Ok(Descriptor {
            vault_id: VaultId(take(bytes, &mut at)?),
            generation: u32::from_be_bytes(take(bytes, &mut at)?),
            vault_pub: Key32(take(bytes, &mut at)?),
            config_pub: Key32(take(bytes, &mut at)?),
            secret_writer_pub: Key32(take(bytes, &mut at)?),
            config_writer_pub: Key32(take(bytes, &mut at)?),
            prev_hash: Hash32(take(bytes, &mut at)?),
            created_at: i64::from_be_bytes(take(bytes, &mut at)?),
        })
    }

    /// What the next generation's `prev_hash` names.
    pub fn hash(&self) -> Hash32 {
        Hash32::sha256(&self.encode())
    }

    /// The exact bytes the owner signs.
    pub fn signing_input(&self) -> Vec<u8> {
        frame(label::DESCRIPTOR, &[&self.encode()])
    }

    /// Whether `self` is the generation directly after `prev`, linked by hash.
    pub fn follows(&self, prev: &Descriptor) -> bool {
        self.check_follows(prev).is_ok()
    }

    /// As [`Descriptor::follows`], naming what does not follow: the vault,
    /// the generation, or the previous descriptor's hash.
    pub fn check_follows(&self, prev: &Descriptor) -> Result<(), IntegrityError> {
        if self.vault_id != prev.vault_id {
            return Err(IntegrityError::BindingMismatch("descriptor's vault id"));
        }
        if Some(self.generation) != prev.generation.checked_add(1) {
            return Err(IntegrityError::BindingMismatch("descriptor's generation"));
        }
        if self.prev_hash != prev.hash() {
            return Err(IntegrityError::BindingMismatch("previous descriptor hash"));
        }
        Ok(())
    }

    /// Whether `self` can be a vault's first generation.
    pub fn is_first(&self) -> bool {
        self.generation == 1 && self.prev_hash == Hash32([0; 32])
    }
}

/// A descriptor as it travels: its canonical bytes and the owner's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct SignedDescriptor {
    pub descriptor: B64,
    pub sig: Sig64,
}

impl SignedDescriptor {
    pub fn new(descriptor: &Descriptor, sig: Sig64) -> SignedDescriptor {
        SignedDescriptor {
            descriptor: B64(descriptor.encode()),
            sig,
        }
    }

    /// The bytes and signature exactly as given, decoded or not.
    pub fn from_parts(descriptor: B64, sig: Sig64) -> SignedDescriptor {
        SignedDescriptor { descriptor, sig }
    }

    /// Decode without verifying. Use only where the result is then verified.
    pub fn decode_unverified(&self) -> Result<Descriptor, IntegrityError> {
        Descriptor::decode(&self.descriptor.0)
    }

    /// Verify the owner's signature and decode.
    pub fn verify(&self, owner_sign_pub: &Key32) -> Result<Descriptor, IntegrityError> {
        let descriptor = Descriptor::decode(&self.descriptor.0)?;
        verify_ed25519(
            owner_sign_pub,
            &descriptor.signing_input(),
            &self.sig,
            "descriptor",
        )?;
        Ok(descriptor)
    }

    /// Verify for a pinned vault: the owner key
    /// hashes to the pinned id, the signature verifies, and the descriptor
    /// names that vault.
    pub fn verify_for(
        &self,
        vault_id: &VaultId,
        owner_sign_pub: &Key32,
    ) -> Result<Descriptor, IntegrityError> {
        if VaultId::from_owner_sign_pub(owner_sign_pub) != *vault_id {
            return Err(IntegrityError::KeyMismatch("owner signing key"));
        }
        let descriptor = self.verify(owner_sign_pub)?;
        if descriptor.vault_id != *vault_id {
            return Err(IntegrityError::KeyMismatch("descriptor's vault id"));
        }
        Ok(descriptor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Descriptor {
        Descriptor {
            vault_id: VaultId([1; 16]),
            generation: 7,
            vault_pub: Key32([2; 32]),
            config_pub: Key32([3; 32]),
            secret_writer_pub: Key32([4; 32]),
            config_writer_pub: Key32([5; 32]),
            prev_hash: Hash32([6; 32]),
            created_at: 1_757_500_000,
        }
    }

    #[test]
    fn encoding_roundtrips_and_has_a_fixed_length() {
        let d = sample();
        let bytes = d.encode();
        assert_eq!(bytes.len(), DESCRIPTOR_LEN);
        assert_eq!(Descriptor::decode(&bytes).unwrap(), d);
        assert_eq!(
            Descriptor::decode(&bytes[..bytes.len() - 1]),
            Err(IntegrityError::Malformed(MALFORMED_LENGTH))
        );
        assert_eq!(
            Descriptor::decode(&[]),
            Err(IntegrityError::Malformed(MALFORMED_LENGTH))
        );
        let mut v0 = bytes.clone();
        v0[0] = 0;
        assert_eq!(
            Descriptor::decode(&v0),
            Err(IntegrityError::Malformed(MALFORMED_VERSION))
        );
        // A later version is refused as a version, whatever its length.
        assert_eq!(
            Descriptor::decode(&[2, 0, 0]),
            Err(IntegrityError::Malformed(MALFORMED_VERSION))
        );
        assert!(d.signing_input().starts_with(b"gv/v1/descriptor\0\x01"));
    }

    #[test]
    fn a_chain_links_by_hash() {
        let first = Descriptor {
            generation: 1,
            prev_hash: Hash32([0; 32]),
            ..sample()
        };
        assert!(first.is_first());
        let next = Descriptor {
            generation: 2,
            prev_hash: first.hash(),
            ..sample()
        };
        assert!(next.follows(&first));
        assert!(!first.follows(&next));
        let forked = Descriptor {
            vault_pub: Key32([9; 32]),
            ..next.clone()
        };
        assert!(forked.follows(&first), "a fork links too: pins catch it");
        assert_ne!(forked.hash(), next.hash());
    }
}
