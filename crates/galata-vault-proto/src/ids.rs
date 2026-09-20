//! Identifiers and byte fields as they appear on the wire.
//!
//! Fixed-size identifiers travel as lowercase hex; public keys, signatures
//! and opaque byte strings as unpadded base64url.

use std::fmt;
use std::str::FromStr;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::FormatError;
use crate::frame::{frame, label};

macro_rules! hex_bytes {
    ($(#[$meta:meta])* $name:ident, $n:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub [u8; $n]);

        impl $name {
            pub const LEN: usize = $n;

            pub fn to_hex(&self) -> String {
                hex::encode(self.0)
            }

            pub fn from_hex(s: &str) -> Result<Self, FormatError> {
                let mut out = [0u8; $n];
                hex::decode_to_slice(s, &mut out)
                    .map_err(|_| FormatError::Hex { expected: $n * 2 })?;
                Ok(Self(out))
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!(stringify!($name), "({})"), self.to_hex())
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.to_hex())
            }
        }

        impl FromStr for $name {
            type Err = FormatError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_hex(s)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.serialize_str(&self.to_hex())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                Self::from_hex(&s).map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_bytes!(
    /// A vault's public identifier. Bound to its owner key: see
    /// [`VaultId::from_owner_sign_pub`].
    VaultId,
    16
);
hex_bytes!(
    /// The public half of an access token.
    TokenId,
    16
);
hex_bytes!(
    /// A record's index: `HMAC-SHA256(index_key, kind ‖ name)`. Reveals
    /// nothing about the name to anyone without the name key.
    NameHmac,
    32
);
hex_bytes!(
    /// A 32-byte digest: a descriptor or ciphertext hash, or an audit-chain hash.
    Hash32,
    32
);

impl VaultId {
    /// `SHA-256("gv/v1/vault-id" ‖ 0x00 ‖ owner_sign_pub)[..16]`.
    ///
    /// Only the holder of the owner key can sign a creation request for this
    /// id, so nobody can squat a vault id, including after it expires. A
    /// client that pins the id can check any claimed owner key against it.
    pub fn from_owner_sign_pub(owner_sign_pub: &Key32) -> VaultId {
        let digest = Sha256::digest(frame(label::VAULT_ID, &[&owner_sign_pub.0]));
        let mut id = [0u8; 16];
        id.copy_from_slice(&digest[..16]);
        VaultId(id)
    }
}

impl Hash32 {
    pub fn sha256(data: &[u8]) -> Hash32 {
        let digest = Sha256::digest(data);
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Hash32(out)
    }
}

/// A 32-byte public key (Ed25519 or X25519), as unpadded base64url.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key32(pub [u8; 32]);

impl fmt::Debug for Key32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Key32({})", URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl Serialize for Key32 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Key32 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom(FormatError::Base64))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))?;
        Ok(Key32(arr))
    }
}

/// An Ed25519 signature, as unpadded base64url.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sig64(pub [u8; 64]);

impl fmt::Debug for Sig64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sig64({}…)", &URL_SAFE_NO_PAD.encode(self.0)[..8])
    }
}

impl Serialize for Sig64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Sig64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        let bytes = URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| serde::de::Error::custom(FormatError::Base64))?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| serde::de::Error::custom("expected 64 bytes"))?;
        Ok(Sig64(arr))
    }
}

/// Opaque bytes (ciphertext, sealed bundles) as unpadded base64url.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct B64(pub Vec<u8>);

impl B64 {
    pub fn encode_str(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    pub fn decode_str(s: &str) -> Result<Vec<u8>, FormatError> {
        URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(|_| FormatError::Base64)
    }
}

impl fmt::Debug for B64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Length only: these are ciphertexts and bundles, and a Debug line
        // is how bytes end up in a log.
        write!(f, "B64({} bytes)", self.0.len())
    }
}

impl Serialize for B64 {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for B64 {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        B64::decode_str(&s)
            .map(B64)
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_ids_roundtrip_through_json() {
        let id = VaultId([0xab; 16]);
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{}\"", "ab".repeat(16)));
        assert_eq!(serde_json::from_str::<VaultId>(&json).unwrap(), id);
        assert!(serde_json::from_str::<VaultId>("\"abcd\"").is_err());
    }

    #[test]
    fn vault_id_is_bound_to_the_owner_key() {
        let a = VaultId::from_owner_sign_pub(&Key32([1; 32]));
        let b = VaultId::from_owner_sign_pub(&Key32([2; 32]));
        assert_ne!(a, b);
        assert_eq!(a, VaultId::from_owner_sign_pub(&Key32([1; 32])));
        // The framing: label, NUL, key.
        let mut expected = [0u8; 16];
        expected.copy_from_slice(
            &Sha256::digest(
                b"gv/v1/vault-id\0"
                    .iter()
                    .chain(&[1u8; 32])
                    .copied()
                    .collect::<Vec<u8>>(),
            )[..16],
        );
        assert_eq!(a, VaultId(expected));
    }

    #[test]
    fn b64_debug_never_shows_bytes() {
        let b = B64(b"top secret ciphertext".to_vec());
        assert_eq!(format!("{b:?}"), "B64(21 bytes)");
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(serde_json::from_str::<B64>(&json).unwrap(), b);
    }

    #[test]
    fn signatures_roundtrip_and_have_exact_length() {
        let s = Sig64([7; 64]);
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<Sig64>(&json).unwrap(), s);
        assert!(serde_json::from_str::<Sig64>("\"AAAA\"").is_err());
    }
}
