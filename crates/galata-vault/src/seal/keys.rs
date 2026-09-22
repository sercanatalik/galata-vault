//! Raw vault and config keys ⇄ age's X25519 types.
//!
//! Bundles carry a vault or config secret as 32 raw bytes, and the API
//! carries the public keys the same way. age 0.12 constructs its X25519
//! identity and recipient only from their bech32 strings
//! (`AGE-SECRET-KEY-1…`, `age1…`), so this is the one place those strings are
//! built. The tests check the conversion against keys age itself generated.

use std::str::FromStr;

use crate::keys::{ConfigSecret, VaultSecret, random_config_secret, random_vault_secret};
use crate::proto::ids::Key32;
use bech32::{Bech32, Hrp};
use zeroize::Zeroizing;

use crate::seal::SealError;

// Evaluated at compile time: `parse_unchecked` is a `const fn`, so an
// invalid HRP here fails the build instead of a call at run time.
const SECRET_HRP: Hrp = Hrp::parse_unchecked("age-secret-key-");
const PUBLIC_HRP: Hrp = Hrp::parse_unchecked("age");

fn identity_of(secret: &[u8; 32]) -> Result<age::x25519::Identity, SealError> {
    // Encoding refuses only a string over bech32's length limit; 32 bytes
    // are far below it. Any failure is a key that cannot be used.
    let encoded = Zeroizing::new(
        bech32::encode_upper::<Bech32>(SECRET_HRP, secret).map_err(|_| SealError::Decrypt)?,
    );
    age::x25519::Identity::from_str(&encoded).map_err(|_| SealError::Decrypt)
}

pub(crate) fn identity(secret: &VaultSecret) -> Result<age::x25519::Identity, SealError> {
    identity_of(secret.as_bytes())
}

pub(crate) fn config_identity(secret: &ConfigSecret) -> Result<age::x25519::Identity, SealError> {
    identity_of(secret.as_bytes())
}

pub(crate) fn recipient(public: &Key32) -> Result<age::x25519::Recipient, SealError> {
    let encoded =
        bech32::encode::<Bech32>(PUBLIC_HRP, &public.0).map_err(|_| SealError::BadPublicKey)?;
    age::x25519::Recipient::from_str(&encoded).map_err(|_| SealError::BadPublicKey)
}

fn public_of(secret: &[u8; 32]) -> Result<Key32, SealError> {
    let public = identity_of(secret)?.to_public().to_string();
    let (_, bytes) = bech32::decode(&public).map_err(|_| SealError::BadPublicKey)?;
    Ok(Key32(
        bytes.try_into().map_err(|_| SealError::BadPublicKey)?,
    ))
}

/// The X25519 public key of a vault secret, computed by age.
pub fn vault_public_key(secret: &VaultSecret) -> Result<Key32, SealError> {
    public_of(secret.as_bytes())
}

/// The X25519 public key of a config secret, computed by age.
pub fn config_public_key(secret: &ConfigSecret) -> Result<Key32, SealError> {
    public_of(secret.as_bytes())
}

/// A fresh keypair for a new vault generation's secrets.
pub fn new_vault_keypair() -> Result<(VaultSecret, Key32), SealError> {
    let secret = random_vault_secret();
    let public = vault_public_key(&secret)?;
    Ok((secret, public))
}

/// A fresh keypair for a new vault generation's configs.
pub fn new_config_keypair() -> Result<(ConfigSecret, Key32), SealError> {
    let secret = random_config_secret();
    let public = config_public_key(&secret)?;
    Ok((secret, public))
}

#[cfg(test)]
mod tests {
    use super::*;
    use age::secrecy::ExposeSecret;

    /// age's own keys survive the trip through raw bytes, unchanged.
    #[test]
    fn conversion_agrees_with_age_generated_keys() {
        for _ in 0..16 {
            let theirs = age::x25519::Identity::generate();
            let theirs_str = theirs.to_string();
            let (_, raw) = bech32::decode(theirs_str.expose_secret()).unwrap();
            let secret = VaultSecret::from_bytes(Zeroizing::new(raw.try_into().unwrap()));

            let ours = identity(&secret).unwrap();
            assert_eq!(ours.to_string().expose_secret(), theirs_str.expose_secret());

            let (_, their_pub) = bech32::decode(&theirs.to_public().to_string()).unwrap();
            assert_eq!(vault_public_key(&secret).unwrap().0.to_vec(), their_pub);
            assert_eq!(
                recipient(&vault_public_key(&secret).unwrap())
                    .unwrap()
                    .to_string(),
                theirs.to_public().to_string()
            );
        }
    }

    #[test]
    fn new_keypairs_encrypt_and_decrypt() {
        let (secret, public) = new_vault_keypair().unwrap();
        let ct = age::encrypt(&recipient(&public).unwrap(), b"hello").unwrap();
        assert_eq!(
            age::decrypt(&identity(&secret).unwrap(), &ct).unwrap(),
            b"hello"
        );

        let (config, config_pub) = new_config_keypair().unwrap();
        let ct = age::encrypt(&recipient(&config_pub).unwrap(), b"hi").unwrap();
        assert_eq!(
            age::decrypt(&config_identity(&config).unwrap(), &ct).unwrap(),
            b"hi"
        );
        // The two keypairs are independent.
        assert!(age::decrypt(&identity(&secret).unwrap(), &ct).is_err());
    }
}
