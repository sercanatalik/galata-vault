//! HKDF-SHA256 with the one fixed salt every derivation uses.
//!
//! The input keying material is always 256 bits of CSPRNG output (a node key
//! or a token secret), or a key derived from one. RFC 5869 extraction is
//! correct for that; a password-hardening KDF would add nothing.
//!
//! Every `info` is framed: `label ‖ 0x00 ‖ data`, with the labels in
//! `crate::proto::frame::label`.

use crate::proto::frame::frame;
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// The HKDF salt for every derivation.
pub const SALT: &[u8] = b"galata-vault/v1";

// HKDF-Expand refuses only an output longer than 255 × HashLen (8160 bytes
// for SHA-256, RFC 5869 §2.3). The output here is a fixed 32-byte array, so
// the error is unreachable for any input; every key derivation goes through
// this function, and an impossible `Result` on each would be noise.
#[allow(clippy::expect_used)]
pub(crate) fn derive32(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(SALT), ikm);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(info, okm.as_mut_slice())
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    okm
}

/// `label ‖ 0x00 ‖ data`.
pub(crate) fn info(label: &str, data: &[u8]) -> Vec<u8> {
    frame(label, &[data])
}
