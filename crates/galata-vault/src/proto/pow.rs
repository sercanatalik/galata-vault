//! Proof-of-work for vault creation: the price of an account-less service.
//!
//! Challenges are **stateless**. The server issues
//! `base64url(id ‖ expires_at ‖ difficulty ‖ tag)`, where
//! `tag = blake3_keyed(server_key, id ‖ expires_at ‖ difficulty)[..16]`, and
//! keeps nothing until a solution is spent (it remembers `id` until expiry, so
//! a challenge works once). A solution is a nonce such that
//! `blake3(derive("galata-vault v1 proof-of-work"), token ‖ nonce)` has at
//! least `difficulty` leading zero bits.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// blake3's derive-key context for the proof-of-work hash.
pub const POW_CONTEXT: &str = "galata-vault v1 proof-of-work";

/// Above this, a challenge is refused as malformed rather than solved forever.
pub const MAX_DIFFICULTY: u8 = 40;
/// How long a challenge stays solvable.
pub const CHALLENGE_TTL_SECS: i64 = 600;

const PAYLOAD_LEN: usize = 16 + 8 + 1;
const TAG_LEN: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PowError {
    #[error("the challenge is malformed")]
    Malformed,
    #[error("the challenge was not issued by this server")]
    Tampered,
    #[error("the challenge has expired")]
    Expired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// Random; remembered once spent, so the challenge is single-use.
    pub id: [u8; 16],
    pub expires_at: i64,
    pub difficulty: u8,
}

impl Challenge {
    fn payload(&self) -> [u8; PAYLOAD_LEN] {
        let mut p = [0u8; PAYLOAD_LEN];
        p[..16].copy_from_slice(&self.id);
        p[16..24].copy_from_slice(&self.expires_at.to_be_bytes());
        p[24] = self.difficulty;
        p
    }

    /// The token handed to a client.
    pub fn issue(&self, server_key: &[u8; 32]) -> String {
        let payload = self.payload();
        let tag = blake3::keyed_hash(server_key, &payload);
        let mut token = Vec::with_capacity(PAYLOAD_LEN + TAG_LEN);
        token.extend_from_slice(&payload);
        token.extend_from_slice(&tag.as_bytes()[..TAG_LEN]);
        URL_SAFE_NO_PAD.encode(token)
    }

    /// Authenticate and decode a token this server issued.
    pub fn open(token: &str, server_key: &[u8; 32], now: i64) -> Result<Challenge, PowError> {
        let raw = URL_SAFE_NO_PAD
            .decode(token.as_bytes())
            .map_err(|_| PowError::Malformed)?;
        if raw.len() != PAYLOAD_LEN + TAG_LEN {
            return Err(PowError::Malformed);
        }
        let (payload, tag) = raw.split_at(PAYLOAD_LEN);
        let expected = blake3::keyed_hash(server_key, payload);
        // Constant-time: fold the XOR of every byte before deciding.
        let diff = expected.as_bytes()[..TAG_LEN]
            .iter()
            .zip(tag)
            .fold(0u8, |acc, (a, b)| acc | (a ^ b));
        if diff != 0 {
            return Err(PowError::Tampered);
        }
        // The length is checked above; these only name the fields.
        let Some((id, rest)) = payload.split_first_chunk::<16>() else {
            return Err(PowError::Malformed);
        };
        let Some((expires_at, rest)) = rest.split_first_chunk::<8>() else {
            return Err(PowError::Malformed);
        };
        let Some(&difficulty) = rest.first() else {
            return Err(PowError::Malformed);
        };
        let (id, expires_at) = (*id, i64::from_be_bytes(*expires_at));
        if difficulty > MAX_DIFFICULTY {
            return Err(PowError::Malformed);
        }
        if now > expires_at {
            return Err(PowError::Expired);
        }
        Ok(Challenge {
            id,
            expires_at,
            difficulty,
        })
    }
}

/// `blake3(derive_key(POW_CONTEXT), challenge ‖ nonce as u64 little-endian)`.
pub fn pow_hash(token: &str, nonce: u64) -> [u8; 32] {
    let mut h = blake3::Hasher::new_derive_key(POW_CONTEXT);
    h.update(token.as_bytes());
    h.update(&nonce.to_le_bytes());
    *h.finalize().as_bytes()
}

pub fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut bits = 0;
    for &b in hash {
        if b == 0 {
            bits += 8;
        } else {
            return bits + b.leading_zeros();
        }
    }
    bits
}

pub fn verify(token: &str, difficulty: u8, nonce: u64) -> bool {
    leading_zero_bits(&pow_hash(token, nonce)) >= u32::from(difficulty)
}

/// Find a nonce. Expected work is 2^difficulty hashes.
///
/// The difficulty comes from the server, so a client refuses one above
/// [`MAX_DIFFICULTY`] (which no server issues) instead of searching forever.
pub fn solve(token: &str, difficulty: u8) -> Result<u64, PowError> {
    if difficulty > MAX_DIFFICULTY {
        return Err(PowError::Malformed);
    }
    (0..=u64::MAX)
        .find(|&nonce| verify(token, difficulty, nonce))
        .ok_or(PowError::Malformed)
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [7; 32];

    fn challenge(difficulty: u8) -> Challenge {
        Challenge {
            id: [3; 16],
            expires_at: 1_000,
            difficulty,
        }
    }

    #[test]
    fn issue_open_roundtrip() {
        let c = challenge(12);
        let token = c.issue(&KEY);
        assert_eq!(Challenge::open(&token, &KEY, 999).unwrap(), c);
    }

    #[test]
    fn expired_tampered_malformed() {
        let token = challenge(12).issue(&KEY);
        assert_eq!(Challenge::open(&token, &KEY, 1_001), Err(PowError::Expired));
        assert_eq!(
            Challenge::open(&token, &[8; 32], 0),
            Err(PowError::Tampered)
        );
        // Raise the difficulty field without the key: the tag no longer matches.
        let mut raw = URL_SAFE_NO_PAD.decode(&token).unwrap();
        raw[24] = 1;
        let forged = URL_SAFE_NO_PAD.encode(raw);
        assert_eq!(Challenge::open(&forged, &KEY, 0), Err(PowError::Tampered));
        assert_eq!(Challenge::open("!!", &KEY, 0), Err(PowError::Malformed));
        let absurd = challenge(MAX_DIFFICULTY + 1).issue(&KEY);
        assert_eq!(Challenge::open(&absurd, &KEY, 0), Err(PowError::Malformed));
    }

    #[test]
    fn solve_then_verify() {
        let token = challenge(10).issue(&KEY);
        let nonce = solve(&token, 10).unwrap();
        assert!(verify(&token, 10, nonce));
        // A solution is bound to its token.
        let other = challenge(10).issue(&[9; 32]);
        let other_nonce = solve(&other, 10).unwrap();
        assert!(verify(&other, 10, other_nonce));
        assert!(verify(&token, 0, 12345), "difficulty 0 always verifies");
    }

    #[test]
    fn leading_zero_count() {
        let mut h = [0u8; 32];
        assert_eq!(leading_zero_bits(&h), 256);
        h[1] = 0b0001_0000;
        assert_eq!(leading_zero_bits(&h), 11);
    }
}
