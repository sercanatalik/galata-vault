//! Fixed-width base62 and the checksummed strings built on it.
//!
//! ```text
//! gvk1_ <base62(32 B), 43 chars> <crc32, 6 chars>   a node key  (49 after the prefix)
//! gvt1_ <base62(64 B), 86 chars> <crc32, 6 chars>   a token     (92 after the prefix)
//!        token bytes = token_id(16) ‖ vault_id(16) ‖ token_secret(32)
//! ```
//!
//! The body is alphanumeric and the prefix ends in `_`, so a double-click
//! selects the whole string. The checksum is CRC32 over the *text*
//! `prefix ‖ body`: a single mistyped character is an 8-bit burst in that
//! input, and CRC32 detects every burst of up to 32 bits. So a one-character
//! typo is always caught, before any network request or storage lookup.
//!
//! The digit in the prefix is the format version. A string of the expected
//! kind under another digit (`gvk2_…`) is refused as
//! [`FormatError::UnknownVersion`], never reinterpreted.

use zeroize::{Zeroize, Zeroizing};

use crate::proto::ids::{TokenId, VaultId};

const ALPHABET: &[u8; 62] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

/// Characters in the checksum suffix: 62^6 > 2^32.
pub const CHECKSUM_WIDTH: usize = 6;

/// The prefix of a node key: a project key, or an exported environment key.
pub const KEY_PREFIX: &str = "gvk1_";
/// The prefix of an access token.
pub const TOKEN_PREFIX: &str = "gvt1_";

/// Bytes in a node key.
pub const KEY_LEN: usize = 32;
/// Bytes in a token secret.
pub const TOKEN_SECRET_LEN: usize = 32;
/// Bytes a token string carries: id, vault id, secret.
pub const TOKEN_LEN: usize = TokenId::LEN + VaultId::LEN + TOKEN_SECRET_LEN;

/// For secret scanners. A match still needs its checksum verified.
pub const KEY_REGEX: &str = r"gvk1_[0-9A-Za-z]{49}";
/// For secret scanners. A match still needs its checksum verified.
pub const TOKEN_REGEX: &str = r"gvt1_[0-9A-Za-z]{92}";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum FormatError {
    #[error("expected the prefix {expected}")]
    WrongPrefix { expected: &'static str },
    #[error("the prefix carries version {found}, which this build does not know")]
    UnknownVersion { found: char },
    #[error("expected {expected} characters after the prefix, found {got}")]
    WrongLength { expected: usize, got: usize },
    #[error("character {position} is not a base62 character")]
    BadCharacter { position: usize },
    #[error("checksum does not match; the string is mistyped or truncated")]
    Checksum,
    #[error("value is out of range for its width")]
    Overflow,
    #[error("expected {expected} hexadecimal characters")]
    Hex { expected: usize },
    #[error("invalid base64url")]
    Base64,
}

/// A string of the expected kind whose prefix digit is not the one this
/// build knows: `gvk2_…` where `gvk1_…` is expected.
fn other_version(expected: &str, s: &str) -> Option<FormatError> {
    let (kind, digit) = expected.split_at(expected.len() - 2);
    let mut rest = s.strip_prefix(kind)?.chars();
    let found = rest.next().filter(char::is_ascii_digit)?;
    (rest.next() == Some('_') && found.to_string() != digit[..1])
        .then_some(FormatError::UnknownVersion { found })
}

/// Characters needed to hold `n` bytes: the smallest `w` with 62^w ≥ 256^n.
/// log2(62) = 5.954196310…, so this is ceil(8n / log2 62) in integers.
pub const fn width_for(n_bytes: usize) -> usize {
    (n_bytes * 8 * 1_000_000_000).div_ceil(5_954_196_310)
}

/// Big-endian `bytes` as exactly `width_for(bytes.len())` base62 characters.
pub fn encode_fixed(bytes: &[u8]) -> String {
    let width = width_for(bytes.len());
    let mut num = Zeroizing::new(bytes.to_vec());
    let mut out = vec![b'0'; width];
    for slot in out.iter_mut().rev() {
        let mut rem: u32 = 0;
        for b in num.iter_mut() {
            let acc = (rem << 8) | u32::from(*b);
            *b = (acc / 62) as u8;
            rem = acc % 62;
        }
        *slot = ALPHABET[rem as usize];
    }
    // Every byte is from the ASCII alphabet, so each is one char.
    let s: String = out.iter().map(|&b| char::from(b)).collect();
    num.zeroize();
    s
}

fn digit(c: u8) -> Option<u32> {
    match c {
        b'0'..=b'9' => Some(u32::from(c - b'0')),
        b'A'..=b'Z' => Some(u32::from(c - b'A') + 10),
        b'a'..=b'z' => Some(u32::from(c - b'a') + 36),
        _ => None,
    }
}

/// The inverse of [`encode_fixed`]. Refuses any width but the exact one, and
/// any value that does not fit in `n_bytes`.
pub fn decode_fixed(s: &str, n_bytes: usize) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let width = width_for(n_bytes);
    if s.len() != width {
        return Err(FormatError::WrongLength {
            expected: width,
            got: s.len(),
        });
    }
    let mut num = Zeroizing::new(vec![0u8; n_bytes]);
    for (position, c) in s.bytes().enumerate() {
        let mut carry = digit(c).ok_or(FormatError::BadCharacter { position })?;
        for b in num.iter_mut().rev() {
            let acc = u32::from(*b) * 62 + carry;
            *b = (acc & 0xff) as u8;
            carry = acc >> 8;
        }
        if carry != 0 {
            return Err(FormatError::Overflow);
        }
    }
    Ok(num)
}

pub(crate) fn checksum(prefix: &str, body: &str) -> String {
    let mut h = crc32fast::Hasher::new();
    h.update(prefix.as_bytes());
    h.update(body.as_bytes());
    encode_fixed(&h.finalize().to_be_bytes())
}

/// `prefix ‖ base62(bytes) ‖ checksum`. Zeroized on drop, because for keys
/// and tokens the string *is* the secret.
pub fn encode_checked(prefix: &str, bytes: &[u8]) -> Zeroizing<String> {
    let body = encode_fixed(bytes);
    let sum = checksum(prefix, &body);
    Zeroizing::new(format!("{prefix}{body}{sum}"))
}

/// The inverse of [`encode_checked`]. The checksum is verified before the
/// body is decoded.
pub fn decode_checked(
    prefix: &'static str,
    s: &str,
    n_bytes: usize,
) -> Result<Zeroizing<Vec<u8>>, FormatError> {
    let rest = s.strip_prefix(prefix).ok_or_else(|| {
        other_version(prefix, s).unwrap_or(FormatError::WrongPrefix { expected: prefix })
    })?;
    let width = width_for(n_bytes);
    if rest.len() != width + CHECKSUM_WIDTH || !rest.is_ascii() {
        return Err(FormatError::WrongLength {
            expected: width + CHECKSUM_WIDTH,
            got: rest.chars().count(),
        });
    }
    let (body, sum) = rest.split_at(width);
    if let Some(position) = sum.bytes().position(|c| digit(c).is_none()) {
        return Err(FormatError::BadCharacter {
            position: width + position,
        });
    }
    if checksum(prefix, body) != sum {
        return Err(FormatError::Checksum);
    }
    decode_fixed(body, n_bytes)
}

/// Encode a 32-byte node key as `gvk1_…`.
pub fn encode_node_key(key: &[u8; KEY_LEN]) -> Zeroizing<String> {
    encode_checked(KEY_PREFIX, key)
}

/// Parse a `gvk1_…` node key.
pub fn decode_node_key(s: &str) -> Result<Zeroizing<[u8; KEY_LEN]>, FormatError> {
    let bytes = decode_checked(KEY_PREFIX, s.trim(), KEY_LEN)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

/// A parsed `gvt1_…` token: the public id, the vault it belongs to, and the
/// secret. The vault id lets a holder pin its vault before the first request
///.
pub struct TokenString {
    pub id: TokenId,
    pub vault_id: VaultId,
    pub secret: Zeroizing<[u8; TOKEN_SECRET_LEN]>,
}

impl std::fmt::Debug for TokenString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenString")
            .field("id", &self.id)
            .field("vault_id", &self.vault_id)
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl TokenString {
    pub fn encode(
        id: &TokenId,
        vault_id: &VaultId,
        secret: &[u8; TOKEN_SECRET_LEN],
    ) -> Zeroizing<String> {
        let mut raw = Zeroizing::new([0u8; TOKEN_LEN]);
        raw[..TokenId::LEN].copy_from_slice(&id.0);
        raw[TokenId::LEN..TokenId::LEN + VaultId::LEN].copy_from_slice(&vault_id.0);
        raw[TokenId::LEN + VaultId::LEN..].copy_from_slice(secret);
        encode_checked(TOKEN_PREFIX, raw.as_slice())
    }

    /// Parse a `gvt1_…` token.
    pub fn parse(s: &str) -> Result<TokenString, FormatError> {
        let raw = decode_checked(TOKEN_PREFIX, s.trim(), TOKEN_LEN)?;
        let mut id = [0u8; TokenId::LEN];
        id.copy_from_slice(&raw[..TokenId::LEN]);
        let mut vault = [0u8; VaultId::LEN];
        vault.copy_from_slice(&raw[TokenId::LEN..TokenId::LEN + VaultId::LEN]);
        let mut secret = Zeroizing::new([0u8; TOKEN_SECRET_LEN]);
        secret.copy_from_slice(&raw[TokenId::LEN + VaultId::LEN..]);
        Ok(TokenString {
            id: TokenId(id),
            vault_id: VaultId(vault),
            secret,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(37).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn widths_match_the_documented_formats() {
        assert_eq!(width_for(4), CHECKSUM_WIDTH);
        assert_eq!(width_for(32), 43);
        assert_eq!(width_for(64), 86);
        assert_eq!(TOKEN_LEN, 64);
        // The largest value of each width still encodes and decodes.
        for n in [4, 16, 32, 48, 64] {
            let max = vec![0xffu8; n];
            assert_eq!(*decode_fixed(&encode_fixed(&max), n).unwrap(), max);
        }
    }

    #[test]
    fn fixed_roundtrip_including_leading_zeros() {
        for bytes in [vec![0u8; 32], sample(32, 1), sample(64, 200), {
            let mut v = vec![0u8; 32];
            v[31] = 1;
            v
        }] {
            let s = encode_fixed(&bytes);
            assert_eq!(s.len(), width_for(bytes.len()));
            assert_eq!(*decode_fixed(&s, bytes.len()).unwrap(), bytes);
        }
    }

    #[test]
    fn overflow_is_refused() {
        let too_big = "z".repeat(width_for(32));
        assert_eq!(decode_fixed(&too_big, 32), Err(FormatError::Overflow));
    }

    #[test]
    fn node_key_roundtrip_and_shape() {
        let key: [u8; 32] = sample(32, 9).try_into().unwrap();
        let s = encode_node_key(&key);
        assert!(s.starts_with(KEY_PREFIX));
        assert_eq!(s.len(), KEY_PREFIX.len() + 49);
        assert!(
            s[KEY_PREFIX.len()..]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric())
        );
        assert_eq!(*decode_node_key(&s).unwrap(), key);
    }

    #[test]
    fn token_roundtrip_carries_the_vault_id_and_redacts_the_secret() {
        let id = TokenId(sample(16, 3).try_into().unwrap());
        let vault = VaultId(sample(16, 44).try_into().unwrap());
        let secret: [u8; 32] = sample(32, 77).try_into().unwrap();
        let s = TokenString::encode(&id, &vault, &secret);
        assert_eq!(s.len(), TOKEN_PREFIX.len() + 92);
        let parsed = TokenString::parse(&s).unwrap();
        assert_eq!(parsed.id, id);
        assert_eq!(parsed.vault_id, vault);
        assert_eq!(*parsed.secret, secret);
        let debug = format!("{parsed:?}");
        assert!(debug.contains("redacted"));
        assert!(!debug.contains(&hex::encode(secret)));
    }

    #[test]
    fn another_version_digit_is_an_unknown_version() {
        // A syntactically valid string of either kind under another digit.
        let key = encode_checked("gvk2_", &[7u8; 32]);
        assert_eq!(
            decode_node_key(&key),
            Err(FormatError::UnknownVersion { found: '2' })
        );
        let token = encode_checked("gvt0_", &[7u8; 48]);
        assert!(matches!(
            TokenString::parse(&token),
            Err(FormatError::UnknownVersion { found: '0' })
        ));
        // Another kind under the right digit is a kind mismatch, not a version.
        assert!(matches!(
            decode_node_key(&token),
            Err(FormatError::WrongPrefix { .. })
        ));
        let err = FormatError::UnknownVersion { found: '2' }.to_string();
        assert!(err.contains("version 2"), "{err}");
    }

    /// Every single-character substitution, at every position, is refused.
    #[test]
    fn every_single_character_typo_is_detected() {
        let key: [u8; 32] = sample(32, 42).try_into().unwrap();
        let id = TokenId(sample(16, 5).try_into().unwrap());
        let vault = VaultId(sample(16, 6).try_into().unwrap());
        let secret: [u8; 32] = sample(32, 99).try_into().unwrap();
        let cases: [(&'static str, Zeroizing<String>, usize); 2] = [
            (KEY_PREFIX, encode_node_key(&key), KEY_LEN),
            (
                TOKEN_PREFIX,
                TokenString::encode(&id, &vault, &secret),
                TOKEN_LEN,
            ),
        ];
        for (prefix, good, n) in cases {
            let bytes = good.as_bytes().to_vec();
            let mut checked = 0;
            for pos in prefix.len()..bytes.len() {
                for &c in ALPHABET.iter() {
                    if c == bytes[pos] {
                        continue;
                    }
                    let mut typo = bytes.clone();
                    typo[pos] = c;
                    let typo = String::from_utf8(typo).unwrap();
                    assert!(
                        decode_checked(prefix, &typo, n).is_err(),
                        "typo at {pos} to {} was accepted",
                        c as char
                    );
                    checked += 1;
                }
            }
            assert!(checked > 2_000);
        }
    }

    #[test]
    fn prefix_length_and_charset_errors_are_named() {
        let key = encode_node_key(&[7u8; 32]);
        assert_eq!(
            decode_node_key(&key.replace("gvk1_", "gvt1_")),
            Err(FormatError::WrongPrefix {
                expected: KEY_PREFIX
            })
        );
        assert!(matches!(
            decode_node_key(&key[..key.len() - 1]),
            Err(FormatError::WrongLength { .. })
        ));
        let mut bad = key.to_string();
        bad.replace_range(10..11, "-");
        assert!(matches!(
            decode_node_key(&bad),
            Err(FormatError::Checksum | FormatError::BadCharacter { .. })
        ));
    }
}
