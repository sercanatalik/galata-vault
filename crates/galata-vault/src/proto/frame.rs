//! The framing convention.
//!
//! Every derivation label, hashed input and signature context is
//!
//! ```text
//! label ‖ 0x00 ‖ field₀ ‖ field₁ ‖ …
//! ```
//!
//! where every label starts with `gv/v1/` and contains no `0x00`. Fields are
//! fixed-width, except at most the last. One convention everywhere, so no
//! two contexts can produce the same bytes.

/// Every label. HKDF `info` strings and signature contexts share one
/// namespace, and each label has exactly one purpose.
pub mod label {
    /// Child node key: `HKDF(K_parent, child ‖ 0 ‖ segment)`.
    pub const CHILD: &str = "gv/v1/child";
    /// A node's owner signing seed.
    pub const OWNER_SIGN: &str = "gv/v1/owner-sign";
    /// A node's owner box (X25519) secret.
    pub const OWNER_BOX: &str = "gv/v1/owner-box";
    /// A token's request-signing key: `HKDF(token_secret, token-auth ‖ 0 ‖ token_id)`.
    pub const TOKEN_AUTH: &str = "gv/v1/token-auth";
    /// A token's bundle-opening key. Nothing on the wire derives it.
    pub const TOKEN_BOX: &str = "gv/v1/token-box";
    /// The HMAC key for name indexes, derived from the name key.
    pub const NAME_INDEX: &str = "gv/v1/name-index";
    /// The XChaCha20-Poly1305 key for name ciphertexts.
    pub const NAME_ENC: &str = "gv/v1/name-enc";
    /// A name ciphertext's associated data.
    pub const NAME_AAD: &str = "gv/v1/name";
    /// The vault id: `SHA-256(vault-id ‖ 0 ‖ owner_sign_pub)[..16]`.
    pub const VAULT_ID: &str = "gv/v1/vault-id";
    /// The owner's signature over a generation descriptor.
    pub const DESCRIPTOR: &str = "gv/v1/descriptor";
    /// The owner's signature over a sealed bundle.
    pub const BUNDLE: &str = "gv/v1/bundle";
    /// A writer key's signature over a record.
    pub const RECORD: &str = "gv/v1/record";
    /// The owner's signature over the children record.
    pub const CHILDREN: &str = "gv/v1/children";
    /// A token-auth signature reporting the token as leaked.
    pub const REPORT: &str = "gv/v1/report";
    /// The first line of a request signing input (a text form, see `sig`).
    pub const SIG: &str = "gv/v1/sig";

    pub const ALL: [&str; 15] = [
        CHILD, OWNER_SIGN, OWNER_BOX, TOKEN_AUTH, TOKEN_BOX, NAME_INDEX, NAME_ENC, NAME_AAD,
        VAULT_ID, DESCRIPTOR, BUNDLE, RECORD, CHILDREN, REPORT, SIG,
    ];
}

/// `label ‖ 0x00 ‖ part₀ ‖ part₁ ‖ …`.
pub fn frame(label: &str, parts: &[&[u8]]) -> Vec<u8> {
    let len = label.len() + 1 + parts.iter().map(|p| p.len()).sum::<usize>();
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    for part in parts {
        out.extend_from_slice(part);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_distinct_and_nul_free() {
        let mut seen = std::collections::BTreeSet::new();
        for l in label::ALL {
            assert!(l.starts_with("gv/v1/"), "{l}");
            assert!(!l.as_bytes().contains(&0), "{l}");
            assert!(seen.insert(l), "{l} is used twice");
        }
    }

    #[test]
    fn frame_layout() {
        assert_eq!(frame("gv/v1/x", &[b"ab", b"c"]), b"gv/v1/x\0abc");
        assert_eq!(frame("gv/v1/x", &[]), b"gv/v1/x\0");
        // The separator keeps a label from running into its first field.
        assert_ne!(frame(label::CHILD, &[b"x"]), frame("gv/v1/childx", &[]));
    }
}
