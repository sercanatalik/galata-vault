//! The children record: how a node knows its children.
//!
//! It is an **owner-only** record at its own endpoint
//! (`GET` and `PUT /v1/vault/children`), not a secret:
//! - sealed to the node's owner box key, so no token can read it;
//! - signed by the owner signing key, so no token, and not the server, can
//!   forge it;
//! - versioned, with the same preconditions as any record.
//!
//! Decrypted, it lists each child's segment and how to obtain the child's key:
//!
//! * `derived`: recompute it from this node's key (one-way HKDF). Carries
//!   no key material.
//! * `sealed`: a random key (after a rekey re-rooted the child), sealed to
//!   this node's owner box key as bundle kind 7.

use serde::{Deserialize, Serialize};

use crate::frame::{frame, label};
use crate::ids::{B64, Hash32, Key32, Sig64, VaultId};
use crate::integrity::{IntegrityError, verify_ed25519};
use crate::path::Segment;

/// Secret names starting with this are reserved; users cannot create them.
pub const RESERVED_PREFIX: &str = "gv:";
pub const CHILDREN_RECORD_VERSION: u32 = 1;

pub fn is_reserved_name(name: &str) -> bool {
    name.starts_with(RESERVED_PREFIX)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
#[non_exhaustive]
pub enum ChildMode {
    Derived,
    Sealed { key_ct: B64 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ChildEntry {
    pub seg: Segment,
    pub created_at: i64,
    pub mode: ChildMode,
}

impl ChildEntry {
    pub fn new(seg: Segment, created_at: i64, mode: ChildMode) -> ChildEntry {
        ChildEntry {
            seg,
            created_at,
            mode,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChildrenRecord {
    pub v: u32,
    children: Vec<ChildEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChildrenError {
    #[error("children record version {0} is not supported")]
    Version(u32),
    #[error("children record lists {0:?} more than once")]
    Duplicate(String),
    #[error("{0:?} is already a child of this node")]
    Exists(String),
    #[error("{0:?} is not a child of this node")]
    Missing(String),
    #[error("children record is not valid JSON: {0}")]
    Json(String),
}

impl Default for ChildrenRecord {
    fn default() -> Self {
        ChildrenRecord::new()
    }
}

impl ChildrenRecord {
    pub fn new() -> ChildrenRecord {
        ChildrenRecord {
            v: CHILDREN_RECORD_VERSION,
            children: Vec::new(),
        }
    }

    pub fn parse(bytes: &[u8]) -> Result<ChildrenRecord, ChildrenError> {
        let mut record: ChildrenRecord =
            serde_json::from_slice(bytes).map_err(|e| ChildrenError::Json(e.to_string()))?;
        if record.v != CHILDREN_RECORD_VERSION {
            return Err(ChildrenError::Version(record.v));
        }
        record.children.sort_by(|a, b| a.seg.cmp(&b.seg));
        if let Some(w) = record.children.windows(2).find(|w| w[0].seg == w[1].seg) {
            return Err(ChildrenError::Duplicate(w[0].seg.to_string()));
        }
        Ok(record)
    }

    /// Canonical bytes: children sorted by segment.
    pub fn to_bytes(&self) -> Result<Vec<u8>, ChildrenError> {
        serde_json::to_vec(self).map_err(|e| ChildrenError::Json(e.to_string()))
    }

    pub fn children(&self) -> &[ChildEntry] {
        &self.children
    }

    pub fn get(&self, seg: &Segment) -> Option<&ChildEntry> {
        self.children.iter().find(|c| &c.seg == seg)
    }

    pub fn insert(&mut self, entry: ChildEntry) -> Result<(), ChildrenError> {
        match self.children.binary_search_by(|c| c.seg.cmp(&entry.seg)) {
            Ok(_) => Err(ChildrenError::Exists(entry.seg.to_string())),
            Err(at) => {
                self.children.insert(at, entry);
                Ok(())
            }
        }
    }

    /// Replace an existing child's mode (a rekey turns `derived` into `sealed`).
    pub fn set_mode(&mut self, seg: &Segment, mode: ChildMode) -> Result<(), ChildrenError> {
        let entry = self
            .children
            .iter_mut()
            .find(|c| &c.seg == seg)
            .ok_or_else(|| ChildrenError::Missing(seg.to_string()))?;
        entry.mode = mode;
        Ok(())
    }

    pub fn remove(&mut self, seg: &Segment) -> Result<ChildEntry, ChildrenError> {
        let at = self
            .children
            .iter()
            .position(|c| &c.seg == seg)
            .ok_or_else(|| ChildrenError::Missing(seg.to_string()))?;
        Ok(self.children.remove(at))
    }
}

/// The owner's signature input for a children record:
/// `frame("gv/v1/children", vault_id(16) ‖ version(8) ‖ SHA-256(ct))`.
pub fn children_signing_input(vault_id: &VaultId, version: u64, ct: &[u8]) -> Vec<u8> {
    frame(
        label::CHILDREN,
        &[&vault_id.0, &version.to_be_bytes(), &Hash32::sha256(ct).0],
    )
}

/// The children record as it is stored and served: its version, the sealed
/// record and the owner's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ChildrenBlob {
    pub version: u64,
    pub ct: B64,
    pub sig: Sig64,
}

impl ChildrenBlob {
    pub fn new(version: u64, ct: B64, sig: Sig64) -> ChildrenBlob {
        ChildrenBlob { version, ct, sig }
    }

    /// Check the owner's signature. Clients refuse anything that fails.
    pub fn verify(&self, vault_id: &VaultId, owner_sign_pub: &Key32) -> Result<(), IntegrityError> {
        verify_ed25519(
            owner_sign_pub,
            &children_signing_input(vault_id, self.version, &self.ct.0),
            &self.sig,
            "children record",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(s: &str) -> Segment {
        Segment::new(s).unwrap()
    }

    fn entry(s: &str) -> ChildEntry {
        ChildEntry {
            seg: seg(s),
            created_at: 1,
            mode: ChildMode::Derived,
        }
    }

    #[test]
    fn roundtrip_is_sorted_and_canonical() {
        let mut r = ChildrenRecord::new();
        r.insert(entry("staging")).unwrap();
        r.insert(entry("dev")).unwrap();
        r.insert(ChildEntry {
            seg: seg("prod"),
            created_at: 2,
            mode: ChildMode::Sealed {
                key_ct: B64(vec![1, 2, 3]),
            },
        })
        .unwrap();
        let names: Vec<_> = r.children().iter().map(|c| c.seg.as_str()).collect();
        assert_eq!(names, ["dev", "prod", "staging"]);
        let bytes = r.to_bytes().unwrap();
        assert_eq!(ChildrenRecord::parse(&bytes).unwrap(), r);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(r#""mode":{"kind":"derived"}"#));
        assert!(text.contains(r#""kind":"sealed","key_ct":"AQID""#));
    }

    #[test]
    fn duplicates_versions_and_unknown_fields_are_refused() {
        let mut r = ChildrenRecord::new();
        r.insert(entry("dev")).unwrap();
        assert_eq!(
            r.insert(entry("dev")),
            Err(ChildrenError::Exists("dev".into()))
        );
        let dup = br#"{"v":1,"children":[{"seg":"a","created_at":1,"mode":{"kind":"derived"}},{"seg":"a","created_at":2,"mode":{"kind":"derived"}}]}"#;
        assert_eq!(
            ChildrenRecord::parse(dup),
            Err(ChildrenError::Duplicate("a".into()))
        );
        assert_eq!(
            ChildrenRecord::parse(br#"{"v":2,"children":[]}"#),
            Err(ChildrenError::Version(2))
        );
        assert!(ChildrenRecord::parse(br#"{"v":1,"children":[],"server":"x"}"#).is_err());
        assert!(
            ChildrenRecord::parse(
                br#"{"v":1,"children":[{"seg":"Bad","created_at":1,"mode":{"kind":"derived"}}]}"#
            )
            .is_err()
        );
    }

    #[test]
    fn detach_and_remove() {
        let mut r = ChildrenRecord::new();
        r.insert(entry("prod")).unwrap();
        r.set_mode(
            &seg("prod"),
            ChildMode::Sealed {
                key_ct: B64(vec![9]),
            },
        )
        .unwrap();
        assert!(matches!(
            r.get(&seg("prod")).unwrap().mode,
            ChildMode::Sealed { .. }
        ));
        assert!(r.remove(&seg("prod")).is_ok());
        assert_eq!(
            r.remove(&seg("prod")),
            Err(ChildrenError::Missing("prod".into()))
        );
    }

    #[test]
    fn reserved_names() {
        assert!(is_reserved_name("gv:children"));
        assert!(is_reserved_name("gv:anything"));
        assert!(!is_reserved_name("GV_TOKEN"));
        assert!(!is_reserved_name("DATABASE_URL"));
    }

    #[test]
    fn the_signing_input_binds_vault_version_and_ciphertext() {
        let base = children_signing_input(&VaultId([1; 16]), 3, b"ct");
        assert!(base.starts_with(b"gv/v1/children\0"));
        assert_ne!(base, children_signing_input(&VaultId([2; 16]), 3, b"ct"));
        assert_ne!(base, children_signing_input(&VaultId([1; 16]), 4, b"ct"));
        assert_ne!(base, children_signing_input(&VaultId([1; 16]), 3, b"cu"));
    }
}
