//! Node keys: the project key and every key derived beneath it.

use galata_vault_proto::FormatError;
use galata_vault_proto::codec::{decode_node_key, encode_node_key};
use galata_vault_proto::frame::label;
use galata_vault_proto::path::Segment;
use zeroize::Zeroizing;

use crate::kdf::{derive32, info};
use crate::owner::OwnerKeys;
use crate::random::random_bytes;

/// The key of one node in a project's tree. Holding it means owning that
/// node's vault and everything beneath it; nothing above or beside it is
/// reachable, because child derivation is one-way.
#[derive(Clone)]
pub struct NodeKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for NodeKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NodeKey(<redacted>)")
    }
}

impl NodeKey {
    /// A fresh project key (or a fresh key for a re-rooted node).
    pub fn generate() -> NodeKey {
        NodeKey(random_bytes::<32>())
    }

    pub fn from_bytes(bytes: Zeroizing<[u8; 32]>) -> NodeKey {
        NodeKey(bytes)
    }

    /// Parse a `gvk1_…` string, checksum first.
    pub fn parse(s: &str) -> Result<NodeKey, FormatError> {
        decode_node_key(s).map(NodeKey)
    }

    /// The `gvk1_…` form, for a recovery or delegation kit.
    pub fn encode(&self) -> Zeroizing<String> {
        encode_node_key(&self.0)
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// `HKDF-SHA256(ikm = self, salt = "galata-vault/v1", info = "gv/v1/child" ‖ 0x00 ‖ segment)`.
    pub fn child(&self, segment: &Segment) -> NodeKey {
        NodeKey(derive32(
            self.0.as_slice(),
            &info(label::CHILD, segment.as_str().as_bytes()),
        ))
    }

    /// Follow `segments` down from this node.
    pub fn descend(&self, segments: &[Segment]) -> NodeKey {
        segments
            .iter()
            .fold(self.clone(), |key, segment| key.child(segment))
    }

    /// The owner keys of this node's vault.
    pub fn owner(&self) -> OwnerKeys {
        OwnerKeys::from_node(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use galata_vault_proto::path::EnvPath;

    fn root() -> NodeKey {
        let mut b = [0u8; 32];
        for (i, x) in b.iter_mut().enumerate() {
            *x = i as u8;
        }
        NodeKey::from_bytes(Zeroizing::new(b))
    }

    #[test]
    fn derivation_is_deterministic_and_segment_specific() {
        let prod = Segment::new("prod").unwrap();
        let dev = Segment::new("dev").unwrap();
        assert_eq!(
            root().child(&prod).as_bytes(),
            root().child(&prod).as_bytes()
        );
        assert_ne!(
            root().child(&prod).as_bytes(),
            root().child(&dev).as_bytes()
        );
        assert_ne!(root().child(&prod).as_bytes(), root().as_bytes());
    }

    #[test]
    fn descend_equals_chained_children() {
        let path = EnvPath::parse("acme/prod/eu").unwrap();
        let tail = &path.segments()[1..];
        let chained = root().child(&tail[0]).child(&tail[1]);
        assert_eq!(root().descend(tail).as_bytes(), chained.as_bytes());
    }

    #[test]
    fn encode_parse_roundtrip_and_redacted_debug() {
        let k = NodeKey::generate();
        let s = k.encode();
        assert!(s.starts_with("gvk1_"));
        assert_eq!(NodeKey::parse(&s).unwrap().as_bytes(), k.as_bytes());
        assert_eq!(format!("{k:?}"), "NodeKey(<redacted>)");
    }

    #[test]
    fn a_key_of_another_version_is_refused() {
        let other = galata_vault_proto::codec::encode_checked("gvk2_", &[9u8; 32]);
        assert!(matches!(
            NodeKey::parse(&other),
            Err(FormatError::UnknownVersion { found: '2' })
        ));
    }

    #[test]
    fn generated_keys_differ() {
        assert_ne!(
            NodeKey::generate().as_bytes(),
            NodeKey::generate().as_bytes()
        );
    }
}
