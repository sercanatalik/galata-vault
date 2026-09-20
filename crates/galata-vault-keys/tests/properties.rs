//! Property tests: nothing that opens server-supplied bytes panics, and
//! names round-trip through the name key.

use galata_vault_keys::{NameContext, NameKey, NodeKey, TokenKeys};
use galata_vault_proto::api::{Scope, SignedBundle};
use galata_vault_proto::children::ChildrenBlob;
use galata_vault_proto::ids::{B64, Sig64, TokenId, VaultId};
use galata_vault_proto::path::Segment;
use galata_vault_proto::record::RecordKind;
use proptest::collection::vec;
use proptest::prelude::*;
use zeroize::Zeroizing;

fn token() -> TokenKeys {
    TokenKeys::from_parts(TokenId([1; 16]), VaultId([5; 16]), Zeroizing::new([2; 32]))
}

fn ctx() -> NameContext {
    NameContext {
        vault_id: VaultId([7; 16]),
        generation: 1,
        kind: RecordKind::Secret,
    }
}

proptest! {
    #[test]
    fn bundle_child_and_children_openers_never_panic(bytes in vec(any::<u8>(), 0..300), sig in any::<[u8; 32]>()) {
        let mut sig64 = [0u8; 64];
        sig64[..32].copy_from_slice(&sig);
        let signed = SignedBundle::new(B64(bytes.clone()), Sig64(sig64));
        let owner = NodeKey::from_bytes(Zeroizing::new([3; 32])).owner();
        let _ = token().open_bundle(&signed, &owner.sign_pub(), Scope::Read, 1);
        let _ = owner.open_own_bundle(&signed, 1);
        let _ = owner.open_child_key(&bytes);
        let _ = owner.open_children(&ChildrenBlob::new(1, B64(bytes), Sig64(sig64)));
    }

    #[test]
    fn name_decryption_never_panics(bytes in vec(any::<u8>(), 0..256)) {
        let _ = NameKey::from_bytes(Zeroizing::new([9; 32])).decrypt_name(&ctx(), &bytes);
    }

    #[test]
    fn names_roundtrip(name in "\\PC{0,64}") {
        let key = NameKey::from_bytes(Zeroizing::new([9; 32]));
        let sealed = key.encrypt_name(&ctx(), &name).unwrap();
        prop_assert_eq!(key.open_name(&ctx(), &key.hmac(&name), &sealed).unwrap(), name);
    }

    #[test]
    fn distinct_segments_give_unrelated_children(a in "[a-z0-9]{1,12}", b in "[a-z0-9]{1,12}") {
        prop_assume!(a != b);
        let root = NodeKey::from_bytes(Zeroizing::new([4; 32]));
        let ka = root.child(&Segment::new(&a).unwrap()).owner();
        let kb = root.child(&Segment::new(&b).unwrap()).owner();
        prop_assert_ne!(ka.vault_id(), kb.vault_id());
    }
}
