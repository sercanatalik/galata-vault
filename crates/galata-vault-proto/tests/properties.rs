//! Property tests: every format round-trips, and no parser panics on
//! arbitrary input.

use galata_vault_proto::audit::{
    Actor, AuditAction, AuditEvent, AuditResult, AuditRow, GENESIS, verify_chain,
};
use galata_vault_proto::children::ChildrenRecord;
use galata_vault_proto::codec::{
    KEY_PREFIX, TOKEN_LEN, TOKEN_PREFIX, TokenString, decode_checked, decode_fixed,
    decode_node_key, encode_fixed, encode_node_key,
};
use galata_vault_proto::descriptor::Descriptor;
use galata_vault_proto::ids::{TokenId, VaultId};
use galata_vault_proto::path::EnvPath;
use galata_vault_proto::sig::{SigActor, SigParams};
use proptest::collection::vec;
use proptest::prelude::*;

proptest! {
    #[test]
    fn fixed_width_roundtrip(bytes in vec(any::<u8>(), 0..80)) {
        let s = encode_fixed(&bytes);
        let decoded = decode_fixed(&s, bytes.len()).unwrap();
        prop_assert_eq!(decoded.as_slice(), bytes.as_slice());
    }

    #[test]
    fn node_keys_roundtrip(key in any::<[u8; 32]>()) {
        prop_assert_eq!(*decode_node_key(&encode_node_key(&key)).unwrap(), key);
    }

    #[test]
    fn tokens_roundtrip(id in any::<[u8; 16]>(), vault in any::<[u8; 16]>(), secret in any::<[u8; 32]>()) {
        let s = TokenString::encode(&TokenId(id), &VaultId(vault), &secret);
        let t = TokenString::parse(&s).unwrap();
        prop_assert_eq!(t.id, TokenId(id));
        prop_assert_eq!(t.vault_id, VaultId(vault));
        prop_assert_eq!(*t.secret, secret);
    }

    #[test]
    fn checked_decoders_never_panic(s in "\\PC{0,120}") {
        let _ = decode_node_key(&s);
        let _ = TokenString::parse(&s);
    }

    /// Plausible-looking bodies: right prefix, base62 characters, any length.
    #[test]
    fn checked_decoders_on_prefixed_noise(body in "[0-9A-Za-z]{0,100}") {
        let _ = decode_checked(KEY_PREFIX, &format!("{KEY_PREFIX}{body}"), 32);
        let _ = decode_checked(TOKEN_PREFIX, &format!("{TOKEN_PREFIX}{body}"), TOKEN_LEN);
    }

    #[test]
    fn valid_paths_roundtrip(segments in vec("[a-z0-9][a-z0-9-]{0,20}", 1..=4)) {
        let s = segments.join("/");
        prop_assert_eq!(EnvPath::parse(&s).unwrap().to_string(), s);
    }

    #[test]
    fn path_parser_never_panics(s in "\\PC{0,200}") {
        let _ = EnvPath::parse(&s);
    }

    #[test]
    fn children_parser_never_panics(bytes in vec(any::<u8>(), 0..512)) {
        let _ = ChildrenRecord::parse(&bytes);
    }

    #[test]
    fn descriptor_decoder_never_panics(bytes in vec(any::<u8>(), 0..400)) {
        let _ = Descriptor::decode(&bytes);
    }

    #[test]
    fn sig_header_parser_never_panics(s in "\\PC{0,300}") {
        let _ = SigParams::parse(&s);
    }

    #[test]
    fn sig_header_roundtrip(
        token in proptest::option::of(any::<[u8; 16]>()),
        vault in any::<[u8; 16]>(),
        ts in any::<i64>(),
        nonce in any::<[u8; 16]>(),
        sig in vec(any::<u8>(), 64),
    ) {
        let actor = token.map_or(SigActor::Owner, |t| SigActor::Token(TokenId(t)));
        let p = SigParams { actor, vault_id: VaultId(vault), ts, nonce, sig: sig.try_into().unwrap() };
        prop_assert_eq!(SigParams::parse(&p.to_header_value()).unwrap(), p);
    }

    /// Changing any single row of a valid chain is detected.
    #[test]
    fn any_edit_breaks_the_chain(len in 2u64..12, victim in 0usize..12, new_ts in any::<i64>()) {
        let mut rows = Vec::new();
        let mut prev = GENESIS;
        for seq in 1..=len {
            let row = AuditRow::from_event(
                seq,
                seq as i64,
                prev,
                AuditEvent::simple(Actor::Owner, AuditAction::SecretRead, None, AuditResult::Ok),
            );
            prev = row.hash;
            rows.push(row);
        }
        let victim = victim % rows.len();
        prop_assume!(rows[victim].ts != new_ts);
        rows[victim].ts = new_ts;
        prop_assert!(verify_chain(None, &rows).is_err());
    }
}
