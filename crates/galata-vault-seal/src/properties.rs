//! Property tests: the envelope round-trips, generated public keys agree with
//! age, and no decoder panics on arbitrary input.

use galata_vault_keys::FullBundle;
use galata_vault_proto::api::AGE_HEADER;
use galata_vault_proto::ids::VaultId;
use galata_vault_proto::record::RecordKind;
use proptest::collection::vec;
use proptest::prelude::*;

use crate::envelope::{
    EnvelopeContext, MAX_NAME_LEN, decode_envelope, encode_envelope, open_value,
};
use crate::keys::{config_public_key, new_vault_keypair, vault_public_key};

proptest! {
    #[test]
    fn envelope_roundtrip(
        name in "\\PC{0,64}",
        value in vec(any::<u8>(), 0..512),
        ts in any::<i64>(),
        version in any::<u64>(),
        generation in any::<u32>(),
    ) {
        prop_assume!(name.len() <= MAX_NAME_LEN);
        let ctx = EnvelopeContext { vault_id: VaultId([7; 16]), generation, version, written_at: ts };
        let d = decode_envelope(&encode_envelope(RecordKind::Secret, None, &ctx, &name, &value).unwrap()).unwrap();
        prop_assert_eq!(d.name, name);
        prop_assert_eq!(d.body.as_slice(), value.as_slice());
        prop_assert_eq!(d.ctx, ctx);
    }

    #[test]
    fn envelope_decoder_never_panics(bytes in vec(any::<u8>(), 0..300)) {
        let _ = decode_envelope(&bytes);
    }

    /// Noise after a genuine age header still reaches age's parser, and must
    /// come back as an error rather than a panic.
    #[test]
    fn open_value_never_panics(noise in vec(any::<u8>(), 0..300)) {
        let (secret, _) = new_vault_keypair().unwrap();
        let ctx = EnvelopeContext { vault_id: VaultId([0; 16]), generation: 1, version: 1, written_at: 0 };
        let _ = open_value(&secret, &ctx, "X", &noise);
        let mut framed = AGE_HEADER.to_vec();
        framed.extend_from_slice(&noise);
        prop_assert!(open_value(&secret, &ctx, "X", &framed).is_err());
    }
}

/// The descriptor's X25519 keys (computed in galata-vault-keys) are the ones age uses.
#[test]
fn generation_public_keys_agree_with_age() {
    for _ in 0..8 {
        let full = FullBundle::generate(1);
        assert_eq!(
            full.vault_secret.public(),
            vault_public_key(&full.vault_secret).unwrap()
        );
        assert_eq!(
            full.config_secret.public(),
            config_public_key(&full.config_secret).unwrap()
        );
    }
}
