//! The test-vector runner for record envelopes (feature `vectors`,
//! `docs/spec/README.md#5`): the plaintext encoding both ways, and opening
//! age ciphertexts. Pure, and not a supported interface; see
//! `crate::proto::vectors`.

use crate::keys::{ConfigSecret, VaultSecret};
use crate::proto::ids::VaultId;
use crate::proto::record::RecordKind;
use crate::proto::vectors::{Inputs, Outcome, Step, hex, integrity_failure, unknown_op};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::seal::SealError;
use crate::seal::envelope::{
    ConfigFormat, EnvelopeContext, EnvelopeFault, decode_envelope, encode_envelope, open_config,
    open_value,
};

/// The constructs this crate runs.
pub const CONSTRUCTS: [&str; 1] = ["envelopes"];

/// Run one case of a construct this crate owns.
pub fn run(construct: &str, op: &str, inputs: &Value) -> Outcome {
    let i = Inputs(inputs);
    let step = match construct {
        "envelopes" => envelopes(op, i),
        other => Err(Outcome::runner_error(format!(
            "galata-vault-seal does not run {other}"
        ))),
    };
    step.unwrap_or_else(|o| o)
}

/// The failure name of a value-crate error.
pub fn seal_failure(e: &SealError) -> &'static str {
    match e {
        SealError::NotAge => "unknown_version",
        SealError::Decrypt => "decrypt_failed",
        SealError::Envelope(f) => match f {
            EnvelopeFault::UnknownVersion(_) => "unknown_version",
            EnvelopeFault::UnknownKind(_) => "unknown_kind",
            EnvelopeFault::UnknownFormat(_) => "unknown_format",
            EnvelopeFault::Truncated => "truncated",
            EnvelopeFault::NameTooLong(_) => "bad_length",
            EnvelopeFault::NameNotUtf8 => "bad_encoding",
        },
        SealError::NameMismatch => "name_mismatch",
        SealError::Binding("vault id") => "vault_mismatch",
        SealError::Binding("generation") => "generation_mismatch",
        SealError::Binding("version") => "version_mismatch",
        SealError::Binding("write time") => "written_at_mismatch",
        SealError::KindMismatch { .. } => "kind_mismatch",
        SealError::NameTooLong => "bad_length",
        SealError::Key(k) => crate::keys::vectors::key_failure(k),
        SealError::Integrity(i) => integrity_failure(i),
        _ => "unmapped seal error",
    }
}

fn kind_of(s: &str) -> Step<RecordKind> {
    match s {
        "secret" => Ok(RecordKind::Secret),
        "config" => Ok(RecordKind::Config),
        other => Err(Outcome::runner_error(format!("no record kind {other:?}"))),
    }
}

fn context(i: Inputs<'_>) -> Step<EnvelopeContext> {
    Ok(EnvelopeContext {
        vault_id: VaultId(i.arr("vault_id")?),
        generation: i.u32("generation")?,
        version: i.u64("version")?,
        written_at: i.i64("written_at")?,
    })
}

fn envelopes(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "encode" => {
            let format = match i.opt_str("format")? {
                None => None,
                Some(f) => Some(
                    ConfigFormat::parse(f)
                        .ok_or_else(|| Outcome::runner_error("an unknown format in the inputs"))?,
                ),
            };
            match encode_envelope(
                kind_of(i.str("kind")?)?,
                format,
                &context(i)?,
                i.str("name")?,
                &i.hex("body")?,
            ) {
                Ok(p) => Outcome::success(json!({ "plaintext": hex(&*p) })),
                Err(e) => Outcome::failure(seal_failure(&e)),
            }
        }
        "decode" => match decode_envelope(&i.hex("plaintext")?) {
            Ok(d) => Outcome::success(json!({
                "kind": d.kind.as_str(),
                "format": d.format.map(ConfigFormat::as_str),
                "vault_id": d.ctx.vault_id.to_hex(),
                "generation": d.ctx.generation,
                "version": d.ctx.version,
                "written_at": d.ctx.written_at,
                "name": d.name,
                "body": hex(&*d.body),
            })),
            Err(e) => Outcome::failure(seal_failure(&e)),
        },
        "open" => {
            let secret = Zeroizing::new(i.arr::<32>("secret_key")?);
            let (ctx, name, ct) = (context(i)?, i.str("name")?, i.hex("value_ct")?);
            let opened = match i.str("open_as")? {
                "secret" => open_value(&VaultSecret::from_bytes(secret), &ctx, name, &ct)
                    .map(|o| (o.value, None)),
                _ => open_config(&ConfigSecret::from_bytes(secret), &ctx, name, &ct)
                    .map(|o| (o.body, Some(o.format.as_str()))),
            };
            match opened {
                Ok((body, format)) => {
                    Outcome::success(json!({ "body": hex(&*body), "format": format }))
                }
                Err(e) => Outcome::failure(seal_failure(&e)),
            }
        }
        _ => return Err(unknown_op("envelopes", op)),
    })
}
