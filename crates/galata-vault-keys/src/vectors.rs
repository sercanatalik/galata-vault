//! The test-vector runner for the constructs this crate owns (feature
//! `vectors`, `docs/spec/README.md#5`): the key schedule, names,
//! descriptors, bundles, record signatures, every signature, and the
//! children record. Pure, and not a supported interface; see
//! `galata_vault_proto::vectors`.

use galata_vault_proto::api::{Scope, SignedBundle, report_signing_input};
use galata_vault_proto::children::{
    ChildrenBlob, ChildrenError, ChildrenRecord, children_signing_input,
};
use galata_vault_proto::descriptor::{Descriptor, SignedDescriptor};
use galata_vault_proto::frame::label;
use galata_vault_proto::ids::{B64, Hash32, Key32, NameHmac, Sig64, TokenId, VaultId};
use galata_vault_proto::integrity::verify_ed25519;
use galata_vault_proto::path::EnvPath;
use galata_vault_proto::record::{RecordContext, RecordKind};
use galata_vault_proto::sig::{SigActor, SigError, SigParams, SignedRequest, signing_input};
use galata_vault_proto::vectors::{
    Inputs, Outcome, Step, format_failure, hex, integrity_failure, unknown_op,
};
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::KeyError;
use crate::bundle::Bundle;
use crate::kdf::{derive32, info};
use crate::name_key::{NameContext, NameKey};
use crate::node::NodeKey;
use crate::token::TokenKeys;
use crate::writer::WriterKey;

/// The constructs this crate runs.
pub const CONSTRUCTS: [&str; 7] = [
    "keys",
    "names",
    "descriptors",
    "bundles",
    "records",
    "signatures",
    "children",
];

/// Run one case of a construct this crate owns.
pub fn run(construct: &str, op: &str, inputs: &Value) -> Outcome {
    let i = Inputs(inputs);
    let step = match construct {
        "keys" => keys(op, i),
        "names" => names(op, i),
        "descriptors" => descriptors(op, i),
        "bundles" => bundles(op, i),
        "records" => records(op, i),
        "signatures" => signatures(op, i),
        "children" => children(op, i),
        other => Err(Outcome::runner_error(format!(
            "galata-vault-keys does not run {other}"
        ))),
    };
    step.unwrap_or_else(|o| o)
}

/// The failure name of a key-crate error.
pub fn key_failure(e: &KeyError) -> &'static str {
    match e {
        KeyError::Format(f) => format_failure(f),
        KeyError::Integrity(i) => integrity_failure(i),
        KeyError::Unseal | KeyError::NameDecrypt => "decrypt_failed",
        KeyError::UnknownVersion(_) => "unknown_version",
        KeyError::UnknownKind(_) => "unknown_kind",
        KeyError::BadLength { .. } => "bad_length",
        KeyError::Truncated => "truncated",
        KeyError::Binding("vault id") => "vault_mismatch",
        KeyError::Binding("token id") => "token_mismatch",
        KeyError::Binding("generation") => "generation_mismatch",
        KeyError::Binding(_) => "unmapped binding",
        KeyError::Kind { .. } => "kind_mismatch",
        KeyError::NameMismatch => "name_mismatch",
        KeyError::Children(c) => children_failure(c),
        KeyError::UnsupportedScope(_) => "unknown_kind",
        // Encryption, not a check on input: no vector expects it.
        KeyError::Encrypt(_) => "encrypt_failed",
    }
}

/// The failure name of a children-record error.
pub fn children_failure(e: &ChildrenError) -> &'static str {
    match e {
        ChildrenError::Version(_) => "unknown_version",
        _ => "bad_encoding",
    }
}

fn kind(i: Inputs<'_>) -> Step<RecordKind> {
    match i.str("kind")? {
        "secret" => Ok(RecordKind::Secret),
        "config" => Ok(RecordKind::Config),
        other => Err(Outcome::runner_error(format!("no record kind {other:?}"))),
    }
}

fn node(i: Inputs<'_>, key: &str) -> Step<NodeKey> {
    Ok(NodeKey::from_bytes(Zeroizing::new(i.arr(key)?)))
}

fn keys(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "hkdf" => {
            let (label, data) = (i.str("label")?, i.hex("data")?);
            let info = info(label, &data);
            let okm = derive32(&i.hex("ikm")?, &info);
            Outcome::success(json!({ "info": hex(&info), "okm": hex(*okm) }))
        }
        "node" => {
            let path = EnvPath::parse(i.str("path")?).map_err(Outcome::runner_error)?;
            let key = node(i, "root_key")?.descend(&path.segments()[1..]);
            let owner = key.owner();
            Outcome::success(json!({
                "node_key": hex(key.as_bytes()),
                "gvk1": key.encode().as_str(),
                "owner_sign_seed": hex(*derive32(key.as_bytes(), &info(label::OWNER_SIGN, &[]))),
                "owner_sign_pub": hex(owner.sign_pub().0),
                "owner_box_secret": hex(*derive32(key.as_bytes(), &info(label::OWNER_BOX, &[]))),
                "owner_box_pub": hex(owner.box_pub().0),
                "vault_id": owner.vault_id().to_hex(),
            }))
        }
        "vault_id" => Outcome::success(json!({
            "vault_id": VaultId::from_owner_sign_pub(&Key32(i.arr("owner_sign_pub")?)).to_hex()
        })),
        "token" => {
            let id = TokenId(i.arr("token_id")?);
            let secret = i.arr::<32>("secret")?;
            let t = TokenKeys::from_parts(id, VaultId(i.arr("vault_id")?), Zeroizing::new(secret));
            Outcome::success(json!({
                "token": t.token_string().as_str(),
                "auth_seed": hex(*derive32(&secret, &info(label::TOKEN_AUTH, &id.0))),
                "auth_pub": hex(t.auth_pub().0),
                "box_secret": hex(*derive32(&secret, &info(label::TOKEN_BOX, &id.0))),
                "box_pub": hex(t.box_pub().0),
            }))
        }
        "name_keys" => {
            let nk = i.hex("name_key")?;
            Outcome::success(json!({
                "index_key": hex(*derive32(&nk, &info(label::NAME_INDEX, &[]))),
                "enc_key": hex(*derive32(&nk, &info(label::NAME_ENC, &[]))),
            }))
        }
        _ => return Err(unknown_op("keys", op)),
    })
}

fn names(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    let ctx = |i: Inputs<'_>| -> Step<NameContext> {
        Ok(NameContext {
            vault_id: VaultId(i.arr("vault_id")?),
            generation: i.u32("generation")?,
            kind: kind(i)?,
        })
    };
    Ok(match op {
        "index" => {
            let nk = NameKey::from_bytes(Zeroizing::new(i.arr("name_key")?));
            Outcome::success(json!({ "index": nk.index(kind(i)?, i.str("name")?).to_hex() }))
        }
        "aad" => Outcome::success(json!({ "aad": hex(ctx(i)?.aad()) })),
        "open" => {
            let nk = NameKey::from_bytes(Zeroizing::new(i.arr("name_key")?));
            match nk.open_name(&ctx(i)?, &NameHmac(i.arr("index")?), &i.hex("name_ct")?) {
                Ok(name) => Outcome::success(json!({ "name": name })),
                Err(e) => Outcome::failure(key_failure(&e)),
            }
        }
        _ => return Err(unknown_op("names", op)),
    })
}

fn descriptor_fields(d: &Descriptor) -> Value {
    json!({
        "generation": d.generation,
        "vault_pub": hex(d.vault_pub.0),
        "config_pub": hex(d.config_pub.0),
        "secret_writer_pub": hex(d.secret_writer_pub.0),
        "config_writer_pub": hex(d.config_writer_pub.0),
        "prev_hash": d.prev_hash.to_hex(),
        "created_at": d.created_at,
    })
}

fn descriptors(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "encode" => {
            let owner = node(i, "owner_node_key")?.owner();
            let d = Descriptor {
                vault_id: owner.vault_id(),
                generation: i.u32("generation")?,
                vault_pub: Key32(i.arr("vault_pub")?),
                config_pub: Key32(i.arr("config_pub")?),
                secret_writer_pub: Key32(i.arr("secret_writer_pub")?),
                config_writer_pub: Key32(i.arr("config_writer_pub")?),
                prev_hash: Hash32(i.arr("prev_hash")?),
                created_at: i.i64("created_at")?,
            };
            Outcome::success(json!({
                "vault_id": owner.vault_id().to_hex(),
                "descriptor": hex(d.encode()),
                "hash": d.hash().to_hex(),
                "signing_input": hex(d.signing_input()),
                "sig": hex(owner.sign_descriptor(&d).sig.0),
            }))
        }
        "verify" => {
            let signed =
                SignedDescriptor::from_parts(B64(i.hex("descriptor")?), Sig64(i.arr("sig")?));
            match signed.verify_for(
                &VaultId(i.arr("vault_id")?),
                &Key32(i.arr("owner_sign_pub")?),
            ) {
                Ok(d) => Outcome::success(descriptor_fields(&d)),
                Err(e) => Outcome::failure(integrity_failure(&e)),
            }
        }
        "follows" => {
            let decode = |key| -> Step<Descriptor> {
                Descriptor::decode(&i.hex(key)?).map_err(Outcome::runner_error)
            };
            match decode("next")?.check_follows(&decode("prev")?) {
                Ok(()) => Outcome::success(json!({})),
                Err(e) => Outcome::failure(integrity_failure(&e)),
            }
        }
        _ => return Err(unknown_op("descriptors", op)),
    })
}

/// What a bundle holds: its kind, and every key, as hex.
fn bundle_outputs(b: &Bundle) -> Value {
    let mut m = Map::new();
    m.insert("kind".into(), b.kind_name().into());
    m.insert("name_key".into(), hex(b.name_key().as_bytes()).into());
    if let Some(k) = b.vault_secret() {
        m.insert("vault_sk".into(), hex(k.as_bytes()).into());
    }
    if let Some(k) = b.config_secret() {
        m.insert("config_sk".into(), hex(k.as_bytes()).into());
    }
    if let Some(k) = b.secret_writer() {
        m.insert("secret_writer".into(), hex(*k.to_bytes()).into());
    }
    if let Some(k) = b.config_writer() {
        m.insert("config_writer".into(), hex(*k.to_bytes()).into());
    }
    Value::Object(m)
}

fn signed_bundle(i: Inputs<'_>) -> Step<SignedBundle> {
    Ok(SignedBundle::new(
        B64(i.hex("sealed")?),
        Sig64(i.arr("sig")?),
    ))
}

fn bundles(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "open_token" => {
            let token = TokenKeys::from_parts(
                TokenId(i.arr("token_id")?),
                VaultId(i.arr("vault_id")?),
                Zeroizing::new(i.arr("token_secret")?),
            );
            let scope = Scope::parse(i.str("scope")?)
                .ok_or_else(|| Outcome::runner_error("an unknown scope in the inputs"))?;
            let bundle = match token.open_bundle(
                &signed_bundle(i)?,
                &Key32(i.arr("owner_sign_pub")?),
                scope,
                i.u32("generation")?,
            ) {
                Ok(b) => b,
                Err(e) => return Ok(Outcome::failure(key_failure(&e))),
            };
            if let Some(d) = i.0.get("descriptor") {
                let d = Inputs(d);
                let descriptor = Descriptor {
                    vault_id: token.vault_id(),
                    generation: d.u32("generation")?,
                    vault_pub: Key32(d.arr("vault_pub")?),
                    config_pub: Key32(d.arr("config_pub")?),
                    secret_writer_pub: Key32(d.arr("secret_writer_pub")?),
                    config_writer_pub: Key32(d.arr("config_writer_pub")?),
                    prev_hash: Hash32([0; 32]),
                    created_at: 0,
                };
                if !bundle.matches(&descriptor) {
                    return Ok(Outcome::failure("descriptor_mismatch"));
                }
            }
            Outcome::success(bundle_outputs(&bundle))
        }
        "open_owner" => {
            let owner = node(i, "owner_node_key")?.owner();
            match owner.open_own_bundle(&signed_bundle(i)?, i.u32("generation")?) {
                Ok(full) => Outcome::success(bundle_outputs(&Bundle::Full(full))),
                Err(e) => Outcome::failure(key_failure(&e)),
            }
        }
        "open_child" => {
            let owner = node(i, "owner_node_key")?.owner();
            match owner.open_child_key(&i.hex("sealed")?) {
                Ok(child) => Outcome::success(json!({ "node_key": hex(child.as_bytes()) })),
                Err(e) => Outcome::failure(key_failure(&e)),
            }
        }
        _ => return Err(unknown_op("bundles", op)),
    })
}

fn record_context(i: Inputs<'_>) -> Step<RecordContext> {
    Ok(RecordContext::new(
        VaultId(i.arr("vault_id")?),
        i.u32("generation")?,
        kind(i)?,
        NameHmac(i.arr("name_index")?),
        i.u64("version")?,
        i.i64("written_at")?,
        &i.hex("name_ct")?,
        i.opt_hex("value_ct")?.as_deref(),
    ))
}

fn records(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "sign" => {
            let writer = WriterKey::from_bytes(&i.arr("writer_seed")?);
            let ctx = record_context(i)?;
            Outcome::success(json!({
                "writer_pub": hex(writer.public().0),
                "tombstone": ctx.tombstone,
                "value_ct_hash": ctx.value_ct_hash.to_hex(),
                "name_ct_hash": ctx.name_ct_hash.to_hex(),
                "signing_input": hex(ctx.signing_input()),
                "sig": hex(writer.sign(&ctx).0),
            }))
        }
        "verify" => {
            match record_context(i)?.verify(&Key32(i.arr("writer_pub")?), &Sig64(i.arr("sig")?)) {
                Ok(()) => Outcome::success(json!({})),
                Err(e) => Outcome::failure(integrity_failure(&e)),
            }
        }
        _ => return Err(unknown_op("records", op)),
    })
}

fn signed(input: Vec<u8>, sig: Sig64) -> Outcome {
    Outcome::success(json!({ "signing_input": hex(input), "sig": hex(sig.0) }))
}

fn signatures(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "request" => {
            let body = i.hex("body")?;
            let request = SignedRequest {
                method: i.str("method")?,
                path_and_query: i.str("path")?,
                body: &body,
                if_match: i.opt_str("if_match")?,
                if_none_match: i.opt_str("if_none_match")?,
            };
            let (ts, nonce) = (i.i64("ts")?, i.arr::<16>("nonce")?);
            let (actor, vault_id, sig) = match i.str("signer")? {
                "owner" => {
                    let owner = node(i, "node_key")?.owner();
                    let text =
                        signing_input(&SigActor::Owner, &owner.vault_id(), ts, &nonce, &request);
                    (SigActor::Owner, owner.vault_id(), owner.sign(&text))
                }
                _ => {
                    let token = TokenKeys::from_parts(
                        TokenId(i.arr("token_id")?),
                        VaultId(i.arr("vault_id")?),
                        Zeroizing::new(i.arr("token_secret")?),
                    );
                    let actor = SigActor::Token(token.id());
                    let text = signing_input(&actor, &token.vault_id(), ts, &nonce, &request);
                    (actor, token.vault_id(), token.sign_raw(&text))
                }
            };
            let text = signing_input(&actor, &vault_id, ts, &nonce, &request);
            let params = SigParams {
                actor,
                vault_id,
                ts,
                nonce,
                sig: sig.0,
            };
            Outcome::success(json!({
                "signing_input": String::from_utf8(text).map_err(Outcome::runner_error)?,
                "sig": hex(sig.0),
                "header": params.to_header_value(),
            }))
        }
        "header" => match SigParams::parse(i.str("header")?) {
            Ok(p) => {
                let (actor, token) = match p.actor {
                    SigActor::Owner => ("owner", Value::Null),
                    SigActor::Token(id) => ("token", id.to_hex().into()),
                    _ => ("unknown", Value::Null),
                };
                Outcome::success(json!({
                    "actor": actor,
                    "token": token,
                    "vault_id": p.vault_id.to_hex(),
                    "ts": p.ts,
                    "nonce": hex(p.nonce),
                    "sig": hex(p.sig),
                }))
            }
            Err(SigError::Version) => Outcome::failure("unknown_version"),
            Err(_) => Outcome::failure("bad_encoding"),
        },
        "descriptor" => {
            let owner = node(i, "owner_node_key")?.owner();
            let d = Descriptor::decode(&i.hex("descriptor")?).map_err(Outcome::runner_error)?;
            signed(d.signing_input(), owner.sign_descriptor(&d).sig)
        }
        "bundle" => {
            let owner = node(i, "owner_node_key")?.owner();
            let (token, scope, generation) = (
                TokenId(i.arr("token_id")?),
                i.u8("scope_code")?,
                i.u32("generation")?,
            );
            let sealed = i.hex("sealed")?;
            signed(
                galata_vault_proto::api::bundle_signing_input(
                    &owner.vault_id(),
                    &token,
                    scope,
                    generation,
                    &sealed,
                ),
                owner.sign_bundle(&token, scope, generation, &sealed),
            )
        }
        "children" => {
            let owner = node(i, "owner_node_key")?.owner();
            let input = children_signing_input(&owner.vault_id(), i.u64("version")?, &i.hex("ct")?);
            let sig = owner.sign(&input);
            signed(input, sig)
        }
        "report" => {
            let token = TokenKeys::from_parts(
                TokenId(i.arr("token_id")?),
                VaultId(i.arr("vault_id")?),
                Zeroizing::new(i.arr("token_secret")?),
            );
            let ts = i.i64("ts")?;
            signed(report_signing_input(&token.id(), ts), token.sign_report(ts))
        }
        "verify" => match verify_ed25519(
            &Key32(i.arr("public_key")?),
            &i.hex("message")?,
            &Sig64(i.arr("sig")?),
            "vector",
        ) {
            Ok(()) => Outcome::success(json!({})),
            Err(e) => Outcome::failure(integrity_failure(&e)),
        },
        _ => return Err(unknown_op("signatures", op)),
    })
}

fn canonical(record: &ChildrenRecord) -> Step<Outcome> {
    let bytes = record.to_bytes().map_err(Outcome::runner_error)?;
    let text = String::from_utf8(bytes).map_err(Outcome::runner_error)?;
    Ok(Outcome::success(json!({ "plaintext": text })))
}

fn children(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    match op {
        "encode" => {
            let doc = json!({ "v": galata_vault_proto::children::CHILDREN_RECORD_VERSION, "children": i.get("children")? });
            let bytes = serde_json::to_vec(&doc).map_err(Outcome::runner_error)?;
            let record = ChildrenRecord::parse(&bytes).map_err(Outcome::runner_error)?;
            canonical(&record)
        }
        "parse" => match ChildrenRecord::parse(i.str("plaintext")?.as_bytes()) {
            Ok(record) => canonical(&record),
            Err(e) => Ok(Outcome::failure(children_failure(&e))),
        },
        "sign" => {
            let owner = node(i, "owner_node_key")?.owner();
            let input = children_signing_input(&owner.vault_id(), i.u64("version")?, &i.hex("ct")?);
            let sig = owner.sign(&input);
            Ok(signed(input, sig))
        }
        "open" => {
            let owner = node(i, "owner_node_key")?.owner();
            let blob =
                ChildrenBlob::new(i.u64("version")?, B64(i.hex("ct")?), Sig64(i.arr("sig")?));
            match owner.open_children(&blob) {
                Ok(record) => canonical(&record),
                Err(e) => Ok(Outcome::failure(key_failure(&e))),
            }
        }
        _ => Err(unknown_op("children", op)),
    }
}
