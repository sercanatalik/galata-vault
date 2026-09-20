//! The test-vector runner (feature `vectors`, `docs/spec/README.md#5`).
//!
//! A vector case names a construct, an operation and its inputs. A runner
//! computes the outputs with this workspace's own code, or names the failure
//! it met, from the registry in `docs/spec/README.md#4`. Each crate runs the
//! constructs it owns (this one: strings, paths, audit, proof of work), and
//! `galata_vault::__vectors` dispatches every construct for the Python wheel.
//!
//! Pure: nothing is kept between calls, and nothing is read or written
//! except by [`check_file`], which the tests use to read a vector file. Not a
//! supported interface: it exists so that every implementation this
//! workspace ships runs the same vectors.

use std::collections::BTreeSet;
use std::path::Path;

use serde_json::{Value, json};

use crate::FormatError;
use crate::api::AuditPage;
use crate::audit::{AuditRow, ChainError, ChainHead, RowStop, verify_rows};
use crate::codec::{self, TokenString};
use crate::descriptor::{MALFORMED_LENGTH, MALFORMED_VERSION};
use crate::ids::{TokenId, VaultId};
use crate::integrity::IntegrityError;
use crate::path::EnvPath;
use crate::pow::{self, Challenge, PowError};

/// What an implementation observed for one case: `success` or a failure
/// name, and the outputs (on a failure, a partial result or null).
#[derive(Debug, Clone, PartialEq)]
pub struct Outcome {
    pub result: String,
    pub outputs: Value,
}

impl Outcome {
    pub fn success(outputs: Value) -> Outcome {
        Outcome {
            result: "success".to_owned(),
            outputs,
        }
    }

    pub fn failure(name: &str) -> Outcome {
        Outcome {
            result: name.to_owned(),
            outputs: Value::Null,
        }
    }

    /// A failure that still reports something (a verified prefix).
    pub fn partial(name: &str, outputs: Value) -> Outcome {
        Outcome {
            result: name.to_owned(),
            outputs,
        }
    }

    /// The case could not be run (a missing input, an unknown operation):
    /// never a failure name, so it never passes.
    pub fn runner_error(e: impl std::fmt::Display) -> Outcome {
        Outcome::failure(&format!("runner error: {e}"))
    }

    /// `{"result": …, "outputs": …}`.
    pub fn to_json(&self) -> Value {
        json!({ "result": self.result, "outputs": self.outputs })
    }
}

/// A step that can end the case early with an outcome.
pub type Step<T> = Result<T, Outcome>;

/// A case's inputs.
#[derive(Debug, Clone, Copy)]
pub struct Inputs<'a>(pub &'a Value);

impl<'a> Inputs<'a> {
    pub fn get(&self, key: &str) -> Step<&'a Value> {
        self.0
            .get(key)
            .ok_or_else(|| Outcome::runner_error(format!("input {key:?} is missing")))
    }

    pub fn str(&self, key: &str) -> Step<&'a str> {
        self.get(key)?
            .as_str()
            .ok_or_else(|| Outcome::runner_error(format!("input {key:?} is not a string")))
    }

    /// A string, or `None` for null or absent.
    pub fn opt_str(&self, key: &str) -> Step<Option<&'a str>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(_) => self.str(key).map(Some),
        }
    }

    pub fn hex(&self, key: &str) -> Step<Vec<u8>> {
        hex::decode(self.str(key)?)
            .map_err(|e| Outcome::runner_error(format!("input {key:?} is not hex: {e}")))
    }

    pub fn opt_hex(&self, key: &str) -> Step<Option<Vec<u8>>> {
        match self.0.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(_) => self.hex(key).map(Some),
        }
    }

    pub fn arr<const N: usize>(&self, key: &str) -> Step<[u8; N]> {
        self.hex(key)?
            .try_into()
            .map_err(|_| Outcome::runner_error(format!("input {key:?} is not {N} bytes")))
    }

    pub fn u64(&self, key: &str) -> Step<u64> {
        self.get(key)?
            .as_u64()
            .ok_or_else(|| Outcome::runner_error(format!("input {key:?} is not a u64")))
    }

    pub fn i64(&self, key: &str) -> Step<i64> {
        self.get(key)?
            .as_i64()
            .ok_or_else(|| Outcome::runner_error(format!("input {key:?} is not an i64")))
    }

    pub fn u32(&self, key: &str) -> Step<u32> {
        u32::try_from(self.u64(key)?)
            .map_err(|_| Outcome::runner_error(format!("input {key:?} is not a u32")))
    }

    pub fn u8(&self, key: &str) -> Step<u8> {
        u8::try_from(self.u64(key)?)
            .map_err(|_| Outcome::runner_error(format!("input {key:?} is not a u8")))
    }
}

/// Lowercase hex.
pub fn hex(bytes: impl AsRef<[u8]>) -> String {
    hex::encode(bytes)
}

/// The failure name of a string or encoding error.
pub fn format_failure(e: &FormatError) -> &'static str {
    match e {
        FormatError::UnknownVersion { .. } => "unknown_version",
        FormatError::WrongPrefix { .. } => "kind_mismatch",
        FormatError::WrongLength { expected, got } if got < expected => "truncated",
        FormatError::WrongLength { .. } => "bad_length",
        FormatError::Checksum => "checksum_mismatch",
        _ => "bad_encoding",
    }
}

/// The failure name of an integrity error.
pub fn integrity_failure(e: &IntegrityError) -> &'static str {
    match e {
        IntegrityError::BadSignature(_) => "bad_signature",
        IntegrityError::KeyMismatch("descriptor's vault id")
        | IntegrityError::BindingMismatch("descriptor's vault id") => "vault_mismatch",
        IntegrityError::KeyMismatch(_) => "key_mismatch",
        IntegrityError::BindingMismatch("descriptor's generation") => "generation_mismatch",
        IntegrityError::BindingMismatch("previous descriptor hash") => "chain_break",
        IntegrityError::Malformed(MALFORMED_VERSION) => "unknown_version",
        IntegrityError::Malformed(MALFORMED_LENGTH) => "bad_length",
        IntegrityError::Malformed(_) => "bad_encoding",
        IntegrityError::VersionRollback { .. } | IntegrityError::GenerationRollback { .. } => {
            "rollback"
        }
        _ => "unmapped integrity error",
    }
}

/// The failure name of an audit-chain error.
pub fn chain_failure(e: &ChainError) -> &'static str {
    match e {
        ChainError::Gap { .. }
        | ChainError::BrokenLink { .. }
        | ChainError::BadHash { .. }
        | ChainError::HeadMismatch => "chain_break",
        ChainError::Rollback { .. } => "rollback",
        ChainError::Fork { .. } => "fork",
        ChainError::UnknownFormat { .. } => "unverifiable_newer_format",
        ChainError::UnknownValue { .. } => "unknown_value",
    }
}

/// The spec files a case may cite.
const SPEC_FILES: [&str; 10] = [
    "README.md",
    "formats.md",
    "keys.md",
    "records.md",
    "signatures.md",
    "protocol.md",
    "http-api.md",
    "audit.md",
    "hosted.md",
    "stability.md",
];

fn anchor_ok(anchor: &str) -> bool {
    let Some((file, section)) = anchor.split_once('#') else {
        return false;
    };
    SPEC_FILES.contains(&file)
        && !section.is_empty()
        && section
            .split('.')
            .all(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Check one vector file, its envelope and every case, against `run`.
/// Returns how many cases ran, or every disagreement.
pub fn check_file(
    path: &Path,
    run: impl Fn(&str, &str, &Value) -> Outcome,
) -> Result<usize, String> {
    let text =
        std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let doc: Value =
        serde_json::from_str(&text).map_err(|e| format!("{} is not JSON: {e}", path.display()))?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .ok_or("a vector file has no name")?;
    let mut problems = Vec::new();
    if doc["suite"] != "galata-vault test vectors" {
        problems.push("the suite is not \"galata-vault test vectors\"".to_owned());
    }
    if doc["protocol"] != 2 {
        problems.push("the protocol is not 2".to_owned());
    }
    if doc["construct"] != stem {
        problems.push(format!("the construct is not {stem:?}, the file's name"));
    }
    if !doc["spec"].as_str().is_some_and(anchor_ok) || !doc["generator"].is_string() {
        problems.push("the file's spec anchor or generator is missing".to_owned());
    }
    let cases = doc["cases"]
        .as_array()
        .filter(|c| !c.is_empty())
        .ok_or("the file has no cases")?;
    let mut ids = BTreeSet::new();
    for case in cases {
        let id = case["id"].as_str().unwrap_or("?");
        let description = case["description"].as_str().unwrap_or("");
        if !ids.insert(id) || !id.starts_with(&format!("{stem}-")) {
            problems.push(format!("{id}: a duplicate or misnamed case id"));
        }
        let (Some(op), Some(expect)) = (case["op"].as_str(), case["expect"].as_str()) else {
            problems.push(format!("{id}: no op or expect"));
            continue;
        };
        if description.is_empty()
            || !case["spec"].as_str().is_some_and(anchor_ok)
            || !case["inputs"].is_object()
        {
            problems.push(format!("{id}: no description, spec anchor or inputs"));
        }
        if expect == "success" && case.get("outputs").is_none() {
            problems.push(format!("{id}: a success case with no outputs"));
        }
        let got = run(stem, op, &case["inputs"]);
        if got.result != expect {
            problems.push(format!(
                "{id} ({description}): expected {expect}, got {}",
                got.result
            ));
        } else if let Some(want) = case.get("outputs")
            && &got.outputs != want
        {
            problems.push(format!(
                "{id} ({description}): outputs differ\n  expected {want}\n  got      {}",
                got.outputs
            ));
        }
    }
    if problems.is_empty() {
        Ok(cases.len())
    } else {
        Err(format!("{}:\n{}", path.display(), problems.join("\n")))
    }
}

/// The constructs this crate runs.
pub const CONSTRUCTS: [&str; 4] = ["strings", "paths", "audit", "pow"];

/// Run one case of a construct this crate owns.
pub fn run(construct: &str, op: &str, inputs: &Value) -> Outcome {
    let i = Inputs(inputs);
    let step = match construct {
        "strings" => strings(op, i),
        "paths" => paths(op, i),
        "audit" => audit(op, i),
        "pow" => proof_of_work(op, i),
        other => Err(Outcome::runner_error(format!(
            "galata-vault-proto does not run {other}"
        ))),
    };
    step.unwrap_or_else(|o| o)
}

/// An operation the construct does not have.
pub fn unknown_op(construct: &str, op: &str) -> Outcome {
    Outcome::runner_error(format!("{construct} has no operation {op:?}"))
}

fn strings(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "base62" => Outcome::success(json!({ "string": codec::encode_fixed(&i.hex("bytes")?) })),
        "base62_decode" => {
            let n = usize::try_from(i.u64("length")?).map_err(Outcome::runner_error)?;
            match codec::decode_fixed(i.str("string")?, n) {
                Ok(bytes) => Outcome::success(json!({ "bytes": hex(&*bytes) })),
                Err(e) => Outcome::failure(format_failure(&e)),
            }
        }
        "checksum" => Outcome::success(
            json!({ "checksum": codec::checksum(i.str("prefix")?, i.str("body")?) }),
        ),
        "encode_key" => {
            let s = codec::encode_node_key(&i.arr("key")?);
            Outcome::success(json!({ "string": s.as_str() }))
        }
        "decode_key" => match codec::decode_node_key(i.str("string")?) {
            Ok(key) => Outcome::success(json!({ "key": hex(*key) })),
            Err(e) => Outcome::failure(format_failure(&e)),
        },
        "encode_token" => {
            let s = TokenString::encode(
                &TokenId(i.arr("token_id")?),
                &VaultId(i.arr("vault_id")?),
                &i.arr("secret")?,
            );
            Outcome::success(json!({ "string": s.as_str() }))
        }
        "decode_token" => match TokenString::parse(i.str("string")?) {
            Ok(t) => Outcome::success(json!({
                "token_id": t.id.to_hex(),
                "vault_id": t.vault_id.to_hex(),
                "secret": hex(*t.secret),
            })),
            Err(e) => Outcome::failure(format_failure(&e)),
        },
        _ => return Err(unknown_op("strings", op)),
    })
}

fn paths(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    if op != "parse" {
        return Err(unknown_op("paths", op));
    }
    Ok(match EnvPath::parse(i.str("path")?) {
        Ok(p) => Outcome::success(json!({
            "segments": p.segments().iter().map(|s| s.as_str()).collect::<Vec<_>>(),
            "depth": p.depth(),
            "project": p.project_name().as_str(),
        })),
        Err(_) => Outcome::failure("bad_path"),
    })
}

fn head_json(head: Option<ChainHead>) -> Value {
    head.map_or(
        Value::Null,
        |h| json!({ "seq": h.seq, "hash": h.hash.to_hex() }),
    )
}

fn audit(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "row_hash" => {
            let Ok(row) = serde_json::from_value::<AuditRow>(i.get("row")?.clone()) else {
                return Ok(Outcome::failure("bad_encoding"));
            };
            match (row.hash_input(), row.expected_hash()) {
                (Some(input), Some(hash)) => Outcome::success(json!({
                    "encoding": hex(input),
                    "hash": hash.to_hex(),
                })),
                _ => Outcome::failure("unverifiable_newer_format"),
            }
        }
        "verify" => {
            let known: Option<ChainHead> =
                serde_json::from_value(i.get("known")?.clone()).map_err(Outcome::runner_error)?;
            let Ok(page) = serde_json::from_value::<AuditPage>(i.get("page")?.clone()) else {
                return Ok(Outcome::failure("bad_encoding"));
            };
            match verify_rows(
                known.as_ref(),
                &page.rows,
                page.head.as_ref(),
                page.stop.as_ref(),
            ) {
                Ok(v) => {
                    let from = match &v.unverifiable {
                        Some(RowStop::NewerFormat { seq, .. }) => json!(seq),
                        _ => Value::Null,
                    };
                    let outputs = json!({
                        "head": head_json(v.head),
                        "verified": v.rows,
                        "unverifiable_from": from,
                    });
                    if v.unverifiable.is_some() {
                        Outcome::partial("unverifiable_newer_format", outputs)
                    } else {
                        Outcome::success(outputs)
                    }
                }
                Err(e) => Outcome::failure(chain_failure(&e)),
            }
        }
        _ => return Err(unknown_op("audit", op)),
    })
}

fn proof_of_work(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    Ok(match op {
        "hash" => {
            let h = pow::pow_hash(i.str("challenge")?, i.u64("nonce")?);
            Outcome::success(json!({ "hash": hex(h), "zero_bits": pow::leading_zero_bits(&h) }))
        }
        "verify" => {
            if pow::verify(i.str("challenge")?, i.u8("difficulty")?, i.u64("nonce")?) {
                Outcome::success(json!({}))
            } else {
                Outcome::failure("bad_proof")
            }
        }
        "issue" => {
            let c = Challenge {
                id: i.arr("id")?,
                expires_at: i.i64("expires_at")?,
                difficulty: i.u8("difficulty")?,
            };
            Outcome::success(json!({ "challenge": c.issue(&i.arr("server_key")?) }))
        }
        "open" => {
            match Challenge::open(i.str("challenge")?, &i.arr("server_key")?, i.i64("now")?) {
                Ok(c) => Outcome::success(json!({
                    "id": hex(c.id),
                    "expires_at": c.expires_at,
                    "difficulty": c.difficulty,
                })),
                Err(PowError::Tampered) => Outcome::failure("bad_signature"),
                Err(PowError::Expired) => Outcome::failure("expired"),
                Err(_) => Outcome::failure("bad_encoding"),
            }
        }
        _ => return Err(unknown_op("pow", op)),
    })
}
