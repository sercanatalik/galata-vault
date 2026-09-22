//! The test-vector runner the Python wheel exposes as
//! `galata_vault._vectors` (feature `vectors`, `docs/spec/README.md#5`).
//!
//! **Private and unsupported.** It runs one vector case with exactly the
//! Rust code this library uses, so the wheel that ships is the build that is
//! tested. Pure: inputs in, what this
//! build observed out. It keeps no key between calls and does no I/O.

use crate::proto::vectors::{Inputs, Outcome, Step, format_failure, unknown_op};
use serde_json::{Value, json};

use crate::owner::kit::{Kit, KitFault};

/// Every construct the vectors cover, and so this runner.
pub const CONSTRUCTS: [&str; 13] = [
    "strings",
    "paths",
    "keys",
    "names",
    "descriptors",
    "bundles",
    "envelopes",
    "records",
    "children",
    "kits",
    "signatures",
    "audit",
    "pow",
];

/// Run one case (`{"op", "inputs", …}`) of `construct`, returning
/// `{"result": "success" | <failure name>, "outputs": …}`.
pub fn run(construct: &str, case: &Value) -> Value {
    let op = case.get("op").and_then(Value::as_str).unwrap_or("");
    let inputs = case.get("inputs").unwrap_or(&Value::Null);
    run_op(construct, op, inputs).to_json()
}

/// Run one operation of `construct` on `inputs`.
pub fn run_op(construct: &str, op: &str, inputs: &Value) -> Outcome {
    if crate::proto::vectors::CONSTRUCTS.contains(&construct) {
        crate::proto::vectors::run(construct, op, inputs)
    } else if crate::keys::vectors::CONSTRUCTS.contains(&construct) {
        crate::keys::vectors::run(construct, op, inputs)
    } else if crate::seal::vectors::CONSTRUCTS.contains(&construct) {
        crate::seal::vectors::run(construct, op, inputs)
    } else if construct == "kits" {
        kits(op, Inputs(inputs)).unwrap_or_else(|o| o)
    } else {
        Outcome::runner_error(format!("no construct {construct:?}"))
    }
}

fn kits(op: &str, i: Inputs<'_>) -> Step<Outcome> {
    if op != "parse" {
        return Err(unknown_op("kits", op));
    }
    Ok(match Kit::check(i.str("text")?) {
        Ok(kit) => {
            let key = kit.key().map_err(Outcome::runner_error)?;
            let bytes = crate::proto::codec::decode_node_key(&key.encode())
                .map_err(Outcome::runner_error)?;
            Outcome::success(json!({
                "kind": match kit.kind() {
                    crate::owner::KitKind::Recovery => "recovery",
                    crate::owner::KitKind::Delegation => "delegation",
                },
                "path": kit.path().to_string(),
                "server": kit.server(),
                "key": crate::proto::vectors::hex(*bytes),
            }))
        }
        Err(fault) => Outcome::failure(match fault {
            KitFault::Syntax => "bad_encoding",
            KitFault::Version(_) => "unknown_version",
            KitFault::Server(_) => "bad_server",
            KitFault::Key(e) => format_failure(&e),
            KitFault::NotAProject(_) => "kind_mismatch",
        }),
    })
}
