//! The record envelope vectors (`testdata/vectors/v1/envelopes.json`,
//! `docs/spec/records.md#3`): plaintext encodings both ways, and age v1
//! ciphertexts produced by the independent Python age implementation
//! (checked against C2SP CCTV) that this crate, through the `age` crate,
//! must open, or refuse with the named failure.

use std::path::PathBuf;

use galata_vault::proto::vectors::check_file;
use galata_vault::seal::vectors::run;

#[test]
fn envelopes() {
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/v1/envelopes.json");
    let n = check_file(&path, run).unwrap_or_else(|e| panic!("{e}"));
    assert!(n > 0);
}
