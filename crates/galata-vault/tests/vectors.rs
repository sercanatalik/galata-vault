//! The kit vectors this crate owns, and every vector file through the
//! runner the Python wheel exposes (`galata_vault::__vectors`), so the
//! wheel's dispatch is checked here too (`docs/spec/README.md#5`).

use std::path::PathBuf;

use galata_vault::__vectors::{CONSTRUCTS, run_op};
use galata_vault::proto::vectors::check_file;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../testdata/vectors/v1")
}

#[test]
fn kits() {
    let n = check_file(&dir().join("kits.json"), run_op).unwrap_or_else(|e| panic!("{e}"));
    assert!(n > 0);
}

#[test]
fn every_vector_file_through_the_wheels_runner() {
    let mut files: Vec<String> = std::fs::read_dir(dir())
        .unwrap()
        .map(|e| {
            e.unwrap()
                .path()
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    files.sort();
    let mut constructs = CONSTRUCTS.map(str::to_owned).to_vec();
    constructs.sort();
    assert_eq!(
        files, constructs,
        "one file per construct, and a runner for each"
    );
    for construct in CONSTRUCTS {
        check_file(&dir().join(format!("{construct}.json")), run_op)
            .unwrap_or_else(|e| panic!("{e}"));
    }
}
