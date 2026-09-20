//! Shared test harness: the real `gv` binary for one machine's home and
//! working directory.
//!
//! Every run asserts that neither stdout nor stderr carried a `gvk1_` key
//! (the CLI test suites prove no key reaches a child process). The
//! assertion lives in this one driver, which every suite that
//! drives `gv` against a vault uses, so a suite cannot run the binary
//! without it. Three copies of this function, only one of which made the
//! assertion, are why it is here.

#![allow(dead_code)]

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

/// Run the real `gv` for one machine's home and working directory.
pub fn gv(home: &Path, work: &Path, args: &[&str], stdin: &[u8], envs: &[(&str, &str)]) -> Output {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_gv"));
    cmd.args(args)
        .env_clear()
        .env("PATH", std::env::var_os("PATH").unwrap())
        .env("GV_HOME", home)
        .env("GV_CREDENTIAL_STORE", "file")
        .current_dir(work)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let mut child = cmd.spawn().unwrap();
    let _ = child.stdin.take().unwrap().write_all(stdin);
    let out = child.wait_with_output().unwrap();
    for stream in [&out.stdout, &out.stderr] {
        let text = String::from_utf8_lossy(stream);
        assert!(
            !text.contains("gvk1_"),
            "gv {args:?} printed a key:\n{text}"
        );
    }
    out
}
