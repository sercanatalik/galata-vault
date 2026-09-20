//! `gv-conformance`: check a galata-vault protocol server against the
//! specification (`docs/spec/README.md#6`).
//!
//! ```text
//! gv-conformance --server http://127.0.0.1:8750
//! gv-conformance --server https://vault.example --allow-remote
//! gv-conformance --embedded ./data-dir
//! gv-conformance --list
//! ```
//!
//! Prints one line per case (id, anchor, pass, FAIL or skip, and why) and a
//! summary. Exits 1 if any case fails, 2 on a usage error or a refused
//! target.

use std::process::ExitCode;

use gv_conformance::{Target, cases, is_loopback, run};

const USAGE: &str = "usage: gv-conformance (--server <url> [--allow-remote] | --embedded <dir>) [--only C01,C02,…] | --list";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut server = None;
    let mut embedded = None;
    let mut allow_remote = false;
    let mut only: Option<Vec<String>> = None;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--server" => server = it.next().cloned(),
            "--embedded" => embedded = it.next().cloned(),
            "--allow-remote" => allow_remote = true,
            "--only" => only = it.next().map(|s| s.split(',').map(str::to_owned).collect()),
            "--list" => {
                for c in cases() {
                    println!("{}  {:<16} {}", c.id, c.anchor, c.title);
                }
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("{USAGE}");
                return ExitCode::from(2);
            }
        }
    }
    let target = match (server, embedded) {
        (Some(url), None) => {
            if !is_loopback(&url) && !allow_remote {
                eprintln!(
                    "gv-conformance: refusing to run against {url}: it is not this machine, and the \
                     suite creates vaults, consumes quota and solves proof of work there. Nothing was \
                     sent. Pass --allow-remote to run it anyway."
                );
                return ExitCode::from(2);
            }
            Target::http(&url)
        }
        (None, Some(dir)) => Target::embedded(std::path::Path::new(&dir)),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let target = match target {
        Ok(t) => t,
        Err(e) => {
            eprintln!("gv-conformance: {e}");
            return ExitCode::from(2);
        }
    };
    let only: Option<Vec<&str>> = only
        .as_ref()
        .map(|o| o.iter().map(String::as_str).collect());
    let report = run(&target, only.as_deref());
    for line in report.lines() {
        println!("{line}");
    }
    if report.failed() > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
