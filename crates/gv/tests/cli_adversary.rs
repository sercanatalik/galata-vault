//! The real `gv` binary against a malicious server: a real gv-server behind
//! `gv-adversary`, a proxy
//! that logs, replays, rewrites and serves stale answers.
//!
//! Each test is one attack, run the way a user runs `gv`: a temporary
//! GV_HOME, the file credential store, a cleared environment. Every attack
//! must end in a refusal that names what failed (and never the value), or
//! the server's own 401.

use std::process::Output;

use galata_vault::keys::{NodeKey, TokenKeys};
use galata_vault::proto::ids::B64;
use gv_adversary::{Adversary, Matcher};

#[path = "cli_common/mod.rs"]
mod common;

/// One user's machine: a home directory and a working directory.
struct Machine {
    home: tempfile::TempDir,
    work: tempfile::TempDir,
    server: String,
}

impl Machine {
    fn new(adv: &Adversary) -> Machine {
        Machine {
            home: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
            server: adv.url().to_owned(),
        }
    }

    fn run(&self, args: &[&str], stdin: &[u8], envs: &[(&str, &str)]) -> Output {
        common::gv(self.home.path(), self.work.path(), args, stdin, envs)
    }

    fn ok(&self, args: &[&str], stdin: &[u8]) -> String {
        let out = self.run(args, stdin, &[]);
        assert!(
            out.status.success(),
            "gv {args:?} failed:\n{}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8(out.stdout).unwrap()
    }

    /// Run, expect failure, return stderr.
    fn fail(&self, args: &[&str], envs: &[(&str, &str)]) -> String {
        let out = self.run(args, b"", envs);
        assert!(
            !out.status.success(),
            "gv {args:?} should have failed:\n{}",
            String::from_utf8_lossy(&out.stdout)
        );
        String::from_utf8(out.stderr).unwrap()
    }

    fn get(&self, name: &str) -> String {
        self.ok(&["get", name, "--env", "acme/dev"], b"")
    }

    fn set(&self, name: &str, value: &str) {
        self.ok(&["set", name, "--env", "acme/dev"], value.as_bytes());
    }

    fn mint(&self, scope: &str) -> String {
        self.ok(
            &["token", "mint", "--scope", scope, "--env", "acme/dev"],
            b"",
        )
        .trim()
        .to_owned()
    }

    /// The key this machine holds for the project.
    fn project_key(&self) -> String {
        let text = std::fs::read_to_string(self.home.path().join("credentials.toml")).unwrap();
        let table: toml::Table = toml::from_str(&text).unwrap();
        table["credentials"]["node:acme"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

/// A malicious server, and a project `acme` with `acme/dev` holding one
/// secret.
fn project() -> (Adversary, Machine) {
    let adv = Adversary::start();
    let m = Machine::new(&adv);
    m.ok(&["init", "acme", "--server", &m.server], b"saved\n");
    m.ok(&["env", "add", "acme/dev"], b"");
    m.set("API_KEY", "super-secret-value");
    (adv, m)
}

/// A refusal names the environment and what failed, and never the value.
#[track_caller]
fn refused(err: &str, reason: &str) {
    assert!(err.contains("acme") && err.contains(reason), "{err}");
    assert!(!err.contains("super-secret-value"), "{err}");
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

/// Any record the server serves, signature changed: `gv get` refuses it,
/// naming the record's version and kind only.
#[test]
fn a_record_with_a_forged_signature_is_refused() {
    let (adv, m) = project();
    adv.rewrite(Matcher::prefix("GET", "/v1/secrets/"), |v| {
        if let Some(sig) = v.get_mut("sig") {
            *sig = serde_json::to_value(B64(vec![7; 64])).unwrap();
        }
    });
    let err = m.fail(&["get", "API_KEY", "--env", "acme/dev"], &[]);
    refused(&err, "does not verify");
    assert!(
        err.contains("version 1 of secret") && !err.contains("API_KEY"),
        "{err}"
    );
    let err = m.fail(&["run", "--env", "acme/dev", "--", "touch", "ran"], &[]);
    refused(&err, "does not verify");
    assert!(!m.work.path().join("ran").exists(), "the command never ran");
}

/// A genuine older version, served after `gv` saw a newer one: the pins in
/// state.toml carry across runs.
#[test]
fn a_rolled_back_version_is_refused_across_runs() {
    let (adv, m) = project();
    let latest = Matcher::prefix("GET", "/v1/secrets/");
    adv.record(latest.clone());
    assert_eq!(m.get("API_KEY"), "super-secret-value");
    m.set("API_KEY", "rotated-value");
    assert_eq!(m.get("API_KEY"), "rotated-value");

    adv.serve_recorded(latest);
    let err = m.fail(&["get", "API_KEY", "--env", "acme/dev"], &[]);
    refused(&err, "version rollback");
    assert!(!err.contains("rotated-value"), "{err}");
}

/// A descriptor whose vault key was swapped, and a vault claimed by another
/// owner key: refused before anything is sealed to them.
#[test]
fn a_substituted_key_or_owner_is_refused() {
    let (adv, m) = project();
    adv.rewrite(Matcher::get("/v1/vault"), |v| {
        let mut d: B64 = serde_json::from_value(v["descriptor"]["descriptor"].clone()).unwrap();
        d.0[21] ^= 0x5a;
        v["descriptor"]["descriptor"] = serde_json::to_value(d).unwrap();
    });
    refused(
        &m.fail(&["get", "API_KEY", "--env", "acme/dev"], &[]),
        "does not verify",
    );
    // Nothing is sealed to a key the owner did not sign.
    adv.clear_log();
    let out = m.run(&["set", "NEW", "--env", "acme/dev"], b"sealed-to-whom", &[]);
    assert!(!out.status.success());
    refused(&String::from_utf8_lossy(&out.stderr), "does not verify");
    assert!(
        !adv.log().iter().any(|l| l.method == "PUT"),
        "no write reached the server"
    );
    adv.clear_rules();

    let theirs = serde_json::to_value(NodeKey::generate().owner().sign_pub()).unwrap();
    adv.rewrite(Matcher::get("/v1/vault"), move |v| {
        v["owner_sign_pub"] = theirs.clone();
    });
    refused(
        &m.fail(&["get", "API_KEY", "--env", "acme/dev"], &[]),
        "does not match the pinned vault",
    );
    adv.clear_rules();
    assert_eq!(m.get("API_KEY"), "super-secret-value");
}

/// Token mode (`GV_TOKEN`, no configuration): another token's genuine
/// bundle, or a forged descriptor, is refused and the command never runs.
#[test]
fn token_mode_refuses_a_moved_bundle_or_forged_descriptor() {
    let (adv, m) = project();
    let (a, b) = (m.mint("read"), m.mint("read"));
    let ci = Machine::new(&adv);
    let env_of = |t: &str| {
        [
            ("GV_TOKEN", t.to_owned()),
            ("GV_SERVER", adv.url().to_owned()),
        ]
    };
    let run = |t: &str, args: &[&str]| {
        let e = env_of(t);
        let e: Vec<(&str, &str)> = e.iter().map(|(k, v)| (*k, v.as_str())).collect();
        ci.run(args, b"", &e)
    };

    let a_self = Matcher::get("/v1/tokens/self").by(TokenKeys::parse(&a).unwrap().id());
    adv.record(a_self.clone());
    let out = run(&a, &["get", "API_KEY"]);
    assert_eq!(String::from_utf8_lossy(&out.stdout), "super-secret-value");
    let (_, body) = adv.recorded(&a_self).unwrap();
    let a_bundle = serde_json::from_slice::<serde_json::Value>(&body).unwrap()["bundle"].clone();

    let b_id = TokenKeys::parse(&b).unwrap().id();
    adv.rewrite(Matcher::get("/v1/tokens/self").by(b_id), move |v| {
        v["bundle"] = a_bundle.clone();
    });
    let out = run(&b, &["run", "--", "touch", "ran"]);
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("does not verify"), "{err}");
    assert!(
        !ci.work.path().join("ran").exists(),
        "the command never ran"
    );
    adv.clear_rules();

    adv.rewrite(Matcher::get("/v1/tokens/self"), |v| {
        let mut d: B64 = serde_json::from_value(v["descriptor"]["descriptor"].clone()).unwrap();
        d.0[53] ^= 0x5a;
        v["descriptor"]["descriptor"] = serde_json::to_value(d).unwrap();
    });
    let out = run(&b, &["get", "API_KEY"]);
    assert!(!out.status.success());
    // Token mode knows no path: the error names the token's vault.
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("integrity check failed")
            && err.contains("descriptor signature does not verify"),
        "{err}"
    );
    assert!(
        !err.contains("super-secret-value") && !err.contains(&b[5..]),
        "{err}"
    );
}

/// A logged `gv set`, sent again, is refused: its signature was spent. The
/// secret keeps the one version that was written.
#[test]
fn a_replayed_write_is_refused() {
    let (adv, m) = project();
    adv.clear_log();
    m.set("API_KEY", "second");
    let put = adv
        .log()
        .into_iter()
        .find(|l| l.method == "PUT" && l.path.starts_with("/v1/secrets/"))
        .expect("the write was logged");
    let (status, body) = adv.replay(&put);
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("unauthorized"))
    );
    let history = m.ok(&["history", "API_KEY", "--env", "acme/dev"], b"");
    assert_eq!(
        history.lines().filter(|l| !l.trim().is_empty()).count(),
        2,
        "{history}"
    );
    assert_eq!(m.get("API_KEY"), "second");
}

/// Nothing `gv` sends, as the owner or with a token, carries a form of a key
/// or a token secret, or a secret's name or value.
#[test]
fn no_request_carries_a_key_a_token_or_a_value() {
    let (adv, m) = project();
    let token = m.mint("read");
    let ci = Machine::new(&adv);
    let env = [("GV_TOKEN", token.as_str()), ("GV_SERVER", adv.url())];
    let out = ci.run(&["get", "API_KEY"], b"", &env);
    assert!(out.status.success());
    m.ok(&["ls", "--env", "acme/dev"], b"");

    let key = m.project_key();
    let forbidden: [&[u8]; 6] = [
        key.as_bytes(),
        &key.as_bytes()[5..],
        token.as_bytes(),
        &token.as_bytes()[5..],
        b"super-secret-value",
        b"API_KEY",
    ];
    let log = adv.log();
    assert!(log.len() > 10);
    for l in &log {
        let seen = l.bytes();
        for f in forbidden {
            assert!(
                !contains(&seen, f),
                "{} {} carries {}",
                l.method,
                l.path,
                String::from_utf8_lossy(f)
            );
        }
        if let Some(auth) = l.header("authorization") {
            assert!(auth.starts_with("GV-Sig v=1,"), "{auth}");
        }
    }
}
