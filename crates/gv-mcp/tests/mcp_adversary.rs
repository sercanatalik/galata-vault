//! gv-mcp against a malicious server:
//! a real gv-server behind `gv-adversary`, a proxy that logs, replays,
//! rewrites and serves stale answers. The owner's setup goes through the
//! client core (a dev-dependency only: the shipped binary links no
//! value-decryption code).
//!
//! gv-mcp holds names-only meta tokens, so the attacks that apply are on
//! what it verifies: the token's view at startup (descriptor, owner key,
//! bundle), every listed record's signature, the status descriptor, and the
//! generation after a rotation. Each must end in an error naming the path
//! and the failure, and never the token.

use std::os::unix::fs::PermissionsExt;

use galata_vault::keys::{NodeKey, TokenKeys};
use galata_vault::mcp::{McpServer, config, open_all};
use galata_vault::proto::ids::{B64, Sig64};
use galata_vault::proto::mcp::{McpConfig, McpEntry};
use galata_vault::testing::RawVault as Core;
use galata_vault::{Api, ClientBuilder, Scope};
use gv_adversary::{Adversary, Matcher};
use serde_json::Value;

/// A malicious server with one vault (`acme/dev`, two secrets) and its
/// honest owner.
struct World {
    adv: Adversary,
    client: Api,
    owner: Core,
    dir: tempfile::TempDir,
}

fn world() -> World {
    let adv = Adversary::start();
    let client = ClientBuilder::new(adv.url()).build().unwrap();
    let key = NodeKey::generate();
    assert!(Core::create(&client, &key, "acme/dev").unwrap());
    let owner = Core::open_owner(&client, &key, "acme/dev").unwrap();
    let w = World {
        adv,
        client,
        owner,
        dir: tempfile::tempdir().unwrap(),
    };
    w.put("DATABASE_URL", b"postgres://secret");
    w.put("DEBUG", b"1");
    w
}

impl World {
    fn put(&self, name: &str, value: &[u8]) {
        let pre = self.owner.current(name).unwrap();
        self.owner.put(name, value, pre).unwrap();
    }

    fn meta(&self) -> TokenKeys {
        self.owner.mint(Scope::Meta, 0, None).unwrap().0
    }

    /// gv-mcp, configured with `entries`, started through the proxy.
    fn open(&self, entries: &[(&str, &TokenKeys)]) -> anyhow::Result<McpServer> {
        let config = McpConfig {
            env: entries
                .iter()
                .map(|(path, t)| McpEntry {
                    path: path.parse().unwrap(),
                    server: self.adv.url().to_owned(),
                    token: t.token_string().to_string(),
                })
                .collect(),
        };
        let file = self.dir.path().join("mcp.toml");
        std::fs::write(&file, toml::to_string(&config).unwrap()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        open_all(config::load(&file)?).map(McpServer::new)
    }
}

/// Startup must fail; its error, as the binary would print it.
fn refused_at_startup(r: anyhow::Result<McpServer>) -> String {
    match r {
        Ok(_) => panic!("gv-mcp started on a forged view"),
        Err(e) => format!("{e:#}"),
    }
}

/// Change one byte of the signed descriptor (21..53 is its vault key,
/// 53..85 its config key).
fn flip_descriptor(v: &mut Value, at: usize) {
    let mut d: B64 = serde_json::from_value(v["descriptor"]["descriptor"].clone()).unwrap();
    d.0[at] ^= 0x5a;
    v["descriptor"]["descriptor"] = serde_json::to_value(d).unwrap();
}

#[track_caller]
fn names_the_failure(err: &str, token: &TokenKeys, reason: &str) {
    assert!(err.contains("acme/dev") && err.contains(reason), "{err}");
    assert!(!err.contains(token.token_string().as_str()), "{err}");
}

/// A listed record whose signature the writer did not make: list, diff and
/// audit refuse it, and work again once the proxy is honest.
#[test]
fn a_listing_with_a_forged_signature_is_refused() {
    let w = world();
    let meta = w.meta();
    let s = w
        .open(&[("acme/dev", &meta), ("acme/prod", &w.meta())])
        .unwrap();
    w.adv.rewrite(Matcher::get("/v1/secrets"), |v| {
        for item in v["items"].as_array_mut().into_iter().flatten() {
            item["sig"] = serde_json::to_value(Sig64([7; 64])).unwrap();
        }
    });
    for err in [
        s.list_secrets_json("acme/dev").unwrap_err(),
        s.diff_json("acme/dev", "acme/prod").unwrap_err(),
        s.audit_json("acme/dev").unwrap_err(),
    ] {
        names_the_failure(&err, &meta, "integrity check failed on a listed record");
        assert!(err.contains("does not verify"), "{err}");
    }
    w.adv.clear_rules();
    let list = s.list_secrets_json("acme/dev").unwrap();
    assert_eq!(list["count"], 2);
}

/// A descriptor whose vault or config key was swapped: gv-mcp refuses to
/// start on it.
#[test]
fn a_substituted_descriptor_key_is_refused_at_startup() {
    let w = world();
    let meta = w.meta();
    for at in [21, 53] {
        w.adv.rewrite(Matcher::get("/v1/tokens/self"), move |v| {
            flip_descriptor(v, at)
        });
        let err = refused_at_startup(w.open(&[("acme/dev", &meta)]));
        names_the_failure(&err, &meta, "integrity check failed");
        assert!(
            err.contains("does not verify") && err.contains(&meta.id().to_hex()),
            "{err}"
        );
        w.adv.clear_rules();
    }
    assert!(w.open(&[("acme/dev", &meta)]).is_ok());
}

/// Another vault's genuine, owner-signed view, served for this token: its
/// owner key does not hash to the vault id the token carries.
#[test]
fn a_swapped_owner_key_is_refused_at_startup() {
    let w = world();
    let meta = w.meta();
    let key = NodeKey::generate();
    assert!(Core::create(&w.client, &key, "other/dev").unwrap());
    let other = Core::open_owner(&w.client, &key, "other/dev").unwrap();
    let theirs = other.mint(Scope::Meta, 0, None).unwrap().0;
    let their_self = Matcher::get("/v1/tokens/self").by(theirs.id());
    w.adv.record(their_self.clone());
    w.open(&[("other/dev", &theirs)]).unwrap();
    let (_, body) = w.adv.recorded(&their_self).unwrap();
    let genuine: Value = serde_json::from_slice(&body).unwrap();

    w.adv
        .rewrite(Matcher::get("/v1/tokens/self").by(meta.id()), move |v| {
            v["owner_sign_pub"] = genuine["owner_sign_pub"].clone();
            v["descriptor"] = genuine["descriptor"].clone();
        });
    let err = refused_at_startup(w.open(&[("acme/dev", &meta)]));
    names_the_failure(&err, &meta, "does not match the pinned vault");
}

/// Another meta token's genuine bundle: the owner's signature binds the
/// token id, so it does not verify for this one.
#[test]
fn a_bundle_moved_between_tokens_is_refused_at_startup() {
    let w = world();
    let (a, b) = (w.meta(), w.meta());
    let a_self = Matcher::get("/v1/tokens/self").by(a.id());
    w.adv.record(a_self.clone());
    w.open(&[("acme/dev", &a)]).unwrap();
    let (_, body) = w.adv.recorded(&a_self).unwrap();
    let bundle = serde_json::from_slice::<Value>(&body).unwrap()["bundle"].clone();

    w.adv
        .rewrite(Matcher::get("/v1/tokens/self").by(b.id()), move |v| {
            v["bundle"] = bundle.clone();
        });
    let err = refused_at_startup(w.open(&[("acme/dev", &b)]));
    names_the_failure(&err, &b, "its bundle does not verify");
}

/// The status tool verifies the descriptor it reports from the pinned id.
#[test]
fn a_forged_status_descriptor_is_refused() {
    let w = world();
    let meta = w.meta();
    let s = w.open(&[("acme/dev", &meta)]).unwrap();
    w.adv
        .rewrite(Matcher::get("/v1/vault"), |v| flip_descriptor(v, 53));
    let err = s.status_json("acme/dev").unwrap_err();
    names_the_failure(&err, &meta, "integrity check failed");
    w.adv.clear_rules();
    assert_eq!(s.status_json("acme/dev").unwrap()["generation"], 1);
}

/// After a rotation gv-mcp moves to the new generation; the genuine old
/// view, served again, is refused.
#[test]
fn a_rolled_back_generation_is_refused() {
    let w = world();
    let meta = w.meta();
    let me = Matcher::get("/v1/tokens/self");
    w.adv.record(me.clone());
    let s = w.open(&[("acme/dev", &meta)]).unwrap();

    assert_eq!(w.owner.rotate(&[]).unwrap(), 2);
    assert_eq!(s.list_secrets_json("acme/dev").unwrap()["count"], 2);
    assert_eq!(s.status_json("acme/dev").unwrap()["generation"], 2);

    // Records claiming generation 1 send gv-mcp back for its view, and the
    // server answers with the genuine generation-1 one.
    w.adv.serve_recorded(me);
    w.adv.rewrite(Matcher::get("/v1/secrets"), |v| {
        for item in v["items"].as_array_mut().into_iter().flatten() {
            item["generation"] = 1.into();
        }
    });
    let err = s.list_secrets_json("acme/dev").unwrap_err();
    names_the_failure(&err, &meta, "generation rollback");
}

/// What gv-mcp sends carries no form of its token, and a logged request,
/// sent again, is refused.
#[test]
fn a_replayed_request_is_refused_and_no_request_carries_the_token() {
    let w = world();
    let meta = w.meta();
    let string = meta.token_string();
    w.adv.clear_log();
    let s = w.open(&[("acme/dev", &meta)]).unwrap();
    s.list_secrets_json("acme/dev").unwrap();
    s.status_json("acme/dev").unwrap();
    s.audit_json("acme/dev").unwrap();

    let log = w.adv.log();
    assert!(log.len() >= 4);
    for l in &log {
        let seen = String::from_utf8_lossy(&l.bytes()).into_owned();
        assert!(
            !seen.contains(string.as_str()) && !seen.contains(&string.as_str()[5..]),
            "{} {} carries the token",
            l.method,
            l.path
        );
        assert!(!seen.contains("DATABASE_URL"), "{} {}", l.method, l.path);
    }
    let listing = log
        .iter()
        .find(|l| l.path.starts_with("/v1/secrets?"))
        .expect("the listing was logged");
    let (status, body) = w.adv.replay(listing);
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("unauthorized"))
    );
}
