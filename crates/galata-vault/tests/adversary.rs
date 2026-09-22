//! The Rust SDK against a malicious server: a real gv-server behind
//! `gv-adversary`, a proxy
//! that logs, replays, rewrites and serves stale answers.
//!
//! Each test is one attack. The owner's setup goes through the shared core,
//! as `gv` does it; the victim is the SDK, opened with a token (and, where an
//! attack targets the owner, the owner's core). Every attack must end in a
//! refusal with a specific code: an integrity code on the client
//! (`bad_signature`, `key_mismatch`, `binding_mismatch`, `version_rollback`,
//! `generation_rollback`), or the server's own 401 or 403. The
//! attacker holds everything the server stores and sees, plus, where a test
//! says so, a token's own bundle.

use galata_vault::keys::{FullBundle, NameContext, NodeKey, TokenKeys, WriterKey, seal_for_scope};
use galata_vault::proto::api::{
    PutSecretRequest, PutSecretResponse, SecretList, SecretVersion, TokenSelf, VaultStatus,
};
use galata_vault::proto::audit::Actor;
use galata_vault::proto::children::{ChildrenBlob, ChildrenRecord};
use galata_vault::proto::codec::TokenString;
use galata_vault::proto::ids::{B64, Hash32, Sig64, VaultId};
use galata_vault::proto::record::{RecordContext, RecordKind};
use galata_vault::proto::sig::SignedRequest;
use galata_vault::seal::{
    ConfigFormat, EnvelopeContext, SealError, new_vault_keypair, open_value, seal_config,
    seal_value,
};
use galata_vault::testing::RawVault as Core;
use galata_vault::{Api, ClientBuilder};
use galata_vault::{Error, ErrorKind, NewConfig, Scope, Vault, code};
use gv_adversary::{Adversary, Logged, Matcher};

// ------------------------------------------------------------------ setup

/// A malicious server with one vault, and its honest owner.
struct World {
    adv: Adversary,
    client: Api,
    owner: Core,
}

fn world() -> World {
    let adv = Adversary::start();
    let client = ClientBuilder::new(adv.url()).build().unwrap();
    let key = NodeKey::generate();
    assert!(Core::create(&client, &key, "acme/dev").unwrap());
    let owner = Core::open_owner(&client, &key, "acme/dev").unwrap();
    World { adv, client, owner }
}

impl World {
    fn mint(&self, scope: Scope) -> TokenKeys {
        self.owner.mint(scope, 0, None).unwrap().0
    }

    fn open(&self, token: &TokenKeys) -> Result<Vault, Error> {
        Vault::new(&token.token_string(), self.adv.url())
    }

    fn put(&self, name: &str, value: &[u8]) -> u64 {
        let pre = self.owner.current(name).unwrap();
        self.owner.put(name, value, pre).unwrap()
    }

    fn put_config(&self, name: &str, body: &[u8]) -> u64 {
        let pre = self.owner.config_current(name).unwrap();
        self.owner
            .put_config(name, ConfigFormat::Toml, body, pre)
            .unwrap()
    }

    /// Another vault on the same server, and its owner.
    fn second_vault(&self, label: &str) -> Core {
        let key = NodeKey::generate();
        assert!(Core::create(&self.client, &key, label).unwrap());
        Core::open_owner(&self.client, &key, label).unwrap()
    }

    /// The genuine children blob, as the server stores it.
    fn genuine_children(&self) -> ChildrenBlob {
        let m = Matcher::get("/v1/vault/children");
        self.adv.record(m.clone());
        self.owner.children().unwrap();
        self.adv.recorded_as(&m)
    }
}

fn secret_path(core: &Core, name: &str) -> String {
    format!("/v1/secrets/{}", core.name_key().hmac(name).to_hex())
}

fn config_path(core: &Core, name: &str) -> String {
    format!("/v1/configs/{}", core.name_key().config_hmac(name).to_hex())
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// The refusal must be an integrity failure with exactly this code.
#[track_caller]
fn integrity(e: Error, want: &str) {
    assert_eq!(
        (e.kind(), e.code()),
        (ErrorKind::Integrity, want),
        "{}",
        e.message()
    );
}

/// The error of a core call that must fail (a core handle has no `Debug`).
fn refused<T>(r: Result<T, Error>) -> Error {
    match r {
        Ok(_) => panic!("the attack was not refused"),
        Err(e) => e,
    }
}

/// A core (owner-side) failure's stable code, as the SDK reports it.
fn core_code(e: Error) -> String {
    e.code().to_owned()
}

/// A record built by the attacker: sealed to the genuine descriptor's key
/// (it is public), its name encrypted with a name key the attacker holds (a
/// meta, read or config token's), and signed with `signer`.
fn forged(
    core: &Core,
    kind: RecordKind,
    name: &str,
    body: &[u8],
    version: u64,
    signer: &WriterKey,
) -> SecretVersion {
    let d = &core.descriptor();
    let at = 1_757_500_000;
    let ctx = EnvelopeContext {
        vault_id: d.vault_id,
        generation: d.generation,
        version,
        written_at: at,
    };
    let value_ct = match kind {
        RecordKind::Secret => seal_value(&d.vault_pub, &ctx, name, body).unwrap(),
        RecordKind::Config => {
            seal_config(&d.config_pub, &ctx, name, ConfigFormat::Toml, body).unwrap()
        }
        _ => unreachable!("the harness forges two record kinds"),
    };
    let name_ct = core
        .name_key()
        .encrypt_name(
            &NameContext {
                vault_id: d.vault_id,
                generation: d.generation,
                kind,
            },
            name,
        )
        .unwrap();
    let index = core.name_key().index(kind, name);
    let rctx = RecordContext::new(
        d.vault_id,
        d.generation,
        kind,
        index,
        version,
        at,
        &name_ct,
        Some(&value_ct),
    );
    SecretVersion::new(
        index,
        version,
        B64(name_ct),
        Some(B64(value_ct)),
        d.generation,
        at,
        Actor::Owner,
        false,
        signer.sign(&rctx),
    )
}

/// Headers for a request signed by `token`, as a client would send it.
fn token_headers(
    token: &TokenKeys,
    method: &str,
    path: &str,
    body: &[u8],
    if_match: Option<&str>,
    if_none_match: Option<&str>,
) -> Vec<(String, String)> {
    let signed = SignedRequest {
        method,
        path_and_query: path,
        body,
        if_match,
        if_none_match,
    };
    let mut headers = vec![
        (
            "authorization".to_owned(),
            token.sign_request(&signed, now()).to_header_value(),
        ),
        ("content-type".to_owned(), "application/json".to_owned()),
    ];
    if let Some(v) = if_match {
        headers.push(("if-match".to_owned(), v.to_owned()));
    }
    if let Some(v) = if_none_match {
        headers.push(("if-none-match".to_owned(), v.to_owned()));
    }
    headers
}

fn send(
    w: &World,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> (u16, serde_json::Value) {
    let headers: Vec<(&str, &str)> = headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    w.adv.send(method, path, &headers, body)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn hex_lower(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|b| format!("{b:02x}").into_bytes())
        .collect()
}

// ------------------------------------------------------------------ attacks

/// Everything a request log, a TLS terminator or the operator sees holds no
/// form of the token secret: requests carry signatures, never the token
/// string, so nothing logged derives the key that opens the token's bundle.
#[test]
fn harvesting_the_token_secret_from_logged_requests() {
    let w = world();
    w.put("DATABASE_URL", b"postgres://secret");
    let token = w.mint(Scope::Read);
    let string = token.token_string();
    let secret = TokenString::parse(&string).unwrap().secret;
    w.adv.clear_log();

    let vault = w.open(&token).unwrap();
    assert_eq!(
        vault.secret("DATABASE_URL").unwrap().expose(),
        b"postgres://secret"
    );
    vault.list().unwrap();
    vault.verify_audit(None).unwrap();

    let log = w.adv.log();
    let signed: Vec<&Logged> = log.iter().filter(|l| l.actor().is_some()).collect();
    assert!(signed.len() >= 4, "the token made signed requests");
    let forms: [Vec<u8>; 5] = [
        string.as_bytes().to_vec(),
        string.as_str().as_bytes()[5..].to_vec(),
        secret[..].to_vec(),
        hex_lower(&secret[..]),
        B64::encode_str(&secret[..]).into_bytes(),
    ];
    for l in &log {
        let seen = l.bytes();
        for form in &forms {
            assert!(
                !contains(&seen, form),
                "{} {} leaks a form of the token secret",
                l.method,
                l.path
            );
        }
        if let Some(auth) = l.header("authorization") {
            assert!(auth.starts_with("GV-Sig v=1,actor="), "{auth}");
        }
    }
    // Each signature is spent once: replaying the logged requests gets the
    // attacker nothing.
    for l in signed {
        assert_eq!(w.adv.replay(l).0, 401, "{} {}", l.method, l.path);
    }
}

/// Changing a public key in the descriptor breaks the owner's signature,
/// for a token holder and for the owner alike.
#[test]
fn a_substituted_vault_or_config_key_is_refused() {
    let w = world();
    // vault_pub is bytes 21..53 of the descriptor, config_pub 53..85.
    for range in [21..53usize, 53..85] {
        let token = w.mint(Scope::Read);
        let r = range.clone();
        w.adv
            .rewrite_as::<TokenSelf>(Matcher::get("/v1/tokens/self"), move |me| {
                for b in &mut me.descriptor.descriptor.0[r.clone()] {
                    *b ^= 0x5a;
                }
            });
        integrity(w.open(&token).unwrap_err(), code::BAD_SIGNATURE);
        w.adv.clear_rules();

        // The genuine owner, faced with a substituted key in its own status.
        let key = NodeKey::generate();
        let label = format!("acme/stage-{}", range.start);
        assert!(Core::create(&w.client, &key, &label).unwrap());
        let at = range.start;
        w.adv
            .rewrite_as::<VaultStatus>(Matcher::get("/v1/vault"), move |s| {
                s.descriptor.descriptor.0[at] ^= 1;
            });
        let e = refused(Core::open_owner(&w.client, &key, &label));
        assert_eq!(core_code(e), code::BAD_SIGNATURE);
        w.adv.clear_rules();
    }
}

/// An `append` token holds the writer keys and no vault key, so its bundle
/// cannot vouch for `vault_pub`: only the owner's signature on the
/// descriptor does. A server that swaps in a key of its own is refused before
/// anything is encrypted to it. (With that check planted away,
/// scripts/adversary-plant.sh, the write goes through and the server
/// decrypts it; the panic below says so.)
#[test]
fn an_append_token_never_encrypts_to_a_substituted_key() {
    let w = world();
    let token = w.mint(Scope::Append);
    let (attacker, attacker_pub) = new_vault_keypair().unwrap();
    w.adv
        .rewrite_as::<TokenSelf>(Matcher::get("/v1/tokens/self"), move |me| {
            // vault_pub is bytes 21..53 of the descriptor.
            me.descriptor.descriptor.0[21..53].copy_from_slice(&attacker_pub.0);
        });
    w.adv.clear_log();
    let vault = match w.open(&token) {
        Err(e) => return integrity(e, code::BAD_SIGNATURE),
        Ok(vault) => vault,
    };
    let wrote = vault.set_secret("S", b"top secret");
    let decrypted = w.adv.log().iter().any(|l| {
        l.method == "PUT"
            && serde_json::from_slice::<PutSecretRequest>(&l.body).is_ok_and(|r| {
                // Anything but "does not decrypt" means the attacker's key opened it.
                let ctx = EnvelopeContext {
                    vault_id: VaultId([0; 16]),
                    generation: 0,
                    version: 0,
                    written_at: 0,
                };
                !matches!(
                    open_value(&attacker, &ctx, "S", &r.value_ct.0),
                    Err(SealError::Decrypt | SealError::NotAge)
                )
            })
    });
    panic!(
        "an append token accepted a substituted vault key (write: {:?}); the server {} decrypt what it was sent",
        wrote.map_err(|e| e.code().to_owned()),
        if decrypted { "could" } else { "could not" }
    );
}

/// An attacker's own owner key cannot stand in for the pinned one: it does
/// not hash to the vault id the client pinned.
#[test]
fn a_swapped_owner_key_is_refused() {
    let w = world();
    let token = w.mint(Scope::Read);
    let attacker = NodeKey::generate().owner();
    let theirs = attacker.sign_descriptor(&FullBundle::generate(1).descriptor(
        attacker.vault_id(),
        Hash32([0; 32]),
        0,
    ));
    let attacker_pub = attacker.sign_pub();
    let desc = theirs.clone();
    w.adv
        .rewrite_as::<TokenSelf>(Matcher::get("/v1/tokens/self"), move |me| {
            me.owner_sign_pub = attacker_pub;
            me.descriptor = desc.clone();
        });
    integrity(w.open(&token).unwrap_err(), code::KEY_MISMATCH);
    w.adv.clear_rules();

    // The owner sees its own vault claimed by another key.
    let key = NodeKey::generate();
    assert!(Core::create(&w.client, &key, "acme/stage").unwrap());
    w.adv
        .rewrite_as::<VaultStatus>(Matcher::get("/v1/vault"), move |s| {
            s.owner_sign_pub = attacker_pub;
            s.descriptor = theirs.clone();
        });
    let e = refused(Core::open_owner(&w.client, &key, "acme/stage"));
    assert_eq!(core_code(e), code::KEY_MISMATCH);
}

/// A bundle sealed to the token's (public) box key with keys the attacker
/// chose, signed by any key but the pinned owner's, is refused.
#[test]
fn a_forged_bundle_is_refused() {
    let w = world();
    w.put("S", b"genuine");
    let token = w.mint(Scope::Read);
    let attacker = NodeKey::generate().owner();
    let bundle = seal_for_scope(
        &attacker,
        &token.box_pub(),
        &token.id(),
        Scope::Read,
        &FullBundle::generate(1),
    )
    .unwrap();
    w.adv
        .rewrite_as::<TokenSelf>(Matcher::get("/v1/tokens/self"), move |me| {
            me.bundle = bundle.clone();
        });
    integrity(w.open(&token).unwrap_err(), code::BAD_SIGNATURE);
}

/// One token's genuine bundle, served to another token, fails: the owner's
/// signature binds the token id and the scope.
#[test]
fn a_bundle_moved_between_tokens_is_refused() {
    let w = world();
    for (from, to) in [(Scope::Read, Scope::Read), (Scope::Admin, Scope::Read)] {
        let (a, b) = (w.mint(from), w.mint(to));
        let from_a = Matcher::get("/v1/tokens/self").by(a.id());
        w.adv.record(from_a.clone());
        w.open(&a).unwrap();
        let a_self: TokenSelf = w.adv.recorded_as(&from_a);
        w.adv
            .rewrite_as::<TokenSelf>(Matcher::get("/v1/tokens/self").by(b.id()), move |me| {
                me.bundle = a_self.bundle.clone();
            });
        integrity(w.open(&b).unwrap_err(), code::BAD_SIGNATURE);
        w.adv.clear_rules();
    }
}

/// Meta, read and config bundles hold no writer key, so what they can build
/// is signed by some other key, and every reader refuses it.
#[test]
fn a_record_forged_with_meta_read_or_config_material_is_refused() {
    let w = world();
    w.put("S", b"genuine");
    w.put_config("app", b"a = 1\n");
    for scope in [Scope::Meta, Scope::Read, Scope::Config] {
        let held = Core::open_token(&w.client, w.mint(scope), "held").unwrap();
        assert!(held.secret_writer().is_none(), "{scope}");
        assert!(held.config_writer().is_none(), "{scope}");
    }

    let rogue = WriterKey::generate();
    let record = forged(&w.owner, RecordKind::Secret, "S", b"forged", 2, &rogue);
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&secret_path(&w.owner, "S")), move |v| {
            *v = record.clone();
        });
    let read = w.open(&w.mint(Scope::Read)).unwrap();
    integrity(read.secret("S").unwrap_err(), code::BAD_SIGNATURE);

    let record = forged(&w.owner, RecordKind::Config, "app", b"a = 2\n", 2, &rogue);
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&config_path(&w.owner, "app")), move |v| {
            *v = record.clone();
        });
    let config = w.open(&w.mint(Scope::Config)).unwrap();
    integrity(config.config("app").unwrap_err(), code::BAD_SIGNATURE);

    // A listing whose signatures were forged is refused as well.
    w.adv
        .rewrite_as::<SecretList>(Matcher::get("/v1/secrets"), |l| {
            for item in &mut l.items {
                item.sig = Sig64([7; 64]);
            }
        });
    let meta = w.open(&w.mint(Scope::Meta)).unwrap();
    integrity(meta.list().unwrap_err(), code::BAD_SIGNATURE);
}

/// An append holder cannot write the owner-only children record, and a
/// forged children record served to the owner is refused.
#[test]
fn the_children_record_cannot_be_written_or_forged_by_a_token() {
    let w = world();
    let append = w.mint(Scope::Append);
    let forger = NodeKey::generate().owner();
    let blob = forger.seal_children(2, &ChildrenRecord::new()).unwrap();
    let body = serde_json::to_vec(&blob).unwrap();
    let headers = token_headers(&append, "PUT", "/v1/vault/children", &body, Some("1"), None);
    assert_eq!(
        send(&w, "PUT", "/v1/vault/children", &headers, &body).0,
        403
    );
    // A token cannot read it either.
    let headers = token_headers(&append, "GET", "/v1/vault/children", b"", None, None);
    assert_eq!(send(&w, "GET", "/v1/vault/children", &headers, b"").0, 403);

    // The honest owner reads it back unchanged...
    let genuine = w.genuine_children();
    let (record, _) = w.owner.children().unwrap();
    assert!(record.children().is_empty());
    // ...and refuses one signed by anyone else, or re-versioned.
    for fake in [
        forger
            .seal_children(genuine.version, &ChildrenRecord::new())
            .unwrap(),
        {
            let mut patched = genuine.clone();
            patched.version = genuine.version + 6;
            patched
        },
    ] {
        w.adv
            .rewrite_as::<ChildrenBlob>(Matcher::get("/v1/vault/children"), move |b| {
                *b = fake.clone();
            });
        let e = w.owner.children().unwrap_err();
        assert_eq!(core_code(e), code::BAD_SIGNATURE);
        w.adv.clear_rules();
    }
}

/// A config-write holder cannot write a secret: the server refuses it, and
/// a secret signed with the config writer key is refused by every reader.
#[test]
fn a_config_write_holder_cannot_write_a_secret() {
    let w = world();
    w.put("SIGNING_KEY", b"0xgenuine");
    let cw = w.mint(Scope::ConfigWrite);
    let held = Core::open_token(
        &w.client,
        TokenKeys::parse(&cw.token_string()).unwrap(),
        "cw",
    )
    .unwrap();
    let config_writer = held.config_writer().unwrap();
    assert!(held.secret_writer().is_none());

    // The server refuses the write outright.
    let record = forged(
        &w.owner,
        RecordKind::Secret,
        "SIGNING_KEY",
        b"0xattacker",
        2,
        &config_writer,
    );
    let path = secret_path(&w.owner, "SIGNING_KEY");
    let body = serde_json::to_vec(&PutSecretRequest::new(
        record.name_ct.clone(),
        record.value_ct.clone().unwrap(),
        record.generation,
        2,
        record.written_at,
        record.sig,
    ))
    .unwrap();
    let headers = token_headers(&cw, "PUT", &path, &body, Some("1"), None);
    assert_eq!(send(&w, "PUT", &path, &headers, &body).0, 403);

    // A colluding server serves it anyway: every reader refuses it.
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&path), move |v| *v = record.clone());
    let read = w.open(&w.mint(Scope::Read)).unwrap();
    integrity(read.secret("SIGNING_KEY").unwrap_err(), code::BAD_SIGNATURE);
    let e = w.owner.get("SIGNING_KEY", None).unwrap_err();
    assert_eq!(core_code(e), code::BAD_SIGNATURE);
}

/// A genuine older version, served as the latest, is refused by a handle
/// that saw a newer one, and by a later handle given its pins.
#[test]
fn a_rolled_back_version_is_refused() {
    let w = world();
    w.put("S", b"v1");
    let token = w.mint(Scope::Read);
    let latest = Matcher::get(&secret_path(&w.owner, "S"));
    let reader = w.open(&token).unwrap();
    w.adv.record(latest.clone());
    assert_eq!(reader.secret("S").unwrap().version(), 1);
    w.put("S", b"v2");
    assert_eq!(reader.secret("S").unwrap().version(), 2);

    w.adv.serve_recorded(latest);
    integrity(reader.secret("S").unwrap_err(), code::VERSION_ROLLBACK);
    let later = w.open(&token).unwrap();
    later.set_pins(reader.pins()).unwrap();
    integrity(later.secret("S").unwrap_err(), code::VERSION_ROLLBACK);
    // A handle with no memory cannot tell: the accepted residual.
    assert_eq!(w.open(&token).unwrap().secret("S").unwrap().version(), 1);
}

/// After a rotation, the old generation's genuine answer is refused by a
/// handle pinned to the new one.
#[test]
fn a_rolled_back_generation_is_refused() {
    let w = world();
    w.put("S", b"v");
    let token = w.mint(Scope::Read);
    let me = Matcher::get("/v1/tokens/self").by(token.id());
    w.adv.record(me.clone());
    let gen1 = w.open(&token).unwrap();
    assert_eq!(gen1.secret("S").unwrap().expose(), b"v");

    assert_eq!(w.owner.rotate(&[]).unwrap(), 2);
    let gen2 = w.open(&token).unwrap();
    assert_eq!(gen2.secret("S").unwrap().expose(), b"v");
    let pins = gen2.pins();
    assert_eq!(pins.descriptor.unwrap().generation, 2);

    // The genuine, owner-signed generation-1 answer, served again.
    w.adv.serve_recorded(me);
    let stale = w.open(&token).unwrap();
    integrity(stale.set_pins(pins).unwrap_err(), code::GENERATION_ROLLBACK);
}

/// A genuine record from another vault, or of the other kind, does not pass
/// for the one asked for.
#[test]
fn ciphertext_swapped_across_vaults_and_kinds_is_refused() {
    let w = world();
    w.put("S", b"mine");
    w.put_config("app", b"a = 1\n");
    w.put("app", b"secret app");
    let other = w.second_vault("other/dev");
    let pre = other.current("S").unwrap();
    other.put("S", b"theirs", pre).unwrap();

    // Their record, as the server stores it.
    let theirs_m = Matcher::get(&secret_path(&other, "S"));
    w.adv.record(theirs_m.clone());
    other.get("S", None).unwrap();
    let theirs: SecretVersion = w.adv.recorded_as(&theirs_m);

    let reader = w.open(&w.mint(Scope::Read)).unwrap();
    let mine = secret_path(&w.owner, "S");
    // As is: it is not filed under the name asked for.
    let t = theirs.clone();
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&mine), move |v| *v = t.clone());
    integrity(reader.secret("S").unwrap_err(), code::BINDING_MISMATCH);
    w.adv.clear_rules();
    // Re-filed under this vault's index: the signature binds the vault.
    let index = w.owner.name_key().hmac("S");
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&mine), move |v| {
            *v = theirs.clone();
            v.name_hmac = index;
        });
    integrity(reader.secret("S").unwrap_err(), code::BAD_SIGNATURE);
    w.adv.clear_rules();

    // The config "app", served as the secret "app".
    let cfg_m = Matcher::get(&config_path(&w.owner, "app"));
    w.adv.record(cfg_m.clone());
    w.owner.get_config("app", None).unwrap();
    let config: SecretVersion = w.adv.recorded_as(&cfg_m);
    let index = w.owner.name_key().hmac("app");
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&secret_path(&w.owner, "app")), move |v| {
            *v = config.clone();
            v.name_hmac = index;
        });
    integrity(reader.secret("app").unwrap_err(), code::BAD_SIGNATURE);
}

/// A tombstone the writer did not sign hides nothing: it is refused, and
/// the genuine value is still there when the proxy stops lying.
#[test]
fn a_forged_tombstone_is_refused() {
    let w = world();
    w.put("S", b"live");
    let reader = w.open(&w.mint(Scope::Read)).unwrap();
    let latest = Matcher::get(&secret_path(&w.owner, "S"));

    // The value dropped, under the old signature.
    w.adv.rewrite_as::<SecretVersion>(latest.clone(), |v| {
        v.value_ct = None;
        v.tombstone = true;
    });
    integrity(reader.secret("S").unwrap_err(), code::BAD_SIGNATURE);
    w.adv.clear_rules();

    // The flag set while the value stays.
    w.adv
        .rewrite_as::<SecretVersion>(latest.clone(), |v| v.tombstone = true);
    integrity(reader.secret("S").unwrap_err(), code::BINDING_MISMATCH);
    w.adv.clear_rules();

    // A tombstone signed with a key the attacker made.
    let rogue = WriterKey::generate();
    let mut fake = forged(&w.owner, RecordKind::Secret, "S", b"x", 2, &rogue);
    fake.value_ct = None;
    fake.tombstone = true;
    w.adv
        .rewrite_as::<SecretVersion>(latest, move |v| *v = fake.clone());
    integrity(reader.secret("S").unwrap_err(), code::BAD_SIGNATURE);
    w.adv.clear_rules();

    assert_eq!(reader.secret("S").unwrap().expose(), b"live");
}

/// What the client refuses, or never verified, must not move its version
/// pins: otherwise one forged answer wedges the handle, and every later
/// genuine answer reads as a rollback.
#[test]
fn a_refused_or_unsigned_version_does_not_move_the_pins() {
    let w = world();
    w.put("S", b"v1");
    let reader = w.open(&w.mint(Scope::Read)).unwrap();
    assert_eq!(reader.secret("S").unwrap().version(), 1);

    // A forged version 9, refused.
    let rogue = WriterKey::generate();
    let fake = forged(&w.owner, RecordKind::Secret, "S", b"forged", 9, &rogue);
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&secret_path(&w.owner, "S")), move |v| {
            *v = fake.clone()
        });
    integrity(reader.secret("S").unwrap_err(), code::BAD_SIGNATURE);
    w.adv.clear_rules();
    let genuine = reader.secret("S");
    assert_eq!(
        genuine
            .as_ref()
            .map(|s| s.version())
            .map_err(|e| e.message()),
        Ok(1),
        "a refused record moved the pin"
    );

    // A write acknowledged as version 999: the acknowledgement is unsigned.
    w.adv
        .rewrite_as::<PutSecretResponse>(Matcher::prefix("PUT", "/v1/secrets/"), |r| {
            r.version = 999
        });
    let pre = w.owner.current("S").unwrap();
    let _ = w.owner.put("S", b"v2", pre);
    w.adv.clear_rules();
    let got = w.owner.get("S", None).map(|(v, _)| v).map_err(core_code);
    assert_eq!(got, Ok(2), "an unsigned acknowledgement moved the pin");
}

/// A logged request, sent again, is refused: each signature's nonce is
/// spent once. Replaying a write changes nothing.
#[test]
fn a_replayed_signed_request_is_refused() {
    let w = world();
    let append = w.open(&w.mint(Scope::Append)).unwrap();
    w.adv.clear_log();
    assert_eq!(append.set_secret("FROM_CI", b"v1").unwrap(), 1);
    let put = w
        .adv
        .log()
        .into_iter()
        .find(|l| l.method == "PUT" && l.path.starts_with("/v1/secrets/"))
        .expect("the write was logged");
    let (status, body) = w.adv.replay(&put);
    assert_eq!(
        (status, body["error"].as_str()),
        (401, Some("unauthorized"))
    );
    assert_eq!(w.owner.current("FROM_CI").unwrap().next_version(), 2);

    let read = w.mint(Scope::Read);
    w.adv.clear_log();
    w.open(&read).unwrap();
    let log = w.adv.log();
    // A new handle reads the unauthenticated capabilities first, then signs.
    assert_eq!(log[0].path, "/v1/capabilities");
    assert!(log[0].header("authorization").is_none());
    let whoami = log
        .into_iter()
        .find(|l| l.path == "/v1/tokens/self")
        .expect("the token's view was logged");
    assert_eq!(w.adv.replay(&whoami).0, 401);
}

/// A fresh, never-sent request whose signature is removed, altered,
/// downgraded to v1 or replaced by a bearer credential is refused; so is a
/// response whose signature was zeroed.
#[test]
fn a_stripped_or_altered_signature_is_refused() {
    let w = world();
    w.put("S", b"v");
    let token = w.mint(Scope::Read);
    let path = "/v1/tokens/self";
    let fresh = || token_headers(&token, "GET", path, b"", None, None);
    let auth_of = |h: &[(String, String)]| {
        h.iter()
            .find(|(k, _)| k == "authorization")
            .unwrap()
            .1
            .clone()
    };
    let with_auth = |h: Vec<(String, String)>, auth: Option<String>| {
        let mut h: Vec<_> = h
            .into_iter()
            .filter(|(k, _)| k != "authorization")
            .collect();
        if let Some(a) = auth {
            h.push(("authorization".to_owned(), a));
        }
        h
    };
    let h = fresh();
    let stripped = with_auth(h, None);
    let h = fresh();
    let a = auth_of(&h);
    let downgraded = with_auth(h, Some(a.replace("v=1", "v=2")));
    let h = fresh();
    let a = auth_of(&h);
    let zeroed = with_auth(
        h,
        Some(format!(
            "{},sig={}",
            a.split(",sig=").next().unwrap(),
            B64::encode_str(&[0; 64])
        )),
    );
    let bearer = with_auth(
        fresh(),
        Some(format!("Bearer {}", token.token_string().as_str())),
    );
    for (what, headers) in [
        ("stripped", stripped),
        ("downgraded", downgraded),
        ("zeroed", zeroed),
        ("bearer", bearer),
    ] {
        let (status, body) = send(&w, "GET", path, &headers, b"");
        assert_eq!(
            (status, body["error"].as_str()),
            (401, Some("unauthorized")),
            "{what}"
        );
    }
    // The same request, signed and untouched, is accepted.
    assert_eq!(send(&w, "GET", path, &fresh(), b"").0, 200);

    let reader = w.open(&token).unwrap();
    w.adv
        .rewrite_as::<SecretVersion>(Matcher::get(&secret_path(&w.owner, "S")), |v| {
            v.sig = Sig64([0; 64]);
        });
    integrity(reader.secret("S").unwrap_err(), code::BAD_SIGNATURE);
}

/// A token under another version digit is refused before any request, and
/// a bearer credential gets the server's uniform 401.
#[test]
fn a_token_of_another_version_is_refused() {
    let w = world();
    let other = galata_vault::proto::codec::encode_checked("gvt2_", &[7u8; 48]);
    let before = w.adv.log().len();
    let e = Vault::new(&other, w.adv.url()).unwrap_err();
    assert_eq!(e.code(), code::INVALID_TOKEN, "{e}");
    assert_eq!(w.adv.log().len(), before, "no request was made");
    let bearer = format!("Bearer {}", other.as_str());
    let (status, _) = w
        .adv
        .send("GET", "/v1/tokens/self", &[("authorization", &bearer)], b"");
    assert_eq!(status, 401);
}

/// The control: when the proxy is not lying, everything works through it.
#[test]
fn an_honest_proxy_changes_nothing() {
    let w = world();
    let writer = w.open(&w.mint(Scope::ConfigWrite)).unwrap();
    assert_eq!(
        writer
            .set_config("app", NewConfig::toml(b"a = 1\n".to_vec()))
            .unwrap(),
        1
    );
    let reader = w.open(&w.mint(Scope::Config)).unwrap();
    assert_eq!(reader.config("app").unwrap().expose(), b"a = 1\n");
    assert!(reader.verify_audit(None).unwrap().head.is_some());
}
