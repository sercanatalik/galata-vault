# galata-vault

End-to-end-encrypted secrets and config documents with no accounts: the
galata-vault Rust SDK. Values are encrypted, decrypted and
verified on this side; the server only ever stores ciphertext and
signatures. `gv`, `gv ui` and the Python package are built on this crate;
there is no second client implementation.

> **galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.**

Two ways in:

- **`Vault`, the token client.** Open a vault with an access token, then read,
  list, write and delete secrets and configs as the token's scope allows,
  verify the audit chain, and refresh after a rotation.
- **`owner`, the owner API.** Everything `gv` does as a project's owner:
  create projects and environments, rediscover a subtree from a key, render
  and parse recovery and delegation kits, mint and revoke tokens, rotate,
  rekey (with resume and abort), and verify audit chains against a persisted
  head.

## Install

```toml
[dependencies]
galata-vault = "0.1"
```

**Stability.** The API is 0.x: a `0.y` bump may break it, and the changelog
says how. The wire and file formats are specified separately, in the
repository's `docs/spec/`, and carry their own version markers: data
written under a marker stays readable by every later release that reads it,
and a format that changes gets a new marker, never a silent change. The minimum supported Rust version
is 1.98; raising it is a minor release. Security fixes cover the latest
`0.y` release (`SECURITY.md`).

## Opening a vault with a token

A vault is opened with an access token minted by the environment's owner
(`gv token mint --scope …`, or `Environment::mint`), and the server it
belongs to.

```rust,no_run
use galata_vault::Vault;

// GV_SERVER, and exactly one of GV_TOKEN or GV_TOKEN_FILE.
let vault = Vault::from_env()?;
// Or explicitly. On Unix the file must be mode 0600 or 0400 and hold one token.
let vault = Vault::from_token_file("/run/secrets/gv-token", "http://127.0.0.1:8443")?;
# Ok::<(), galata_vault::Error>(())
```

The server must be `https://`, or `http://` on loopback. A token's checksum
is checked before any request, and neither the token nor anything decrypted
ever appears in an error.

Opening verifies the vault from the vault id inside the `gvt1_` token: the
owner signing key must hash to it, the generation descriptor must be signed
by that key, and the token's bundle must be owner-signed for this token and
hold exactly the keys the descriptor names. Every request is signed with a
key derived from the token; the token string itself is never sent.

**Token files on Windows.** This crate cannot verify a Windows ACL without
`unsafe` code or another dependency, so `from_token_file` and `GV_TOKEN_FILE`
refuse the file there (`invalid_token_file`). A caller that has checked the
file's access control itself opens it with
`Vault::from_token_file_with(path, server, TokenFileCheck::CallerVerified)`.
`Vault::new` with a token from a secure source works everywhere.

## Reading and writing

```rust,no_run
use galata_vault::{Expect, NewConfig, Vault};
# let new_body = String::new();

let vault = Vault::from_env()?;

let db = vault.secret("DATABASE_URL")?;          // SecretValue
let bytes: &[u8] = db.expose();                  // exactly what was written
let set = vault.secrets(&["A", "B"])?;           // all, or an error; never some
let all = vault.readable(None)?;                 // every secret this token may read

let app = vault.config("app")?;                  // ConfigDocument
let settings: toml::Table = app.deserialize()?;  // toml and json only
let version = app.version();

// An edit that fails if someone else wrote in between. Never retried.
vault.set_config("app", NewConfig::toml(new_body).expect_version(version))?;
vault.set_secret_expecting("API_KEY", b"k2", Expect::Version(1))?;
vault.delete_secret("OLD_KEY", None)?;           // a signed tombstone; history is kept
let versions = vault.history("API_KEY")?;
# Ok::<(), galata_vault::Error>(())
```

Every record read carries a signature by the generation's writer key for its
kind, over its vault, generation, name index, version, write time and
ciphertext. A record that does not verify is an `Integrity` error; so is a
value whose encrypted envelope names a different vault, generation, version
or name.

`SecretValue` and `ConfigDocument` zeroize on drop, and cannot be printed:
no `Display`, no `Serialize`, and a `Debug` that shows names, versions,
formats and sizes only.

A long-lived handle survives a rotation: a write that meets the new
generation fails with `Error::StaleGeneration`; `vault.refresh()` fetches the
new bundle and descriptor, and the retry succeeds.

## The owner API

```rust,no_run
use std::sync::Arc;
use galata_vault::owner::{Owner, RetiresAllTokens};
use galata_vault::{FileStateStore, KeyStore, Scope};
# fn my_key_store() -> Arc<dyn KeyStore> { unimplemented!() }

let mut owner = Owner::open(my_key_store(), Arc::new(FileStateStore::new("/var/lib/acme")))?;

// Nothing reaches the server until the kit is acknowledged.
let init = owner.begin_init("acme", "https://vault.example")?;
store_somewhere_safe(&init.recovery_kit().render()?);
init.confirm_kit_stored()?;

owner.env_add(&"acme/prod".parse()?)?;
let env = owner.environment(&"acme/prod".parse()?)?; // derefs to Vault
env.set_secret("DATABASE_URL", b"postgres://db.internal/app")?;
let token = env.mint(Scope::Read, 0, &[])?;           // token.expose(), once
owner.close(env)?;                                    // remembers pins, saves state
# fn store_somewhere_safe(_: &str) {}
# let _ = (token, RetiresAllTokens);
# Ok::<(), Box<dyn std::error::Error>>(())
```

The library asks nothing and prints nothing. Every confirmation `gv` asks
for is a typestate or an argument: `PendingInit::confirm_kit_stored`,
`export_kit(path, GrantsSubtreeOwnership)`, `begin_rekey(path,
RetiresAllTokens)`. Every warning goes to the `Events` observer or into an
outcome (`Removal`, `Repair`, `RekeyOutcome`). No kit file is written: the
caller stores what it is handed. A path that is not in the known tree is
refused before any request, with the closest known path as data
(`Error::UnknownPath { suggestion, .. }`).

## Seams

Nothing reaches the host unless it is handed the means:

| seam | what it is | provided |
|---|---|---|
| `Transport` | one method: send the canonical request the protocol signs, get status, headers and body | `HttpTransport` (feature `http`); `Embedded` (feature `embedded`); `RecordingTransport` (feature `test-util`) |
| `Api` | the typed operations over any `Transport`: builds, signs and interprets every request | always |
| `ClientBuilder` | timeout (120 s), proxy (none unless given; never from the environment), root certificates or the platform verifier, user agent, observer; redirects are never followed | feature `http` |
| `KeyStore` | where held node keys live | none (bring your own; `gv` uses the OS keychain) |
| `StateStore` | the known tree, keep-alive times, audit heads, pins, a rekey in progress | `FileStateStore` (`gv`'s `config.toml` and `state.toml`, mode 0600 on Unix) |
| `Events` | expiry, progress and warnings, for the handle that made the request | `NoEvents` (the default) |

Nothing is process-global: two handles with two observers each hear only
their own notices.

## Features

- `http` (default): the HTTP transport. Without it no HTTP client (`ureq`,
  `rustls`, `ring`) is linked; callers bring a `Transport` and use
  `Vault::with_api` and `Owner::with_connector`.
- `platform-verifier`: verify TLS with the operating system's trust store.
- `embedded`: the in-process backend, `galata_vault::embedded::open(dir)`: a
  `Transport` that runs `galata-vault-server-core` over the SQLite store in a data
  directory, the layout `gv-server local` uses, with no socket, HTTP or
  async runtime. Every request is signed and checked as over HTTP. It links
  `galata-vault-server-core`, `galata-vault-store` and `rusqlite`, and no HTTP server, runtime or
  S3 client (`scripts/check-sdk-linkage.sh`). One process opens a directory
  at a time (`data_dir_in_use` otherwise); several processes share vaults
  through `gv-server local`. The module documentation states what the
  embedding process can bypass, and which cryptographic checks still bind
  it.
- `test-util`: in-memory key and state stores, `RecordingTransport`, and
  `galata_vault::testing` for adversarial test harnesses.

## Detecting rollback

```rust,no_run
# let vault = galata_vault::Vault::from_env()?;
# let kept: Option<galata_vault::ChainHead> = None;
let report = vault.verify_audit(kept)?;   // every scope may do this
let keep = report.head;                   // store it; pass it next time
# let store = galata_vault::FileStateStore::new("/var/lib/acme");
let report = vault.audit(&store)?;        // or keep it in a StateStore

let pins = vault.pins();                  // descriptor and record versions seen
vault.set_pins(pins)?;                    // on a later handle: refuses regressions
# Ok::<(), galata_vault::Error>(())
```

A caller that keeps the audit head and the pins across runs detects a server
that shows an older record version (`version_rollback`), an older or
different generation (`generation_rollback`), or a history that does not
continue from the kept head (`audit_mismatch`). The recorded head moves only
when the whole fetched range verifies. A client that keeps nothing cannot
tell a rolled-back or forked server from an honest one.

## What a token can do

| scope          | list | read secrets | write secrets | read configs | write configs |
|----------------|:----:|:------------:|:-------------:|:------------:|:-------------:|
| `meta`         |  ✓   |              |               |              |               |
| `append`       |  ✓   |              |       ✓       |              |       ✓       |
| `read`         |  ✓   |      ✓       |               |      ✓       |               |
| `admin`        |  ✓   |      ✓       |       ✓       |      ✓       |       ✓       |
| `config`       |  ✓   |              |               |      ✓       |               |
| `config-write` |  ✓   |              |               |      ✓       |       ✓       |

The limits are cryptographic: a scope's bundle holds only the keys its row
needs. A `config` or `config-write` token never holds the vault key, and a
`config-write` token holds the config writer key but not the secret writer
key, so it cannot read or write a secret whatever it is given. The server's
scope checks decide what succeeds; the SDK refuses nothing locally that the
scope permits. Minting and rotation need the owner key.

## Configs are checked before they are written

- The body must parse in its declared format (`toml`, `json`); `yaml` and
  `text` must be UTF-8.
- A body holding a credential literal is refused: a `gvt1_` token or `gvk1_`
  key with a valid checksum, a PEM private key, or `0x` and exactly 64 hex digits. Config tokens
  are weaker than secret readers, so a key in a config is a key for every
  config reader. `NewConfig::allow_literals()` overrides it for one write.

Errors name the line and the kind of problem, never the text.

## Errors

One type, `galata_vault::Error`: a `#[non_exhaustive]` enum whose variants
carry structured detail (`Conflict { expected, current, .. }`,
`UnknownPath { suggestion, .. }`, `Integrity { failure, .. }`, …) and keep
their source where there is one (a transport failure's `source()` is the
I/O or TLS error). It is `Send`, `Sync` and `Clone`.

`code()` is a stable string, the same the Python package reports and the
same this crate reported before the enum existed; `kind()` is one of `Auth`,
`Forbidden`, `NotFound`, `Conflict`, `Transport`, `Invalid`, `Integrity` or
`Other`. The `Integrity` codes are `bad_signature`, `key_mismatch`,
`binding_mismatch`, `version_rollback`, `generation_rollback` and
`audit_mismatch`. No error ever holds a token, key
material, a value or a config body.

## The host process

The library is blocking; from async code, call it through `spawn_blocking`. A
`Vault` is `Send + Sync`, so one handle serves every thread. It touches no
keychain and no process limits, writes nothing to stdout or stderr, prompts
for nothing, installs no signal handler, starts no runtime and keeps no
process-global state. `scripts/check-sdk-linkage.sh` keeps keyring, rlimit,
rpassword, clap and pyo3 out of its dependency graph, and
`scripts/check-client-linkage.sh` keeps value decryption out of `galata-vault-client`,
the transport crate beneath it.

## Examples

`cargo run -p galata-vault --example <name>` (and `--features embedded` for
`embedded`):

- `token_read`: read one secret with a token from the environment.
- `owner_workflow`: create a project with an in-memory key store, add an
  environment, mint, read with the token, rotate.
- `custom_transport`: a `Transport` that logs each request's method and path.
- `embedded`: open a data directory, create a project and an environment,
  set a secret and read it back through a read token, with no server.
