# galata-vault

End-to-end-encrypted secrets and config documents for software, with no
accounts. A project is a key you generate. Everything is encrypted and signed
on your machine, and the server (or an in-process backend) stores only
ciphertext it cannot read, under signatures it cannot forge.

galata-vault is a Rust library first: the `galata-vault` SDK. Built on it are
the `gv` command line, a Python package, a server that cannot decrypt, and a
metadata-only MCP server for AI agents.

> **galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.**

**Stability.** The crates are 0.x: a `0.y` release may break the API, a
`0.y.z` release does not, and [CHANGELOG.md](CHANGELOG.md) lists every
change. The wire and file formats are specified separately, in
[docs/spec/](docs/spec/README.md), and carry their own version markers: data
written under a marker stays readable by every later release that reads it,
and a format that changes gets a new marker. The minimum supported Rust
version is 1.98, and raising it is a minor release. Security fixes cover the
latest `0.y` release ([SECURITY.md](SECURITY.md)).

## Install

**Not yet published: these lines work after 0.1.0 is published.** Until
then, build from a checkout (`cargo build --release -p galata-vault-cli
--features ui` for `gv`, `-p galata-vault-server` for `gv-server`).

```sh
cargo add galata-vault                  # the Rust SDK
cargo binstall galata-vault-cli         # gv, prebuilt (or: cargo install galata-vault-cli --features ui)
brew install sercanatalik/tap/galata-vault-cli   # gv from the project's Homebrew tap
pip install galata-vault                # the Python package, with gv
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/sercanatalik/galata-vault/releases/latest/download/galata-vault-cli-installer.sh | sh
```

Each [GitHub release](https://github.com/sercanatalik/galata-vault/releases)
also carries a PowerShell installer for `gv`, and shell installers for
`gv-server` and `gv-mcp`. Every binary has a GitHub artifact attestation:
`gh attestation verify <file> --repo sercanatalik/galata-vault`.

## The SDK

```rust,no_run
let vault = galata_vault::Vault::from_env()?;   // GV_SERVER, and GV_TOKEN or GV_TOKEN_FILE
let url = vault.secret("DATABASE_URL")?;        // .expose() gives the exact bytes written
let app: toml::Table = vault.config("app")?.deserialize()?;
# Ok::<(), Box<dyn std::error::Error>>(())
```

- **`Vault`, the token client.** Read, list, write and delete secrets and
  configs as the token's scope allows; fetch history and status; verify the
  audit chain; `refresh()` after a rotation.
- **`owner`, the owner API.** Everything `gv` does as a project's owner:
  projects, environments, rediscovery from a key, recovery and delegation
  kits, minting and revoking tokens, rotation, rekey (with resume and abort),
  and audit verification against a stored head. It prompts for nothing and
  prints nothing.
- **Seams.** Requests go through a `Transport` (`ClientBuilder` builds the
  HTTP one), keys through a `KeyStore` you supply, and local bookkeeping
  through a `StateStore`. Nothing is process-global, and the SDK leaves its
  host alone: no keychain, no process limits, nothing on stdout or stderr.
- **`embedded`, no server.** With the `embedded` feature,
  `galata_vault::embedded::open(dir)` runs the server's rules in-process over
  a data directory: no socket, no HTTP, no async runtime.

Errors are one `#[non_exhaustive]` enum with stable codes, and integrity
failures are their own variant. See the [SDK's README](crates/galata-vault/README.md)
and its [examples](crates/galata-vault/examples/).

## The command line

```sh
gv-server local                                  # or use a server you trust
gv init acme --server http://127.0.0.1:8750      # writes acme-recovery.gvkit; keep it safe
gv env add acme/prod
printf %s "$DATABASE_URL" | gv set DATABASE_URL --env acme/prod
gv run --env acme/prod -- ./deploy               # secrets arrive as environment variables
gv token mint --scope read --env acme/prod       # for CI: GV_TOKEN + GV_SERVER
gv config set app --format toml --env acme/prod < app.toml
gv ui                                            # the vault in your browser, on loopback
```

The concepts behind it (the key tree, delegation and rekey, tokens and what
revocation means, config documents, durability, the local UI, the MCP
server) are in [docs/guide.md](docs/guide.md). `galata-vault-cli` is also a
library: another binary can carry the `gv` command tree under its own name
([crates/galata-vault-cli/README.md](crates/galata-vault-cli/README.md)).

## Python

```python
import galata_vault

vault = galata_vault.Vault.from_env()   # GV_SERVER, and GV_TOKEN or GV_TOKEN_FILE
url = vault.get("DATABASE_URL")
app = vault.get_config("app").parse()   # a dict
```

The wheel runs the same Rust code as `gv`, and bundles `gv` itself. See
[crates/gv-py/README.md](crates/gv-py/README.md).

## The server

The server stores ciphertext (age v1), signed records, HMAC name indexes
with encrypted names, public keys, owner-signed descriptors and bundles, and
an audit hash chain. It never receives a plaintext name or value, a project
or environment path, or any key that decrypts; the server binary links no
decryption code, and a CI guard fails the build if it ever does. Every
client pins a vault id before trusting anything, so a server cannot
substitute a key, forge or move a record, or rewrite the tree unnoticed.
[docs/threat-model.md](docs/threat-model.md) says what each actor can and
cannot do.

`gv-server local` needs no configuration and listens on loopback. For other
machines you trust, run a configured `gv-server` behind a TLS-terminating
proxy: [deploy/README.md](deploy/README.md).

## Crates

| Crate | On crates.io | Role |
|---|---|---|
| `galata-vault` | yes | the SDK: the token client, the owner API, the `embedded` backend |
| `galata-vault-cli` | yes | `gv`, and a library another binary can brand and extend |
| `galata-vault-server` | yes | `gv-server`: the HTTP API, an axum shell over the core |
| `galata-vault-mcp` | yes | `gv-mcp`: the metadata-only MCP server |
| `galata-vault-proto` | yes, internal | formats, API types, descriptors, audit chain, signature verification |
| `galata-vault-keys` | yes, internal | key tree, owner, token and writer keys, bundles, name key |
| `galata-vault-seal` | yes, internal | age envelopes, signed records, rotation; client-only |
| `galata-vault-client` | yes, internal | the client transport and request signing; no value decryption |
| `galata-vault-store` | yes, internal | SQLite storage and journal records |
| `galata-vault-server-core` | yes, internal | the server's rules, with no HTTP, async or decryption code |
| `gv-py` | no (PyPI: `galata-vault`) | the Python package |
| `gv-adversary`, `gv-conformance` | no | the malicious-server harness, the conformance suite |

"Internal" crates are implementation details, with no semver promise beyond
the shared version: depend on `galata-vault`. [ARCHITECTURE.md](ARCHITECTURE.md)
maps them.

## Documentation

- [docs/spec/](docs/spec/README.md): the protocol, with test vectors in
  `testdata/vectors/v1/` and a conformance suite
- [docs/threat-model.md](docs/threat-model.md) and [ARCHITECTURE.md](ARCHITECTURE.md)
- [docs/guide.md](docs/guide.md): concepts and the command line
- [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md),
  [RELEASING.md](RELEASING.md)

## Contributing and licence

`scripts/check-all.sh` runs everything CI runs. Contributions are accepted
under the Developer Certificate of Origin: see
[CONTRIBUTING.md](CONTRIBUTING.md) and the [Code of Conduct](CODE_OF_CONDUCT.md).

Licensed under the [MIT licence](LICENSE-MIT).
