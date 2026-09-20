# Architecture

galata-vault is an end-to-end-encrypted secrets and config service with no
accounts: a project is a key, environments are a one-way key tree, and each
node of the tree is one vault on a server. Clients encrypt, sign and verify
everything; the server stores ciphertext and public keys and checks
signatures, and cannot decrypt because no code in its build can. The same
server rules also run in-process, over a data directory, for an application
that needs no server.

This is a map, not a manual. The protocol is specified in
[docs/spec/](docs/spec/README.md); what each actor can and cannot do is in
[docs/threat-model.md](docs/threat-model.md).

## Codemap

Client side, bottom to top:

- **`crates/galata-vault-proto`**: the shared vocabulary of the protocol. String
  formats (`gvk1_`, `gvt1_`, paths), the framing convention and the label
  registry, every request and response body, descriptors, record contexts,
  the audit chain, proof of work, and Ed25519 verification. Holds no private
  key and cannot sign or decrypt. Depends on nothing in the workspace. Start
  at `src/api.rs` and `src/frame.rs`.
- **`crates/galata-vault-keys`**: key material that is not a secret value. The key
  tree, owner, token and writer keys, owner-signed bundles (sealed boxes),
  the name key and the children record. Cannot decrypt a value. Depends on
  `galata-vault-proto`. Start at the diagram in `src/lib.rs`, then `src/bundle.rs`.
- **`crates/galata-vault-seal`**: the only crate that can read a secret value. age v1
  envelopes, signed records, and the rotation batch. Depends on `galata-vault-proto` and
  `galata-vault-keys`. Start at `src/envelope.rs` and `src/record.rs`.
- **`crates/galata-vault-client`**: the client transport. The `Transport` seam, the
  typed `Api` that builds and signs every canonical request, and the HTTP
  transport (feature `http`). Links no value decryption. Depends on `galata-vault-proto`
  and `galata-vault-keys`. Start at `src/transport.rs`, then `src/api.rs`.
- **`crates/galata-vault`**: the Rust SDK. `Vault` (the token client),
  `owner` (projects, environments, kits, tokens, rotation, rekey, audit),
  pins against rollback, and, with feature `embedded`, an in-process backend
  over `galata-vault-server-core`. Depends on `galata-vault-client`, `galata-vault-proto`, `galata-vault-keys`,
  `galata-vault-seal` (and `galata-vault-server-core`, `galata-vault-store` with `embedded`). Start at
  `src/vault.rs` (`Handle`), then `src/token.rs` and `src/owner/`.
- **`crates/galata-vault-cli`**: the `gv` command and the `gv ui` local UI, as a
  library another binary can brand. Built on the SDK. Start at `src/cli.rs`
  and `src/context.rs`.
- **`crates/gv-py`**: the Python package: a binding of the SDK, the bundled
  `gv`, and the private `_vectors` runner. Start at `src/lib.rs` and
  `python/galata_vault/__init__.py`.
- **`crates/galata-vault-mcp`**: the metadata-only MCP server, over `galata-vault-client`. Holds
  only `meta` tokens. Start at `src/tools.rs` and `src/env.rs`.

Server side, bottom to top:

- **`crates/galata-vault-store`**: the `Store` trait and its SQLite implementation.
  Ciphertext, hashes and public keys only; audit rows are appended in the
  same transaction as the action. Depends on `galata-vault-proto`. Start at `src/lib.rs`.
- **`crates/galata-vault-server-core`**: every rule the server enforces, as a
  synchronous library: authentication on the canonical request, the scope
  matrix, quotas, preconditions, critical operations through the journal,
  replay, the capabilities document, and the route table. Depends on
  `galata-vault-proto` and `galata-vault-store` only. Start at `src/lib.rs` (`Core::call`) and
  `src/route.rs` (`ROUTES`).
- **`crates/galata-vault-server`**: the HTTP server, an axum shell over the core:
  response hygiene, the loopback and TLS-proxy rule, and `local` mode. One
  build, with no feature that changes what it enforces. Start at `src/lib.rs`
  (`router`) and `src/main.rs`.

Tests and tools:

- **`crates/gv-adversary`**: the malicious-server harness: a real server
  behind a scriptable proxy that forges, replays and rolls back. The SDK,
  `gv`, `gv-mcp` and the Python package are run against it.
- **`crates/gv-conformance`**: the black-box conformance suite for servers
  (unpublished): numbered cases that cite the spec, run against any server
  URL or the embedded backend.
- **`scripts/vectors/`**: an independent Python implementation of the
  protocol that generates `testdata/vectors/v1/`. It shares no code with the
  crates.

## The layer rule

Each crate depends only on the crates below it in its column:

```text
client:  galata-vault-proto → galata-vault-keys → galata-vault-seal → galata-vault-client → galata-vault → galata-vault-cli, gv-py
                              (galata-vault-mcp uses galata-vault-client, never galata-vault-seal)
server:  galata-vault-proto → galata-vault-store → galata-vault-server-core → galata-vault-server
```

`galata-vault` with `embedded` is the one place the columns meet: the SDK
links `galata-vault-server-core` and `galata-vault-store` to serve itself in-process, and still
reaches vault state only through signed canonical requests to the core.

## Invariants, as absences

Each of these is a fact about the resolved dependency graph or the protocol,
and each has a check that fails when it stops being true.

- **The server cannot decrypt.** `galata-vault-server-core` and `galata-vault-server`
  link none of `galata-vault-keys`, `galata-vault-seal`, `age`, `crypto_box` or
  `x25519-dalek`, at any depth. `scripts/check-server-linkage.sh`.
- **The core has no runtime.** `galata-vault-server-core` links no `axum`, `hyper`,
  `tokio` or `aws-sdk-s3`, and `galata-vault-server` links no S3 client.
  `scripts/check-server-linkage.sh`.
- **The MCP server cannot read or write a value.** `galata-vault-mcp` links no
  `galata-vault-seal` or `age`, and its tokens' bundles hold only the name key.
  `scripts/check-mcp-linkage.sh`; the MCP tests.
- **The client transport cannot decrypt, and leaves its host alone.**
  `galata-vault-client` links no `galata-vault-seal`, `age`, `keyring`, `rlimit`, `rpassword`,
  `clap` or `pyo3`. `scripts/check-client-linkage.sh`.
- **The SDK leaves its host alone.** `galata-vault` links no keychain,
  process-limit, prompt, CLI, Python, HTTP-server or async-runtime crate, and
  cargo refuses to publish it. `scripts/check-sdk-linkage.sh`.
- **Nothing on the wire derives a box key.** A token signs requests with
  `token_auth`; `token_box`, which opens its bundle, is derived from the
  token secret, which is never sent and never stored by the server
  (`docs/spec/keys.md#6`). The adversarial harness checks a full capture.
- **`galata-vault-proto` holds no private key.** It verifies signatures and cannot sign
  or decrypt; signing keys live in `galata-vault-keys`, decryption in `galata-vault-seal`.
- **Every derivation label is registered.** `scripts/check-spec-labels.sh`
  compares the label literals in `galata-vault-proto`, `galata-vault-keys` and `galata-vault-seal` with the
  registry in `docs/spec/keys.md#3`.
- **Responses tolerate what requests refuse.** No response type refuses an
  unknown field (the audit row excepted), and every request type does;
  `galata-vault-proto`'s `every_response_tolerates_an_unknown_field` and
  `requests_refuse_unknown_fields` tests.

Every guard has a `plant` mode that injects its own violation;
`scripts/test-guards.sh` proves each one fails when planted.

## Cross-cutting ideas

- **One canonical request.** A request is its method, path and query,
  preconditions, authorization and body; the signature covers exactly those.
  The HTTP transport, the embedded transport and the core all see the same
  bytes, so there is one authentication path and no trusted shortcut.
- **One route table.** `galata_vault_server_core::ROUTES` routes every call the core
  serves, builds `galata-vault-server`'s own routes, and is compared with the endpoint
  table of `docs/spec/http-api.md#2` by a test.
- **The `Transport` seam.** Everything the SDK, `gv`, the Python package and
  the MCP server send goes through `galata_vault_client::Transport`: HTTP, the embedded
  backend, a recording transport in tests, or the adversary's proxy.
- **Pinned identities.** Every client pins a vault id (derived from its key,
  or carried in its token) and verifies the owner key, the descriptor, its
  bundle and every record from it. The server is not trusted with anything
  it could forge.

## Where the checks live

| What | Where | Run by |
|---|---|---|
| The specification | `docs/spec/` | read; its tables and labels are checked by the guards and tests above |
| Byte-level test vectors | `testdata/vectors/v1/`, generated by `scripts/vectors/generate.py` | `tests/vectors.rs` in `galata-vault-proto`, `galata-vault-keys`, `galata-vault-seal`, `galata-vault`; `crates/gv-py/tests/test_vectors.py`; CI regenerates and diffs them |
| age implementation cross-check | `testdata/cctv/age/` (C2SP CCTV) | the generator, before it writes anything |
| Server behaviour | `crates/gv-conformance` | CI, against `gv-server local` and the embedded backend |
| Client behaviour against a hostile server | `crates/gv-adversary` | the `adversary` tests of the SDK, `gv`, `gv-mcp`; the Python suite |
| Everything at once | `scripts/check-all.sh` | CI and locally |
