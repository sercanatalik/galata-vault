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

One published crate, `galata-vault`, whose modules are what used to be ten
crates. Each is behind the feature named beside it in
[README.md](README.md#one-crate-and-what-is-in-it); paths below are relative
to `crates/galata-vault/src/`.

Client side, bottom to top:

- **`proto`**: the shared vocabulary of the protocol. String
  formats (`gvk1_`, `gvt1_`, paths), the framing convention and the label
  registry, every request and response body, descriptors, record contexts,
  the audit chain, proof of work, and Ed25519 verification. Holds no private
  key and cannot sign or decrypt. Depends on nothing in the workspace. Start
  at `src/api.rs` and `src/frame.rs`.
- **`keys`**: key material that is not a secret value. The key
  tree, owner, token and writer keys, owner-signed bundles (sealed boxes),
  the name key and the children record. Cannot decrypt a value. Depends on
  `proto`. Start at the diagram in `src/lib.rs`, then `src/bundle.rs`.
- **`seal`**: the only crate that can read a secret value. age v1
  envelopes, signed records, and the rotation batch. Depends on `proto` and
  `keys`. Start at `src/envelope.rs` and `src/record.rs`.
- **`client`**: the client transport. The `Transport` seam, the
  typed `Api` that builds and signs every canonical request, and the HTTP
  transport (feature `http`). Links no value decryption. Depends on `proto`
  and `keys`. Start at `src/transport.rs`, then `src/api.rs`.
- **the crate root**: the Rust SDK. `Vault` (the token client),
  `owner` (projects, environments, kits, tokens, rotation, rekey, audit),
  pins against rollback, and, with feature `embedded`, an in-process backend
  over `server_core`. Depends on `client`, `proto`, `keys`,
  `seal` (and `server_core`, `backend` with `embedded`). Start at
  `src/vault.rs` (`Handle`), then `src/token.rs` and `src/owner/`.
- **`cli`**: the `gv` command and the `gv ui` local UI, as a
  library another binary can brand. Built on the SDK. Start at `src/cli.rs`
  and `src/context.rs`.
- **`crates/gv-py`**: the Python package: a binding of the SDK, the bundled
  `gv`, and the private `_vectors` runner. Start at `src/lib.rs` and
  `python/galata_vault/__init__.py`.
- **`mcp`**: the metadata-only MCP server, over `client`. Holds
  only `meta` tokens. Start at `src/tools.rs` and `src/env.rs`.

Server side, bottom to top:

- **`backend`**: the `Store` trait and its SQLite implementation.
  Ciphertext, hashes and public keys only; audit rows are appended in the
  same transaction as the action. Depends on `proto`. Start at `src/lib.rs`.
- **`server_core`**: every rule the server enforces, as a
  synchronous library: authentication on the canonical request, the scope
  matrix, quotas, preconditions, critical operations through the journal,
  replay, the capabilities document, and the route table. Depends on
  `proto` and `backend` only. Start at `src/lib.rs` (`Core::call`) and
  `src/route.rs` (`ROUTES`).
- **`server`**: the HTTP server, an axum shell over the core:
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

Modules depend only on what is below them in their column, and the features
are what make that checkable:

```text
client:  proto → keys → seal → client → the crate root → cli, gv-py
                        (mcp uses client, never seal)
server:  proto → backend → server_core → server
```

`sdk` is the feature that turns on the client column; `server` turns on the
server column and does **not** enable `sdk`. So a server build has no value
or name crypto compiled into it at all, and cannot grow any by accident: the
code is not there to call.

`embedded` is the one place the columns meet: the SDK links `server_core` and
`backend` to serve itself in-process, and still no HTTP server, runtime or
S3 client.

Inside one crate the compiler cannot enforce the columns the way ten crates
did -- a `#[cfg]` could widen them. [`scripts/check-linkage.sh`](scripts/check-linkage.sh)
is what replaces it: it reads the dependency graph per feature set, and it
reads the source for a serving module that names `crate::keys`, `crate::seal`
or `crate::client`. Both halves fail the build.
