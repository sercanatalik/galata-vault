# galata-vault-keys

Client-side key material that is not a secret value: the project and environment key tree (one-way HKDF), owner signing and
box keys, token keys, writer keys, owner-signed bundles, and the name key
that indexes and encrypts record names.

This crate cannot decrypt a secret value: values are age ciphertext, and age
lives in `galata-vault-seal`. The metadata-only MCP server links this crate
and not that one, and a guard in the repository fails the build if that
changes.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault). The formats are
> specified in the repository's `docs/spec/`, and their stability promise
> lives there, not in this crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
