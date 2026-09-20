# galata-vault-proto

The shared vocabulary of the galata-vault protocol: string formats (`gvk1_`,
`gvt1_`, paths), the framing convention, API types, descriptors, record
contexts, proof of work and audit-chain hashing.

Every galata-vault crate links this one, so it can never decrypt: it holds
no private key and depends on no cipher. It parses, checks checksums, hashes
audit rows and verifies Ed25519 signatures.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault). The formats are
> specified in the repository's `docs/spec/`, and their stability promise
> lives there, not in this crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
