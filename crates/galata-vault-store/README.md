# galata-vault-store

Storage for a galata-vault server: the `Store` interface and its SQLite (WAL)
implementation, plus the journal records that keep revocations, rotations
and deletions durable.

Rows hold ciphertext, signatures, hashes, public keys and metadata. There is
no project, path, plaintext name or client address anywhere in the schema.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault) (its `embedded`
> feature uses this crate). The formats are specified in the repository's
> `docs/spec/`, and their stability promise lives there, not in this
> crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
