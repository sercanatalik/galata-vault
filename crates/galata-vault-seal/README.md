# galata-vault-seal

The only galata-vault crate that can read a secret value: age v1 encryption
to a generation descriptor's public keys, decryption with a generation's
private keys, writer-signed records, and the rotation batch that re-encrypts
a whole vault.

Client-only. The server, the archive and the MCP server never link it, and
the linkage guards in the repository fail the build if one does.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault). The formats are
> specified in the repository's `docs/spec/`, and their stability promise
> lives there, not in this crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
