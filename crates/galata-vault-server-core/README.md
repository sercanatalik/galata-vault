# galata-vault-server-core

The rules of a galata-vault server, as a synchronous library: request
authentication, the scope matrix, quotas, record versions and preconditions,
vault creation and token registration, revocation, rotation and deletion
through the journal, and journal replay.

Two transports reach it: the HTTP server (`galata-vault-server`) and the
SDK's in-process backend (`galata-vault`, feature `embedded`). It links no
HTTP stack, no async runtime and no decryption code, and a guard in the
repository fails the build if that changes.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault). The formats are
> specified in the repository's `docs/spec/`, and their stability promise
> lives there, not in this crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
