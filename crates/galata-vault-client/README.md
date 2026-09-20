# galata-vault-client

The galata-vault client transport: the layer the Rust SDK (`galata-vault`)
and the metadata-only MCP server (`galata-vault-mcp`) share.

- `Transport`: one method carrying the canonical request the protocol signs
  (method, path and query, preconditions, authorization, body). It names no
  HTTP-library type, so tests, proxies and in-process backends can implement
  it.
- `Api`: the typed operations over any `Transport`. It signs each request as
  the owner or a token holder and maps answers to typed results or an
  `ApiError` with the server's stable code.
- `ClientBuilder` and `HttpTransport` (feature `http`, default): ureq over
  rustls, no redirects, no proxy unless given (never from the environment),
  a 120-second timeout, and the bundled roots, given roots, or the platform
  verifier (feature `platform-verifier`).
- `Events`: expiry, progress and warnings go to the observer of the handle
  that made the request. Nothing is process-global, and nothing is printed.
- `RecordingTransport` (feature `test-util`).

This crate can sign requests and read metadata, never decrypt a value: it
links no `galata-vault-seal` or `age`, and `scripts/check-client-linkage.sh`
fails the build if it ever does. That is what lets `galata-vault-mcp` use it
and still be unable to return a secret.

> **Implementation detail of galata-vault.** No semver guarantee beyond the
> workspace version: applications depend on
> [`galata-vault`](https://crates.io/crates/galata-vault), which re-exports
> this crate as `galata_vault::client`. The formats are specified in the
> repository's `docs/spec/`, and their stability promise lives there, not in
> this crate's API.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

Licensed under the MIT licence.
