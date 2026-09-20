# galata-vault-server

The galata-vault HTTP server, `gv-server`: an axum shell over
`galata-vault-server-core` that serves the protocol under `/v1`. It stores
ciphertext, signatures and public keys, and it cannot read any of it: the
binary links no decryption code, and a guard in the repository fails the
build if it ever does.

> galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.

## Install

After 0.1.0 is published:

```sh
cargo install galata-vault-server      # the gv-server binary
```

## Run it on your machine

```sh
gv-server local        # http://127.0.0.1:8750, data in ~/.local/share/galata-vault
```

Local mode needs no configuration file, listens on loopback only, and asks
nothing of its callers: no proof of work, no rate limits, no idle expiry.
`gv-server local --print-service launchd` (or `systemd`) prints a user
service definition. Serving other machines needs a configured server behind
a TLS-terminating proxy: see `deploy/README.md` in the repository.

## What it asks of its callers

Nothing beyond the protocol. There is one build, with no feature that
changes what it enforces: it authenticates every request, enforces the
per-vault quotas, and admits everything else. It requires no proof of work,
rate-limits nothing, and never deletes a vault for inactivity. A
configuration naming `pow_difficulty`, `idle_expiry_days`, `[rate_limits]`,
an S3 journal, `production` or `profile` is refused at startup, naming the
setting, rather than started with the control ignored.

A server that callers you do not trust can reach belongs behind a proxy that
terminates TLS and limits requests.

The library half (`galata_vault_server`) exposes the router and state for
tests and embedding; it follows the workspace version with no separate
semver promise.

Licensed under the MIT licence.
