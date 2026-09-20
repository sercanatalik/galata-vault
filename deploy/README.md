# Running a server

`gv-server` stores ciphertext, signatures and public keys, and cannot read
any of it: the binary links no decryption code, and
`scripts/check-server-linkage.sh` fails the build if it ever does. That is
what makes running one a modest undertaking — an operator who reads every
byte on the disk learns names' HMACs, sizes and times, and no secret value.
The [threat model](../docs/threat-model.md) says exactly what an operator
can and cannot do; read it before you decide what this server is worth
protecting.

> galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.

## Your own machine

Nothing here is needed:

```sh
gv-server local        # http://127.0.0.1:8750, data in ~/.local/share/galata-vault
```

Local mode takes no configuration file, listens on loopback only, and asks
nothing of its callers. `gv-server local --print-service launchd` (or
`systemd`) prints a user service definition to adapt.

This page is for the other case: a server that machines other than yours
reach.

## What this build does not do

Read this before planning a deployment, because it decides the shape of one.

There is **one build**, with no feature that changes what it enforces. It
authenticates every request and enforces the per-vault quotas. It does not
implement proof of work, rate limiting, or idle expiry. Those controls are
specified — clients understand them, and
[docs/spec/hosted.md](../docs/spec/hosted.md) is their appendix — but no
server in this repository implements them.

So a configuration naming one is **refused at startup, by name**, rather
than started with the control silently ignored:

| Setting | Startup |
|---|---|
| `profile` (any value, `"hosted"` named specially) | refused |
| `production = true` | refused |
| `pow_difficulty` greater than 0 | refused |
| `idle_expiry_days` greater than 0 | refused |
| `[rate_limits]` | refused |
| `[journal] kind = "s3"` | refused |

Zero counts as "none" for the two numeric settings, so a configuration that
only ever switched them off still starts.

**Everything that admission control would have done, the proxy in front must
do.** Anyone who can reach the server can attempt to create vaults, limited
only by the quotas.

## The shape of a deployment

```
   clients ──TLS──▶  proxy (terminates TLS, rate-limits, IP-filters)
                       │  plain HTTP over loopback
                       ▼
                     gv-server  listen = 127.0.0.1:8750
                       │
                       ├── database  (SQLite)
                       └── journal   (a directory beside it)
```

`gv-server` serves no TLS itself. It **refuses to start on a non-loopback
address** unless `behind_tls_proxy = true` says something in front is
terminating TLS. Setting that flag while nothing does means plaintext on the
wire: the signatures still protect request integrity, but the proxy is what
makes the connection private.

## The configuration

```toml
# gv-server --config /etc/galata-vault/server.toml
# (or set GV_SERVER_CONFIG)

listen = "127.0.0.1:8750"    # default; non-loopback needs behind_tls_proxy
database = "/var/lib/galata-vault/vault.db"

# Only when a proxy really terminates TLS in front.
behind_tls_proxy = true

# Name this server and its version in GET /v1/capabilities. Off by default:
# no client needs it, and it helps anyone fingerprinting the deployment.
advertise_version = false

# Running under `litestream replicate -exec`.
litestream = false

[journal]
kind = "file"
dir = "/var/lib/galata-vault/journal"

# Optional. Unset, the quotas below are the defaults.
[limits]
max_names = 200
max_value_bytes = 16384
max_versions = 20
max_vault_bytes = 4194304
max_tokens = 128
max_configs = 64
max_config_bytes = 262144
max_config_versions = 20
```

A typo inside `[journal]` is refused rather than ignored, and so is an
unknown field anywhere in the file.

`max_body_bytes` is derived from the quotas — the largest rotation batch a
full vault can produce — and setting it below what the quotas require is
refused, naming both numbers.

## Before the first start

```sh
gv-server check --config /etc/galata-vault/server.toml
```

That validates the configuration, opens the journal and round-trips a probe
through it, then exits. Run it before the first start and after every
change: it catches a bad journal path while nothing is serving.

## The journal, and what durability you actually have

The file journal is a directory beside the database. It undoes a restored
*older copy* of the database — the rollback the protocol's audit chain lets
a client detect — but it **does not survive the loss of the disk**, because
it is on that disk. `gv-server local` says so at startup, in a warning.

If the data matters, the disk needs replication underneath: `litestream`
(set `litestream = true` when running under `litestream replicate -exec`) or
snapshots of the volume. Losing the database loses the vaults; there is no
account system and no recovery path on the server side, by design. Owners
hold their own keys, and a vault's contents cannot be reconstructed from
anything the server has.

## Data directory permissions

The data directory must be `0700`. The server and the embedded backend both
refuse a more permissive one rather than serve from it, so create it with
the mode set:

```sh
install -d -m 700 -o galata-vault -g galata-vault /var/lib/galata-vault
```

## Operating notes

- **Run it as its own unprivileged user**, owning only the data directory.
- **Back up the database and the journal together**, from the same moment. A
  journal older than the database is worse than none.
- **Watch the disk.** The quotas bound a single vault, not how many vaults
  exist; nothing here limits vault creation.
- **The logs name no secrets** — no values, no token strings, no record
  names in clear. They do carry vault ids and record name HMACs.
- **Upgrading** is replacing the binary and restarting. Formats may change
  before 1.0; read [CHANGELOG.md](../CHANGELOG.md) before upgrading, and
  check [docs/spec/stability.md](../docs/spec/stability.md) for what a
  format marker guarantees.

## Checking a server is honest

A server is not trusted by clients, and you can hold your own to the same
standard. The conformance suite runs the protocol against any server:

```sh
scripts/conformance.sh          # a local gv-server, then the embedded backend
```

`cargo run -p gv-conformance -- --server <url>` runs it against a deployed
one. It creates and deletes its own vaults, so point it at a server you are
willing to write to.
