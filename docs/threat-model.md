# galata-vault threat model

This document states, for each party that could attack a galata-vault user,
what that party can do, what it cannot, and what enforces each limit:
**cryptography** (a key the party does not hold, a signature it cannot make,
a binding it cannot change) or **server policy** (a rule an honest server
applies, which a dishonest one may not). Phase 5's external review packet
builds on it. Every security claim in the README must trace to a row here
(see the last section).

The protocol it describes is specified in [docs/spec/](spec/README.md). Where
this document and the specification disagree, the specification wins.

## Assumptions

- A client is not compromised while it is unlocked: the machine running `gv`,
  the SDK or the Python package, and the process itself, are the user's.
- The primitives hold: Ed25519, X25519, HKDF-SHA256, HMAC-SHA256, SHA-256,
  BLAKE3, ChaCha20-Poly1305, XChaCha20-Poly1305, XSalsa20-Poly1305 (sealed
  boxes) and age v1.
- Honest users keep their node keys and token strings to themselves.
- Clients keep the state the protocol asks them to keep (descriptor and
  version pins, audit heads) where the protection says it depends on it.

## Actors

### An active malicious server

Includes a dishonest operator, anyone who controls the server's machine, and
another process answering on the port a client uses (for `gv-server local`,
the local port).

| | What | Enforced by |
|---|---|---|
| can | withhold or delete any vault, record, row or the whole service | nothing (availability is out of scope) |
| can | see the residual metadata below | nothing |
| can | show a client that keeps no state an old but correctly signed record, generation or audit history | nothing without client state (see "Rollback and fork") |
| can | show different clients different, individually consistent audit histories | nothing without an external witness |
| can | ignore every server-policy limit: the `read` allow-list, TTLs, expiry, revocation before rotation, quotas, rate limits | these are server policy |
| can | refuse to serve, answer errors, or claim capabilities it does not have (claiming not to speak protocol version 1 makes clients refuse it) | nothing |
| cannot | read a value, a config body or a record name | cryptography: values are age ciphertext to keys in owner-signed bundles; names are XChaCha20-Poly1305 under the name key (`records.md#3`, `keys.md#8`) |
| cannot | substitute a vault or config public key, or a writer key | cryptography: every key comes from a descriptor signed by the owner key, which hashes to the vault id the client pinned (`records.md#1`, `protocol.md#4`) |
| cannot | forge a bundle, or move a token's bundle to another token, scope or generation | cryptography: the owner signs vault, token, scope and generation, and the plaintext repeats them (`records.md#2`) |
| cannot | forge a record or tombstone, or move one between vaults, generations, names, versions or kinds | cryptography: the writer signature binds all of them, and the decrypted envelope repeats them (`records.md#3`, `records.md#4`) |
| cannot | forge the children record, or redirect an environment | cryptography: only the owner signs it (`records.md#5`) |
| cannot | roll back a record, generation or audit history past what a client has pinned | client state: pins and heads (`protocol.md#12`, `audit.md#5`) |
| cannot | derive any key from what clients send | cryptography: requests are signed, and no request carries a key or the token secret (`signatures.md#2`, `keys.md#6`) |
| cannot | impersonate the owner, mint a token, rotate, or claim a vault id | cryptography: all need the owner signing key; the vault id is its hash |

### A TLS terminator or a log reader

Anyone who sees requests and responses in the clear: a reverse proxy, a CDN,
a request log, a packet capture after TLS.

| | What | Enforced by |
|---|---|---|
| can | see everything the server sees in transit: ciphertext, signatures, public keys, name indexes, metadata | nothing |
| can | delay or drop a request, or deliver a withheld request itself, once, within the ±300 s skew window | nothing beyond the window |
| cannot | decrypt anything, or derive a key | cryptography: no credential that decrypts crosses the wire (`signatures.md#2`) |
| cannot | replay a request | server policy: each signature's nonce is spent once, within the skew window (`signatures.md#2.3`) |
| cannot | alter a request's method, path, query, preconditions or body | cryptography: the signature covers them |
| cannot | find a credential in a URL | server policy: credentials in a query string are refused unprocessed (`http-api.md#4.1`) |

### A stolen database dump or backup

Includes the SQLite database, the journal, and any backup of the data
directory.

| | What | Enforced by |
|---|---|---|
| can | see ciphertext, sealed bundles, public keys, descriptors, name indexes, audit rows, spent nonces and the residual metadata | nothing |
| cannot | decrypt a value, a name or a bundle | cryptography: no private key is stored |
| cannot | authenticate as a token or an owner | cryptography: the server stores only `auth_pub` and `owner_sign_pub`; no token secret or secret hash |
| cannot | derive a token's box key | cryptography: it derives only from the token secret (`keys.md#6`) |
| cannot | undo an acknowledged revocation, rotation or deletion by restoring an older copy on the same server | server policy: the journal is replayed before anything is served |

### An `append` token holder

Holds the name key and both writer keys of the current generation.

| | What | Enforced by |
|---|---|---|
| can | create, update and delete secrets and configs, with valid writer signatures | cryptography: it holds the secret and config writer keys |
| can | list names and decrypt them, and read history metadata, audit and status | cryptography: it holds the name key |
| cannot | read a value or a config body | cryptography: its bundle has no vault or config private key (`records.md#2.2`) |
| cannot | write the children record, a descriptor or a bundle; mint, rotate, rekey or delete | cryptography: all need the owner signing key |
| cannot | read records through the API | server policy: the server refuses its reads (it could not decrypt them anyway) |
| cannot | be attributed a write cryptographically, as against another writer-key holder | writer keys are per generation per kind, not per token; the audit row names the authenticated token (server policy) |
| after revocation without rotation | keeps its writer keys, whose signatures still verify in the current generation | revocation is forward-only; the server refuses its requests (policy); rotation cuts it off (cryptography) |

### A `config` token holder

Holds the name key and the config private key.

| | What | Enforced by |
|---|---|---|
| can | read configs, list names, history, audit and status | cryptography: config key and name key |
| cannot | decrypt a secret | cryptography: its bundle type has no field for the vault key |
| cannot | write anything | cryptography: it holds no writer key |

### A `config-write` token holder

Holds the name key, the config private key and the config writer key.

| | What | Enforced by |
|---|---|---|
| can | read, create, update and delete configs | cryptography: config key and config writer key |
| cannot | read or write a secret | cryptography: no vault key, and secret records verify only against the secret writer key (`records.md#4`) |
| cannot | write the children record, descriptors or bundles | cryptography: owner key only |

### A `meta` token holder, including the MCP server

Holds the name key only. `gv-mcp` holds only `meta` tokens.

| | What | Enforced by |
|---|---|---|
| can | list and decrypt names, and read history metadata, audit and status; verify record signatures from their hashes | cryptography: name key; public descriptor |
| cannot | read or write a value or a config | cryptography: its bundle holds the name key only; `gv-mcp` refuses a bundle that holds more, and links no value decryption (`scripts/check-mcp-linkage.sh`) |
| cannot | learn names of environments it holds no token for | cryptography: each vault has its own name key |
| cannot | tell the server that two environments are related by comparing them | protocol: `diff_envs` compares on the client, from independent requests |

### `read` and `admin` token holders

| | What | Enforced by |
|---|---|---|
| `read` can | read every secret and config of the generation | cryptography: vault and config private keys |
| `read` cannot | read a secret outside its allow-list through the API | server policy only: it holds the vault key |
| `read` cannot | write anything | cryptography: no writer key |
| `admin` can | read and write secrets and configs, list tokens, revoke without rotating | cryptography for the keys (every key of the generation); server policy for token listing and revocation |
| `admin` cannot | mint, rotate, rekey, write the children record or delete the vault | cryptography: owner signing key only |

### Another process running as the same local user

| | What | Enforced by |
|---|---|---|
| can | read and change `gv-server local`'s or an embedded application's data directory, open `vault.db`, and so bypass scopes, quotas, the allow-list and audit | nothing: file permissions stop other users, not this one |
| can | usually read the user's node keys and tokens: from the OS keychain where the platform lets any process of the user read it, from token files, kits and `gv`'s configuration, or by attaching to a client process | the operating system; typically nothing |
| can | then act as the owner of every project whose key it reads | nothing: holding the key is ownership |
| can | answer on the local port in place of `gv-server local` | nothing: it is then a malicious server (above) |
| cannot | forge anything a client verifies without a key it can read | cryptography: pinned vault ids and signatures bind it as they bind a malicious server |

This actor is close to "a compromised unlocked client", which is out of scope:
the protections that remain are those against a malicious server, and they
last only while the process cannot read the user's keys.

### A network attacker

| | What | Enforced by |
|---|---|---|
| can | observe traffic volume and timing to the server | nothing |
| can | block or delay traffic | nothing |
| cannot | read or change requests | TLS, which clients require for any non-loopback server (`http://` only to loopback) |
| cannot | redirect a client to another server | clients follow no redirect, and a project's server URL is pinned in its kit and local state |
| cannot | forge or replay anything, even with a server it controls | cryptography, as against a malicious server |

## Out of scope

- A compromised client while it is unlocked, including malware running as
  the user (see the same-user row).
- Side channels on the client host: timing, cache, power, swap and core
  dumps beyond what the CLI already limits.
- Availability against a malicious server or network.
- Post-quantum attackers: X25519 and Ed25519 throughout.
- The local UI's browser-side risks, which have their own review
  (`docs/local-ui.md`).

## Residual metadata

End-to-end encryption hides contents, not everything. The server, or anyone
with its data, sees:

- how many vaults exist, and each one's size, number of names and versions,
  and write and read times;
- how many config documents each vault holds, with each one's ciphertext
  size and number of versions (configs and secrets are stored apart, so they
  can be told apart);
- token ids, scopes and expiry times, and which token touched which record
  index and version (the audit chain);
- name indexes, stable within a generation, so repeated access to the same
  record is visible, though not which record it is.

It can infer:

- which vaults belong to one project, from creation timing and addresses;
- client addresses, which the server writes to no database, log or metric. A
  TLS terminator's logs are the operator's own.

## Rollback and fork attacks that remain without an external witness

The audit chain is computed by the server with no key, and the protocol has
no external witness. So:

- A server can show a client that keeps no state an old, internally
  consistent history: an older generation, an older version of a record, a
  shorter audit chain. Every signature on it verifies.
- A server can fork: show different clients different, individually
  consistent histories. Neither detects it unless they compare heads.
- A server can withhold rows or records: not serve the latest write, or any
  write, to some clients.
- Detection is only relative to state a client kept: its descriptor pin
  (generation and hash), its per-name version pins, and its audit head. `gv`
  keeps them in `state.toml`; the SDKs detect rollback only when the caller
  persists and passes them back. A client that loses that state loses the
  protection.
- An old but correctly signed record is still an authentic record of that
  version: a server cannot make up a value, only choose which authentic one
  to show.

## Limits that are server policy only

- the `read` token allow-list;
- token lifetimes, and vault idle expiry;
- revocation before the next rotation (a revoked holder may keep keys it
  already unwrapped, and writer signatures it can make still verify until
  the vault rotates);
- quotas and rate limits;
- the uniform 401, which hides whether a vault or token exists;
- scope checks on reads by holders that could not decrypt the result anyway.

## README claims and the rows behind them

| README claim | Supported by |
|---|---|
| "The server stores only ciphertext, and everything you rely on from it is signed by keys it does not hold." | malicious server: cannot read, substitute, forge or move; stolen dump: cannot decrypt |
| The server cannot decrypt, substitute a key, forge a record or rewrite the tree unnoticed. | malicious server rows; tree: the children record row |
| The server build cannot link decryption code. | stolen dump and malicious server rows; ARCHITECTURE.md invariants (`scripts/check-server-linkage.sh`) |
| The MCP server cannot read or write values. | `meta` and MCP rows |
| Names are hidden too. | malicious server: cannot read a record name; residual metadata (indexes are visible) |
| The audit chain is verified by the client against the last head it saw. | malicious server: cannot roll back past a pinned head; "Rollback and fork" for what remains |
| Environments are a one-way key tree; a subtree's key gives nothing above it. | not an actor limit: the key schedule (`docs/spec/keys.md#4`); a delegation-kit holder is the owner of its subtree, and of nothing above it |
| A request log or the TLS terminator holds nothing that decrypts. | TLS terminator or log reader rows |
| A `meta`, `read` or `config` token cannot produce a valid write, a `config-write` token cannot produce a valid secret, and an `append` token cannot redirect an environment: by cryptography. | `meta`, `read`, `config`, `config-write` and `append` rows |
| Revocation is forward-only; rotation is the cut-off. | `append` row "after revocation"; "Limits that are server policy only" |
| A leaked token can be revoked without sending it. | TLS terminator: nothing on the wire derives a key; `docs/spec/signatures.md#7` |
| An older copy of the database cannot bring back a revoked token, undo a rotation or revive a deleted vault. | stolen dump: journal replay (server policy) |
| Client IP addresses are held only in memory, and only by a public instance's rate limiter. | residual metadata |
| Threat table: disk, backups or journal leak; request logs or TLS terminator leak; malicious operator or port squatter; token leak; project key leak; compromised unlocked laptop out of scope. | stolen dump; TLS terminator; malicious server and same-user rows; token-holder rows; same-user row (holding the key is ownership); out of scope |
| What the protocol does not do: prevent a fork or withholding; enforce by cryptography the allow-list, TTLs and expiry, revocation before rotation, or quotas; hide metadata. | "Rollback and fork"; "Limits that are server policy only"; residual metadata |
