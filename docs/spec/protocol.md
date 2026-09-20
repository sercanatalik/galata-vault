# Protocol flows

Status: **draft** (docs/spec/README.md#1).

How clients and a server use the formats of the other documents: creating a
vault, minting and registering tokens, opening, reading, writing, listing,
rotating, rekeying, rediscovering and revoking. Endpoints and status codes
are in http-api.md; bytes in formats.md, keys.md and records.md; signatures
in signatures.md.

<a id="1"></a>
## 1. Roles and client state

- **Owner:** whoever holds a node key (keys.md#4). It derives the node's
  owner keys and vault id (keys.md#5), and holds every key of every
  generation through its owner bundle.
- **Token holder:** whoever holds a `gvt1_` token string (formats.md#2.4).
  The string names the token id, the vault id and the token secret; the
  holder derives `token_auth` and `token_box` (keys.md#6). Its scope decides
  which keys its bundle holds (records.md#2.2).
- **Server:** stores ciphertext, signatures and public keys, enforces
  scopes, preconditions and quotas, and computes the audit chain. It holds no
  key that opens anything it stores, and is not trusted with anything a
  client can verify.

A client MAY keep state between sessions, and a client that does detects
more (§12): for each vault, the descriptor generation and hash it verified,
the latest version of each record it read, and the last audit head it
verified. The SDKs let the caller supply and receive these pins.

<a id="2"></a>
## 2. Vault creation

1. The owner derives the node's owner keys and vault id (keys.md#5).
2. It fetches the server's capabilities once per API handle
   (http-api.md#6) and MUST refuse, sending nothing authenticated, a server
   whose `protocols` does not list `"1"` (`unsupported_protocol`).
3. If the capabilities set `proof_of_work`, or the server answered 404
   (older than the document), it obtains and solves a challenge
   (hosted.md#2); otherwise it sends none.
4. It generates generation 1's five keys (keys.md#7), a descriptor for
   generation 1 with a zero `prev_hash` (records.md#1), signs it, and seals
   and signs its own bundle (records.md#2).
5. It sends `POST /v1/vaults` with the vault id, both owner public keys, the
   signed descriptor, the owner bundle and any solved challenge, signed as
   the owner (signatures.md#2).

The server checks, in order: the admission (a solved, unspent, unexpired
challenge when it asks for proof of work); that the vault id is the hash of
the owner signing key (`vault_id_mismatch`); that the request is signed by
that key for that vault (the uniform 401); that the descriptor verifies for
the vault and is generation 1 with a zero previous hash; that the owner
bundle is owner-signed for generation 1; then it spends the challenge and
the nonce and stores the vault. A vault id that exists is `conflict`.

6. The owner then writes an empty children record at version 1
   (records.md#5), under `If-None-Match: *`.

Nobody else can create a vault at this id, even after it expires, because
the id is the hash of the owner's signing key. Conformance: the
"capabilities" and "vault lifecycle" cases (README.md#6).

<a id="3"></a>
## 3. Minting a token

1. The owner generates a random 16-byte token id and a random 32-byte token
   secret, and derives `token_auth` and `token_box` (keys.md#6).
2. It seals the bundle of the scope's kind (records.md#2.2) to the token's
   `token_box` public key and signs it for this vault, token id, scope and
   the current generation (records.md#2.4).
3. It sends `POST /v1/tokens`, owner-signed, with the token id, both public
   keys, the scope, the TTL, an optional allow-list, the generation and the
   signed bundle.
4. It shows the `gvt1_` string once.

The server MUST refuse a registration not signed by the owner (`forbidden`
for a token), a bundle whose owner signature does not verify for this token,
scope and generation (`bad_signature`), a generation that is not current
(`stale_generation`), an allow-list on any scope but `read`
(`invalid_request`), and a TTL above the scope's maximum (`ttl_too_long`). A
TTL of 0 takes the scope's default. Defaults and maximums:

| Scope | Default TTL | Maximum TTL |
|---|---|---|
| `admin` | 1 day | 30 days |
| every other scope | 90 days | 365 days |

The server stores the token id, scope, expiry, allow-list, both public keys
and the signed bundle. It never receives the token secret, and nothing it
stores derives `token_box`. A request body naming a scope the server does
not know is refused (`invalid_request`, http-api.md#7).

<a id="4"></a>
## 4. Opening a vault

<a id="4.1"></a>
### 4.1 As the owner

1. Capabilities, as in §2 step 2.
2. `GET /v1/vault`, owner-signed. The status MUST name the derived vault id,
   the owner's own signing and box public keys (`key_mismatch`).
3. The descriptor MUST verify from the derived vault id (records.md#1.4),
   and name the generation the status reports.
4. The owner bundle MUST open (records.md#2.5) and hold exactly the
   descriptor's keys.
5. The client applies its pins (§12).

<a id="4.2"></a>
### 4.2 As a token holder

1. The token string MUST parse, checksum first (formats.md#2.5), before any
   request.
2. Capabilities, as in §2 step 2.
3. `GET /v1/tokens/self`, token-signed. The answer MUST name this token and
   the vault id in the token string (`key_mismatch`).
4. A scope the client does not know means it cannot check the bundle's kind:
   it MUST refuse with `unsupported_by_client` (http-api.md#7).
5. The verification chain: the pinned vault id (from the token string) → the
   owner signing key, which MUST hash to it → the descriptor, which MUST
   verify (records.md#1.4) → the bundle, which MUST open for this token,
   scope and generation (records.md#2.5) → the keys, which MUST be the
   descriptor's.
6. The client applies its pins (§12).

Only after these steps may a client encrypt, verify or decrypt anything for
the vault.

<a id="5"></a>
## 5. Reading

1. The client computes the record's index (keys.md#8.1) and fetches
   `GET /v1/{secrets|configs}/{index}` (the latest version) or
   `…/{index}/versions/{version}`.
2. The served record MUST name the requested index, and, for a specific
   version, that version.
3. Its signature MUST verify against the descriptor's writer key for its
   kind (records.md#4), before any pin moves.
4. For the latest version, a version lower than the one the client last saw
   is a rollback (§12).
5. The client decrypts the name and checks it against the index
   (keys.md#8.3), then decrypts the value and checks every binding
   (records.md#3.3).

The server refuses a read by a scope that may not read the kind
(`forbidden`), and a `read` token's read of a secret outside its allow-list
(`forbidden`); both refusals are audited. A latest version that is a
tombstone is answered 404 `not_found`, with the tombstone's version as the
`ETag`. Every value read is audited with its version and ciphertext hash
(audit.md#1). The conformance case "server-side scope policy" (README.md#6)
checks the scope refusals.

<a id="6"></a>
## 6. Writing and deleting

Every write names the version it creates, and carries a precondition that
the request signature covers (signatures.md#2.1):

| Precondition | When | Signed version |
|---|---|---|
| `If-None-Match: *` | the name has never existed | 1 |
| `If-None-Match: *` | the latest version is a tombstone (a revival) | the tombstone's version + 1 |
| `If-Match: v` | the latest version is the live version `v` | `v + 1` |

- A write sends `PUT /v1/{secrets|configs}/{index}` with the name
  ciphertext, the age ciphertext, the generation, the version, the write time
  and the writer signature (records.md#4).
- A deletion sends `DELETE /v1/{secrets|configs}/{index}` with `If-Match: v`
  and a body carrying a signed tombstone for version `v + 1`.

The server MUST refuse, and store nothing for: a write without a
precondition (428 `precondition_required`); both preconditions, or
`If-None-Match` other than `*`, or a delete under `If-None-Match`
(`invalid_request`); a failed precondition (412 `precondition_failed`); a
signed version other than the one it would assign (409 `version_mismatch`);
a generation other than the current one (409 `stale_generation`); a value
that is not age v1 (`not_age_ciphertext`); a record whose signature does not
verify against the current descriptor (`bad_signature`); and a write over a
quota (`value_too_large`, `name_quota_exceeded`, `vault_quota_exceeded`,
`config_too_large`, `config_quota_exceeded`). Refused authenticated writes
are audited as `refused`. A successful write answers with the new version,
also as the `ETag`. A client whose write fails its precondition MUST NOT
retry it blindly: another writer won, and nothing was overwritten.
Conformance: "a write without a precondition is 428", "failed preconditions
are 412" and "a signed version other than the assigned one" (README.md#6);
`testdata/vectors/v1/signatures.json` covers the signed preconditions.

<a id="7"></a>
## 7. Listing and history

- `GET /v1/{secrets|configs}?limit=<n>&after=<index>` lists the latest
  version of each name, ordered by index, at most 500 per page (100 by
  default). A page is full when it holds `limit` items, and then carries
  `next_cursor`, the last index, to pass as `after`. Each item carries the
  name index, name ciphertext, version, write time, ciphertext size,
  tombstone flag, generation, `value_ct_hash` and signature. Every scope may
  list.
- `GET /v1/{secrets|configs}/{index}/versions` lists every retained
  version's metadata, oldest first, with both ciphertext hashes and the
  signature. The server retains the most recent versions of each name up to
  the quota (`max_versions`, `max_config_versions`), pruning the oldest in
  the same transaction as a write.

A client verifies each listed signature from the hashes (records.md#4),
without decrypting, and decrypts each name and checks it against its index
(keys.md#8.3). Conformance: "history and tombstones" and "listing and
pagination" (README.md#6).

<a id="8"></a>
## 8. Rotation

A rotation moves a vault to a new generation in one atomic, owner-only
batch. It is the only way to cut off a revoked holder's copies of the keys.

1. The owner reads the vault's status (the token list included) and every
   retained version of both kinds. The status's generation MUST be the one
   the handle verified.
2. Before building anything, it MUST refuse with `unsupported_by_client` if
   any surviving token has a scope the client does not know: it cannot
   reseal that token's bundle correctly (http-api.md#7).
3. It generates the next generation's keys and a descriptor linked to the
   current one (records.md#1.3), signed by the owner.
4. It verifies every retained version against the current descriptor (a
   forged record is refused, not re-signed), decrypts it, re-encrypts it to
   the new keys and re-signs it with the new writer key, keeping its version
   number and write time; tombstones stay tombstones.
5. It seals and signs a new owner bundle, and a new bundle of the right kind
   for every surviving token, for the new generation.
6. It sends `POST /v1/vault/rotations` with the generation and revision the
   batch was built from, the descriptor, the owner bundle, every rotated
   secret and config version, every resealed bundle, and the tokens to revoke
   in the same step.

The server checks: owner-only; every value is age v1; the generation and
revision are current (409 `conflict`: the vault changed, rebuild); the
descriptor verifies and follows the current one (`key_mismatch`); every
record verifies under the new writer key for its kind; every bundle is
owner-signed for the new generation and, for a token, its stored scope; and
the batch is complete (`incomplete_rotation`): every retained version exactly
once with its write time and tombstone flag, every revoked token in the
vault, and exactly one resealed bundle for every surviving token. It then
applies the batch in one transaction, journaled (http-api.md#2). A server's
request body limit MUST allow the largest batch its quotas allow. After a
rotation, token holders re-open their bundle (§4.2) to use the new
generation. Conformance: "rotation that revokes a token" (README.md#6).

<a id="9"></a>
## 9. Rekey

A rekey re-roots a node: the node gets a fresh random key, and it and every
node below it move to new vaults. It is a client-driven sequence of ordinary
operations; the server has no rekey operation and no rekey proof
(signatures.md#8).
1. The owner generates a fresh random node key; every node below derives
   from it (keys.md#4).
2. It creates every new vault (§2) and copies every record into it (§6),
   re-encrypted and re-signed for the new vault.
3. It writes the new vaults' children records and, if it holds the parent's
   key, points the parent's children record at the new key as a `sealed`
   entry (records.md#5, records.md#2.6).
4. It deletes the old vaults last (`DELETE /v1/vault`, journaled), which
   ends every token of theirs.

Each step is recorded before the next begins, and each is idempotent, so an
interrupted rekey can be resumed or, before the parent is relinked, aborted.
The new recovery or delegation kit (records.md#6) is written before anything
changes on the server.

<a id="10"></a>
## 10. Children and rediscovery

Each node's owner-only children record (records.md#5) lists its children.
From any node key, a client rediscovers the subtree: it opens the node's
vault (§4.1), opens and verifies its children record (records.md#5.3), and
for each entry derives the child's key (`derived`) or opens the sealed child
key (`sealed`, records.md#2.6), then recurses. A client MUST refuse a
children record that fails verification or parsing; an entry in a mode the
client does not know fails the parse (records.md#5.1), so it refuses the
whole record. A `sealed` key that does not open is skipped with a warning,
and rediscovery continues with the other children. No token can read the
children record, so no token learns the tree; the conformance case "the
children record is owner-only" (README.md#6) checks the server's side.

<a id="11"></a>
## 11. Revocation and leak reports

- `DELETE /v1/tokens/{id}`, by the owner or an `admin` token, revokes a
  token at the server, journaled (http-api.md#2). It is forward-only: the
  holder keeps whatever keys it already unwrapped, so it can still decrypt
  what it copied, and a writer key it holds still produces signatures that
  verify; only the server's refusal to authenticate the token stops it.
- Revoking with rotation (§8, the `revoke` list) moves the vault to fresh
  keys in the same step, so the revoked token's keys open and sign nothing
  stored afterwards.
- `POST /v1/tokens/report` revokes a leaked token on proof of possession
  with its `token_auth` key (signatures.md#7), audited as `token_report`.
  The token string is never sent.
- `DELETE /v1/vault`, owner-only, deletes the vault and every token in it,
  journaled.

A journaled operation is written to the journal inside its transaction; if
the journal cannot be written, it is not applied and the answer is 503
`unavailable`. Replay after a restore re-applies it.

<a id="12"></a>
## 12. Pins

A client that keeps state for a vault MUST refuse:
- a descriptor for a generation lower than one it verified
  (`generation_rollback`);
- a different descriptor for a generation it verified
  (`generation_rollback`);
- a newer descriptor that does not follow the pinned one through an unbroken
  chain of owner-signed descriptors (`GET /v1/vault/descriptors`,
  records.md#1.3);
- a latest version of a record lower than one it read (`version_rollback`);
- a record whose signed version differs from the version the server reports
  for it;
- an audit chain that does not continue from its stored head (audit.md#5).

A client that keeps no state cannot detect a server that shows it an older,
correctly signed generation, record version or audit history, or a fork
between clients. These residuals, and the limits that are server policy
only, are listed in the threat model (`docs/threat-model.md`).
