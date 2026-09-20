# HTTP API

Status: **draft** (docs/spec/README.md#1).

This document is the reference for the `/v1` API: every endpoint, how each
authenticates, which token scopes it permits, its preconditions, its status
codes and its error codes, the capabilities document, and the rules that let
a newer server and an older client work together. The bytes inside the bodies
(descriptors, bundles, records, signatures) are specified in `records.md`,
`signatures.md` and `audit.md`; the flows that use these endpoints are in
`protocol.md`.

The endpoint table (#2) and the error table (#5.2) are checked mechanically
against the code: the endpoint table against the route table
`galata_vault_server_core::ROUTES`, and the error table against `galata_vault_proto::api::ErrorCode`.
A difference in either direction fails the tests.

<a id="1"></a>
## 1. Base

- Every protocol endpoint is under `/v1`. A server MUST answer a path under
  any other version prefix (`/v0`, `/v2`, …) with 404 `not_found`, and MUST
  NOT interpret it as a `/v1` path.
- Every call addresses exactly one vault, and the credential chooses it: the
  owner signature names the vault id, and a token belongs to one vault. No
  endpoint takes a vault id in its path, and the server knows no project,
  path or plaintext name.
- Request and response bodies are JSON (#4.3). A request that carries no body
  sends none, and its signature covers the empty body.
- The HTTP shell answers two endpoints of its own, outside `/v1`:
  `GET /healthz` and `GET /readyz` (503 `unavailable` while the journal is
  unreachable). They take no credential and carry no vault data. The
  embedded transport serves neither.
- An unknown path is 404 `not_found`. A known path with a method it does not
  serve is 400 `invalid_request`.
- A request body larger than the server's body limit is refused with 413
  `value_too_large` before it is read further. The limit is at least the
  largest rotation batch the server's quotas allow (`protocol.md#8`).

<a id="2"></a>
## 2. Endpoints

`Auth` names the scheme of #3. `Scopes` names the token scopes the server
permits; the owner may call every endpoint that accepts an owner signature. A
token whose scope is not permitted gets 403 `forbidden` (#3.3). Queries:
listings take `after` (the last `name_hmac` of the previous page) and `limit`
(default 100, clamped to 1..500); the audit takes `after` (a sequence number)
and `limit` (default and maximum 1000); the descriptor chain takes `after` (a
generation).

| Method | Path | Auth | Scopes | Request | Response | Notes |
|---|---|---|---|---|---|---|
| GET | `/v1/capabilities` | none | — | — | `Capabilities` | 200. Identical for every caller (#6). |
| POST | `/v1/challenges` | none | — | `ChallengeRequest` | `ChallengeResponse` | 200. Served only while capabilities set `proof_of_work`; otherwise 404 `not_found` (hosted.md#2.1). |
| POST | `/v1/vaults` | owner | — (signed by the owner key being registered) | `CreateVaultRequest` | `CreateVaultResponse` | 201. 409 `conflict` if the vault exists; `vault_id_mismatch`, `bad_signature`, `key_mismatch`, `invalid_request` for a descriptor that is not a first generation; proof-of-work errors (hosted.md#2.3). |
| GET | `/v1/vault` | owner, token | every scope | — | `VaultStatus` | 200. `tokens` only for the owner and `admin`; `owner_bundle` only for the owner. |
| DELETE | `/v1/vault` | owner | owner only | — | `DeleteVaultResponse` | 200. Journaled; every token of the vault stops authenticating. |
| GET | `/v1/vault/descriptors` | owner, token | every scope | — | `DescriptorList` | 200. The owner-signed chain after `after`, ascending. |
| GET | `/v1/vault/children` | owner | owner only | — | `ChildrenBlob` | 200 with `ETag`; 404 `not_found` before the first write. |
| PUT | `/v1/vault/children` | owner | owner only | `ChildrenBlob` | `PutSecretResponse` | 201 under `If-None-Match: *`, 200 under `If-Match`; 428, 412, 409 `version_mismatch` as for records; `bad_signature` unless the owner signed it. |
| POST | `/v1/vault/rotations` | owner | owner only | `RotationRequest` | `RotationResponse` | 200. One atomic, journaled batch; 409 `conflict` when built from a stale generation or revision; `incomplete_rotation`, `not_age_ciphertext`, `bad_signature`, `key_mismatch`. |
| POST | `/v1/tokens` | owner | owner only | `RegisterTokenRequest` | `RegisterTokenResponse` | 201. 409 `conflict` for a registered id; `ttl_too_long`, `token_quota_exceeded`, `stale_generation`, `bad_signature`; an allow-list only for `read`. |
| GET | `/v1/tokens/self` | token | every scope | — | `TokenSelf` | 200. An owner signature gets 400 `invalid_request`. |
| POST | `/v1/tokens/report` | none | — (the token-auth signature is in the body) | `ReportTokenRequest` | `RevokeResponse` | 200. Journaled. Every failure is the uniform 401 (#3.2). |
| DELETE | `/v1/tokens/{token_id}` | owner, token | `admin` | — | `RevokeResponse` | 200. Journaled; forward-only (`protocol.md#11`). |
| GET | `/v1/audit` | owner, token | every scope | — | `AuditPage` | 200. The rows after `after`, and the vault's head. |
| GET | `/v1/secrets` | owner, token | every scope | — | `SecretList` | 200. Metadata only; tombstones included. |
| GET | `/v1/secrets/{name_hmac}` | owner, token | `read`, `admin` | — | `SecretVersion` | 200 with `ETag`. A tombstone as latest is 404 `not_found` with the tombstone's version as `ETag`. A read token's allow-list applies. Audited. |
| PUT | `/v1/secrets/{name_hmac}` | owner, token | `append`, `admin` | `PutSecretRequest` | `PutSecretResponse` | 201 under `If-None-Match: *`, 200 under `If-Match`, with `ETag`; 428, 412, 409 `version_mismatch`, 409 `stale_generation`, 422 `not_age_ciphertext` or `bad_signature`, quota codes. |
| DELETE | `/v1/secrets/{name_hmac}` | owner, token | `append`, `admin` | `DeleteRecordRequest` | `PutSecretResponse` | 200 with `ETag`: a signed tombstone. `If-Match` only; 428 without it. |
| GET | `/v1/secrets/{name_hmac}/versions` | owner, token | every scope | — | `VersionList` | 200. Every retained version's metadata and signature. |
| GET | `/v1/secrets/{name_hmac}/versions/{version}` | owner, token | `read`, `admin` | — | `SecretVersion` | 200 with `ETag`: a retained version, a tombstone included. Allow-list applies. Audited. |
| GET | `/v1/configs` | owner, token | every scope | — | `SecretList` | 200. As `/v1/secrets`. |
| GET | `/v1/configs/{name_hmac}` | owner, token | `read`, `admin`, `config`, `config-write` | — | `SecretVersion` | As the secret read; no allow-list. |
| PUT | `/v1/configs/{name_hmac}` | owner, token | `append`, `admin`, `config-write` | `PutSecretRequest` | `PutSecretResponse` | As the secret write; config quotas. |
| DELETE | `/v1/configs/{name_hmac}` | owner, token | `append`, `admin`, `config-write` | `DeleteRecordRequest` | `PutSecretResponse` | As the secret delete. |
| GET | `/v1/configs/{name_hmac}/versions` | owner, token | every scope | — | `VersionList` | As the secret history. |
| GET | `/v1/configs/{name_hmac}/versions/{version}` | owner, token | `read`, `admin`, `config`, `config-write` | — | `SecretVersion` | As the secret version read. |
| GET | `/healthz` | none | — | — | `{"status":"ok"}` | 200. HTTP shell only. |
| GET | `/readyz` | none | — | — | `{"status":"ready"}` | 200, or 503 `unavailable` while the journal is unreachable. HTTP shell only. |

<a id="3"></a>
## 3. Authentication

<a id="3.1"></a>
### 3.1 Schemes

- **none.** The request carries no `Authorization`. An endpoint of this
  scheme does not authenticate a credential sent to it.
- **owner.** `Authorization: GV-Sig v=1,actor=owner,…`, verified against the
  vault's stored `owner_sign_pub` (`signatures.md#2`). For `POST /v1/vaults`
  the signature is verified against the `owner_sign_pub` in the body, whose
  hash MUST be the body's vault id.
- **token.** `Authorization: GV-Sig v=1,actor=token,token=<id>,…`, verified
  against the token's registered `auth_pub`. The token must belong to the
  vault the header names.
- **owner, token.** Either of the two.

A server MUST accept a credential only in `Authorization` (#4.1). It MUST
answer a `Bearer` credential, a `GV-Sig` header of any version but `2`, and a
malformed header with the uniform 401. It MUST verify the signature and the
skew before it spends the nonce, and MUST spend each nonce once
(`signatures.md#2.3`).

<a id="3.2"></a>
### 3.2 The uniform 401

Every authentication failure before a credential is proven gets the same
answer, 401 with the body

```json
{"error":"unauthorized","message":"authentication failed"}
```

whether the token is unknown, revoked or of another vault, the vault does not
exist or has expired (hosted.md#3), the signature does not verify, the
timestamp is outside the skew window, the nonce was already spent, or the
header is missing, malformed, `Bearer` or not `v=1`. A server MUST NOT reveal
which. `token_expired` (401) is answered only after the holder has proved
possession: the signature verified and the nonce was spent.

<a id="3.3"></a>
### 3.3 Scopes

An authenticated token whose scope does not permit the endpoint gets 403
`forbidden`, and the server appends an audit row with result `refused`
(`audit.md#1`), except where the endpoint refuses before it names an action
(`GET /v1/vault/children`). An owner-only endpoint called with a token
signature is 403 `forbidden`. A `read` token's allow-list restricts which
secrets it may read; it is enforced by the server only (policy, not
cryptography: the token holds the vault key). The cryptographic limits behind
each scope are in `records.md#2.2` and `docs/threat-model.md`.

<a id="4"></a>
## 4. Headers

<a id="4.1"></a>
### 4.1 Authorization and credentials

Credentials travel only in `Authorization`. A server MUST refuse, with 400
`credential_in_query` and without processing the request, any request whose
query string has a parameter named `token`, `access_token`, `auth`,
`authorization`, `sig`, `signature`, `key` or `secret` (case-insensitive), or
contains `gvt1_` or `gvk1_` (plain or with `_` percent-encoded). It MUST NOT
authenticate or log the value.

<a id="4.2"></a>
### 4.2 Preconditions and `ETag`

- Every write names the version it expects: `If-None-Match: *` to create (or
  to revive a name whose latest version is a tombstone), or `If-Match:
  <version>` to update or delete. `If-Match` accepts the version bare, quoted,
  or weak (`W/"<version>"`). `If-None-Match` accepts only `*`. Both headers
  together are 400 `invalid_request`; a delete takes `If-Match` only.
- A write without either header MUST be refused with 428
  `precondition_required`. A precondition that does not hold MUST be refused
  with 412 `precondition_failed`, and nothing is written.
- The version the record's signature binds MUST be the version the
  precondition creates (1, or `v + 1`); otherwise 409 `version_mismatch`
  (`records.md#4`).
- Both headers are part of the request signature (`signatures.md#2.1`), so an
  intermediary cannot change them.
- A record read, a record write and the children record answer with `ETag:
  "<version>"`.

<a id="4.3"></a>
### 4.3 Content-Type

A client sends `Content-Type: application/json` with every body. Every
response, success or error, is `application/json`. A server MUST NOT serve
HTML, whatever `Accept` asks for.

<a id="4.4"></a>
### 4.4 Response hygiene

Every response MUST carry:

- `X-Content-Type-Options: nosniff`
- `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`
- `Cache-Control: no-store`
- `Referrer-Policy: no-referrer`
- `X-Frame-Options: DENY`

An error MUST NOT echo the request body, a header value, a token or
ciphertext.

<a id="4.5"></a>
### 4.5 `X-GV-Expires-At`

Only a server with an idle-expiry window sends it: Unix seconds, on every
answer after authentication (hosted.md#3). A server without a window MUST
NOT send it.

<a id="4.6"></a>
### 4.6 `Retry-After`

A 429 `rate_limited` answer carries `Retry-After` in seconds (hosted.md#4).

<a id="5"></a>
## 5. Errors

<a id="5.1"></a>
### 5.1 The error body

Every error answer is 4xx or 5xx with the body

```json
{"error": "<code>", "message": "<text for a person>"}
```

and no other field. Neither field contains ciphertext, token material or a
client address, and the message never quotes the request. The code is stable;
the message is not, and a client MUST NOT parse it.

Codes are only ever added. A code MUST NOT be renamed, MUST NOT be removed
while a supported client may still receive it, and MUST NOT be reused with a
different meaning. A new error condition gets a new code. Every code a server
emits MUST appear in #5.2 with its status; a client handles a code it does
not know as #7.3 says.

<a id="5.2"></a>
### 5.2 The error table

`Retry` says what a client may do with the same operation:

- `yes`: nothing changed; the operation may succeed if sent again, signed
  afresh (a signed request's nonce is spent), after `Retry-After` where
  given.
- `refresh`: nothing changed; the operation may succeed once rebuilt from
  fresh state (the current version, generation, revision or a new
  challenge).
- `no`: it fails again as sent; the request, the credential or the vault must
  change first.

| Code | Status | Retry | Meaning |
|---|---|---|---|
| `invalid_request` | 400 | no | The body, a path parameter, a query value or a header is malformed, a request body carries an unknown field, or the method is not served on the path. |
| `credential_in_query` | 400 | no | A credential in the query string (#4.1). |
| `challenge_expired` | 400 | refresh | The proof-of-work challenge has expired (hosted.md#2.3). |
| `invalid_proof_of_work` | 400 | no | A creation needs a solved challenge and carries none, or one this server did not issue, or a nonce that does not solve it. |
| `unauthorized` | 401 | no | The uniform authentication failure (#3.2). |
| `token_expired` | 401 | no | The token has expired; answered only after the holder proved possession. |
| `forbidden` | 403 | no | The credential's scope or allow-list does not permit it, or the endpoint is owner-only (#3.3). |
| `not_found` | 404 | no | No such endpoint, record, version or children record, or the latest version is a tombstone. |
| `conflict` | 409 | refresh | The thing exists already (a vault, a token id, a record created twice), or a rotation was built from a stale generation or revision. |
| `stale_generation` | 409 | refresh | A write or registration names a generation that is not the vault's current one. |
| `challenge_reused` | 409 | refresh | The proof-of-work challenge was already spent. |
| `version_mismatch` | 409 | refresh | The record's signed version is not the version the precondition creates. |
| `version_rollback` | 409 | no | A client saw a newer version of a record than the server now shows. Reported by clients; no server emits it. |
| `generation_rollback` | 409 | no | A client saw a newer or different generation than the server now shows. Reported by clients; no server emits it. |
| `precondition_failed` | 412 | refresh | `If-Match` or `If-None-Match` does not hold. |
| `value_too_large` | 413 | no | A secret value above the per-value quota, or a request body above the body limit. |
| `config_too_large` | 413 | no | A config document above the per-config quota. |
| `vault_id_mismatch` | 422 | no | A creation's vault id is not the hash of its owner signing key. |
| `not_age_ciphertext` | 422 | no | A value is not age v1 ciphertext. |
| `incomplete_rotation` | 422 | no | A rotation batch leaves out a retained version or a surviving token, or names a token not in the vault. |
| `ttl_too_long` | 422 | no | A token's lifetime is above its scope's maximum. |
| `vault_quota_exceeded` | 422 | no | The vault's storage quota. |
| `name_quota_exceeded` | 422 | no | The vault's secret-name quota. |
| `token_quota_exceeded` | 422 | no | The vault's token quota. |
| `config_quota_exceeded` | 422 | no | The vault's config-document quota. |
| `bad_signature` | 422 | no | A descriptor, bundle, record or children signature does not verify. |
| `key_mismatch` | 422 | no | A key does not match the vault's descriptor or pinned id, or a new descriptor does not follow the current one. |
| `precondition_required` | 428 | no | A write without `If-Match` or `If-None-Match`. |
| `rate_limited` | 429 | yes | A request budget is spent; `Retry-After` says when to try again (hosted.md#4). |
| `internal` | 500 | yes | The server failed; the operator's log has the detail. |
| `unavailable` | 503 | yes | A critical operation could not be journaled, so it was not applied; or the journal is unreachable (`/readyz`). |

A server emits every code in the table except `version_rollback`
and `generation_rollback`, which exist so that clients report
those failures with the same code a server would use.

<a id="6"></a>
## 6. Capabilities

<a id="6.1"></a>
### 6.1 The document

`GET /v1/capabilities` MUST be answered without authentication, with the same
document for every caller, and with no per-vault data. The embedded transport
MUST return the same document as a server with the same policy.

| Field | Type | Meaning |
|---|---|---|
| `protocols` | array of strings | The protocol versions served: `["1"]`. |
| `formats` | object | The version of each format this build implements: `descriptor` 2, `bundle` 2, `envelope` 3, `children` 2, `audit_row` 3 (the row format it writes), `request_signature` 2. 0 or absent means not advertised. |
| `proof_of_work` | `{"difficulty": n}` or null | What vault creation needs; null when it needs no challenge (hosted.md#2). |
| `idle_expiry_days` | number or null | Days without an authenticated request before a vault expires; null when no vault expires (hosted.md#3). |
| `limits` | object | The per-vault quotas: `max_names`, `max_value_bytes`, `max_versions`, `max_vault_bytes` (secrets and configs together), `max_tokens`, `max_configs`, `max_config_bytes`, `max_config_versions`. |
| `features` | array of strings | The optional behaviours in force (#6.2). |
| `server` | string, optional | The server's name and version, `gv-server/<version>`. Present only when the operator sets `advertise_version = true`; absent by default, to limit fingerprinting. |

`proof_of_work`, `idle_expiry_days` and `limits` were the whole document
before this version and keep their names and meaning. A document without
`protocols` comes from a server that predates the field, and MUST be read as
`["1"]`. A server that answers the request with 404 predates the document: a
client MUST then assume it asks for proof of work, and learn of expiry only
from its responses.

A default server's document:

```json
{
  "protocols": ["1"],
  "formats": {"descriptor": 2, "bundle": 2, "envelope": 3, "children": 2, "audit_row": 3, "request_signature": 2},
  "proof_of_work": null,
  "idle_expiry_days": null,
  "limits": {"max_names": 200, "max_value_bytes": 16384, "max_versions": 20, "max_vault_bytes": 4194304,
             "max_tokens": 128, "max_configs": 64, "max_config_bytes": 262144, "max_config_versions": 20},
  "features": ["token_report"]
}
```

<a id="6.2"></a>
### 6.2 Features

A client MUST ignore a feature name it does not know.

| Feature | Meaning |
|---|---|
| `token_report` | `POST /v1/tokens/report` is served. Every core serves it. |
| `rate_limits` | A request budget per token and per vault is enforced: any authenticated request may be answered 429 with `Retry-After` (hosted.md#4). |

<a id="6.3"></a>
### 6.3 What a client does with it

- A client MUST fetch the capabilities before a handle's first authenticated
  request, and SHOULD fetch them at most once per handle and its clones,
  remembering the answer (a 404 included).
- A client MUST refuse a server whose `protocols` does not list `"1"`, with
  `unsupported_protocol`, before it sends any authenticated request.
- A client MUST request a proof-of-work challenge only when `proof_of_work`
  is set.
- A client MUST keep ancestors alive and warn about expiry only when the
  server announces expiry, in `idle_expiry_days` or in `X-GV-Expires-At`.
- A client MUST send a request field introduced after protocol version 1 only to a
  server whose capabilities advertise it (#7.1).

<a id="7"></a>
## 7. Forward compatibility

A newer server must never make an older client lose information or act on
something it does not understand.

<a id="7.1"></a>
### 7.1 Requests are strict

A server MUST refuse a request body that carries a field it does not know,
with 400 `invalid_request`, and MUST change nothing. It MUST likewise refuse
an enum value it does not know, such as a token scope. Silently ignoring a
field could drop a precondition or a restriction the client meant. A client
MUST send a field introduced after protocol version 1 only when the server's
capabilities advertise support for it.

<a id="7.2"></a>
### 7.2 Responses are tolerant

A client MUST ignore a field it does not know in any response body, except an
audit row: every field of a row is hashed, so a row with an unknown field is
malformed and a new row field comes with a new row format (`audit.md#4`). A
`galata-vault-proto` unit test (`every_response_tolerates_an_unknown_field`) parses
every response body with an unknown field added at every level.

<a id="7.3"></a>
### 7.3 Values a client does not know

- **Kept and shown.** A token scope (`TokenSummary.scope`,
  `TokenSelf.scope`), an error code (`ErrorBody.error`) and a record writer's
  actor kind (`SecretVersion.written_by`, `VersionMeta.written_by`) that the
  client does not know MUST be accepted and kept, by name, for display (in
  the Rust crates, `galata_vault_proto::tolerant::Tolerant`). The rest of the response is
  read normally.
- **Never acted on.** Every operation whose correctness depends on
  understanding such a value MUST refuse with `unsupported_by_client` and MUST
  change nothing:
  - opening a vault with a token whose scope the client does not know (its
    bundle's kind cannot be checked);
  - rotation, and so the resealing of every token's bundle, while any
    surviving token's scope is unknown;
  - minting a token while the vault holds a token of unknown scope;
  - audit verification over a row naming an action or actor the client does
    not know (`audit.md#4`);
  - reading, writing or verifying a record of a kind the client does not
    know (`records.md#3`).

  The children record is not tolerant: it carries its own format version, and
  an entry the client cannot parse makes the record malformed
  (`records.md#5`).
- **Unknown error codes.** A client MUST keep the code string and the
  server's message, and MUST NOT replace the message with a status text. It
  derives the error's kind from the HTTP status class: 401 authentication,
  403 forbidden, 404 not found, 409 and 412 conflict, anything else other.
  A refusal whose body names no code is reported as `http_<status>`.
- **Unknown audit row formats** are reported as unverifiable, never as
  tampered and never as verified (`audit.md#4`).

<a id="7.4"></a>
### 7.4 Codes a client raises

A client reports server codes as the server sent them. It also has codes of
its own, which no server emits; the protocol-relevant ones are:

| Code | Meaning |
|---|---|
| `unsupported_protocol` | The server's capabilities do not list protocol `"1"`; nothing authenticated was sent. |
| `unsupported_by_client` | The operation depends on a value this client does not know (#7.3); nothing changed. |
| `http_<status>` | The server refused with a body that names no code. |
| `unreachable` | No answer: the connection, TLS or the transport failed, or a redirect (never followed). |
| `bad_signature`, `key_mismatch`, `binding_mismatch`, `version_rollback`, `generation_rollback`, `audit_mismatch` | Something the server served does not verify (`protocol.md#4`, `audit.md#5`). |
| `invalid_token` | A token string that does not parse or whose checksum does not match (`formats.md#2`). |
| `error` | A success whose body is not what the protocol says it is. |

The SDK's full list, including codes about local state, is its `code`
module (`crates/galata-vault/src/error.rs`).

<a id="8"></a>
## 8. Bodies

Field types: `VaultId` and `TokenId` are 32 lowercase hex characters;
`NameHmac` and `Hash32` are 64. Public keys (`Key32`, 32 bytes), signatures
(`Sig64`, 64 bytes) and opaque bytes (`B64`: ciphertext, sealed bundles,
descriptor bytes) are unpadded base64url. Integers are JSON numbers; times are
Unix seconds. A field shown as `T?` may be null or, where noted, absent.

Every request body in this section refuses a field it does not know (#7.1);
no response body does, except the audit row (#7.2).

<a id="8.1"></a>
### 8.1 Shared objects

- `SignedDescriptor`: `{"descriptor": B64 (189 bytes, records.md#1), "sig": Sig64}`.
- `SignedBundle`: `{"sealed": B64, "sig": Sig64}` (`records.md#2`).
- `Actor`: `{"kind": "owner"}` or `{"kind": "token", "id": TokenId}`.
- `Limits`: the eight quota fields of #6.1, each a number; a missing field
  takes its default.
- `ChainHead`: `{"seq": u64, "hash": Hash32}`.

<a id="8.2"></a>
### 8.2 Vaults

- `ChallengeRequest`: `{"purpose": "create_vault"}`.
- `ChallengeResponse`: `{"challenge": string, "difficulty": u8, "expires_at": i64}`.
- `CreateVaultRequest`: `{"challenge": string? (absent when none), "nonce": u64? (absent when none), "vault_id": VaultId, "owner_sign_pub": Key32, "owner_box_pub": Key32, "descriptor": SignedDescriptor, "owner_bundle": SignedBundle}`.
- `CreateVaultResponse`: `{"vault_id": VaultId, "generation": u32, "expires_at": i64?}`.
- `VaultStatus`: `{"vault_id", "generation": u32, "revision": u64, "owner_sign_pub": Key32, "owner_box_pub": Key32, "descriptor": SignedDescriptor, "config_count": u32, "created_at": i64, "last_active_at": i64, "expires_at": i64?, "bytes_used": u64, "limits": Limits, "tokens": [TokenSummary]?, "owner_bundle": SignedBundle?}`.
- `TokenSummary`: `{"token_id": TokenId, "scope": string (tolerant, #7.3), "created_at": i64, "expires_at": i64, "box_pub": Key32, "allow_list": [NameHmac]?}`.
- `DescriptorList`: `{"descriptors": [SignedDescriptor]}`.
- `RotationRequest`: `{"from_generation": u32, "from_revision": u64, "descriptor": SignedDescriptor, "owner_bundle": SignedBundle, "secrets": [RotatedVersion], "configs": [RotatedVersion], "tokens": [ResealedBundle], "revoke": [TokenId]}`.
- `RotatedVersion`: `{"old_name_hmac": NameHmac, "version": u64, "name_hmac": NameHmac, "name_ct": B64, "value_ct": B64? (null for a tombstone), "written_at": i64, "sig": Sig64}`.
- `ResealedBundle`: `{"token_id": TokenId, "bundle": SignedBundle}`.
- `RotationResponse`: `{"generation": u32}`.
- `DeleteVaultResponse`: `{"vault_id": VaultId}`.
- `ChildrenBlob`: `{"version": u64, "ct": B64, "sig": Sig64}` (`records.md#5`); both the request and the response of the children endpoints.

<a id="8.3"></a>
### 8.3 Tokens

- `RegisterTokenRequest`: `{"token_id": TokenId, "auth_pub": Key32, "box_pub": Key32, "scope": string (strict: a scope the server does not know is refused), "ttl_secs": u64 (0: the scope's default), "allow_list": [NameHmac]?, "generation": u32, "bundle": SignedBundle}`.
- `RegisterTokenResponse`: `{"token_id": TokenId, "expires_at": i64}`.
- `TokenSelf`: `{"token_id": TokenId, "vault_id": VaultId, "scope": string (tolerant), "expires_at": i64, "allow_list": [NameHmac]?, "owner_sign_pub": Key32, "descriptor": SignedDescriptor, "bundle": SignedBundle}`.
- `ReportTokenRequest`: `{"token_id": TokenId, "ts": i64, "sig": Sig64}` (`signatures.md#7`).
- `RevokeResponse`: `{"revoked": [TokenId]}`.

Scope lifetimes: `admin` defaults to 1 day and allows at most 30; every other
scope defaults to 90 days and allows at most 365.

<a id="8.4"></a>
### 8.4 Records

- `SecretList`: `{"items": [SecretListItem], "next_cursor": NameHmac?}`.
- `SecretListItem`: `{"name_hmac": NameHmac, "name_ct": B64, "version": u64, "written_at": i64, "size": u32, "tombstone": bool, "generation": u32, "value_ct_hash": Hash32, "sig": Sig64}`.
- `SecretVersion`: `{"name_hmac": NameHmac, "version": u64, "name_ct": B64, "value_ct": B64? (null for a tombstone), "generation": u32, "written_at": i64, "written_by": Actor (tolerant), "tombstone": bool, "sig": Sig64}`.
- `PutSecretRequest`: `{"name_ct": B64, "value_ct": B64, "generation": u32, "version": u64, "written_at": i64, "sig": Sig64}`.
- `DeleteRecordRequest`: `{"name_ct": B64, "generation": u32, "version": u64, "written_at": i64, "sig": Sig64}`.
- `PutSecretResponse`: `{"version": u64}`.
- `VersionList`: `{"versions": [VersionMeta]}`.
- `VersionMeta`: `{"version": u64, "written_at": i64, "written_by": Actor (tolerant), "size": u32, "tombstone": bool, "generation": u32, "value_ct_hash": Hash32, "name_ct_hash": Hash32, "sig": Sig64}`.

The same shapes serve `/v1/secrets` and `/v1/configs`.

<a id="8.5"></a>
### 8.5 Audit and errors

- `AuditPage`: `{"rows": [AuditRow], "head": ChainHead?}`; the row is in
  `audit.md#1`.
- `ErrorBody`: `{"error": string (tolerant), "message": string}` (#5.1).
