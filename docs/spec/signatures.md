# Signatures

Status: **draft** (docs/spec/README.md#1).

Every signature in the protocol, with its exact signing input, the key that
signs and the key that verifies. Notation: `‖` is concatenation; integers
are big-endian; base64url is unpadded; `frame(label, …)` is
`label ‖ 0x00 ‖ …` (keys.md#1). Every label is in the registry (keys.md#3).
Vectors: `testdata/vectors/v1/signatures.json` reproduces one signing input
and signature for every kind below; the construct files cite the same inputs.

<a id="1"></a>
## 1. Ed25519

Every signature is Ed25519 (RFC 8032). Signing is deterministic, so the
vectors reproduce signatures byte for byte from their seeds.

Every verifier MUST verify strictly, as `ed25519-dalek`'s `verify_strict`
does, and MUST refuse (`bad_signature`):
- a signature whose scalar `s` is not reduced (`s ≥ L`);
- a public key that does not decode to a curve point;
- a public key of small order, and a signature whose `R` is of small order.

A small-order public key would otherwise accept a signature `R = [s]B` over
any message. The vectors include a signature with `s + L`, the identity point
as a public key, and a public key that is not a point.

<a id="2"></a>
## 2. Request signature (GV-Sig v=1)

Owners and tokens authenticate every request the same way: a signature over
the request as sent, carried in `Authorization`. No credential that decrypts
anything crosses the wire (keys.md#6).

<a id="2.1"></a>
### 2.1 Signing input

The signing input is ten lines of text joined by `\n` (0x0A), with no
trailing newline:

| Line | Content |
|---|---|
| 1 | `gv/v1/sig` |
| 2 | the actor: `owner`, or `token:` followed by the token id in lowercase hex |
| 3 | the method, upper case |
| 4 | the path and query, exactly as sent (e.g. `/v1/audit?after=5&limit=1000`) |
| 5 | lowercase hex SHA-256 of the body; of the empty string when there is none |
| 6 | the vault id, lowercase hex |
| 7 | `ts`: Unix seconds, decimal |
| 8 | the nonce: 16 random bytes, base64url |
| 9 | the `If-Match` value, or empty |
| 10 | the `If-None-Match` value, or empty |

The owner signs with its owner signing key (keys.md#5); a token signs with
its `token_auth` key (keys.md#6). A client MUST use a fresh random nonce for
every request. Because the preconditions are signed, a server or proxy
cannot turn a conditional write into an unconditional one.

<a id="2.2"></a>
### 2.2 Header

```
Authorization: GV-Sig v=1,actor=owner,vault=<hex>,ts=<unix>,nonce=<b64url>,sig=<b64url>
Authorization: GV-Sig v=1,actor=token,token=<hex>,vault=<hex>,ts=<unix>,nonce=<b64url>,sig=<b64url>
```

The scheme is `GV-Sig` followed by one space, then comma-separated
`name=value` parameters. A parser MUST refuse:
- a `v` other than `2` (`unknown_version`);
- a parameter given twice, a parameter it does not know, a missing
  parameter, `actor=token` without `token`, `actor=owner` with `token`, a
  nonce that is not 16 bytes, a signature that is not 64 bytes, or any other
  scheme such as `Bearer` (`bad_encoding`).

A server answers every one of these with the uniform 401 (http-api.md#3).

<a id="2.3"></a>
### 2.3 Verification by the server

The server verifies a request in this order, and answers any failure with
the uniform 401 `unauthorized` (http-api.md#3):
1. the header parses (§2.2);
2. the vault (actor `owner`) or the token (actor `token`) is known, and a
   token belongs to the vault the header names;
3. `ts` is within 300 seconds of the server's clock;
4. the signature verifies (§1) over the signing input (§2.1) rebuilt from
   the request as received, against the stored `owner_sign_pub` or the
   token's stored `auth_pub`;
5. the vault has not expired (hosted.md#3);
6. the nonce has not been spent for this vault: the server spends it only
   after the signature verifies, so nobody can burn another caller's nonces,
   and remembers it for 600 seconds past `ts`.

Only after step 6 does a token holder learn that its token expired
(`token_expired`). A request that authenticates as a token and asks for an
owner-only operation is refused with 403 `forbidden`. Vault creation is the
exception to step 2: the vault is not yet known, so the server verifies the
request against the owner signing key in the request body, after checking
that the key hashes to the vault id (protocol.md#2). Conformance: the
"uniform 401" case (README.md#6).

<a id="3"></a>
## 3. Descriptor signature

The owner signing key signs `frame("gv/v1/descriptor", descriptor)` over the
189-byte descriptor (records.md#1). Verified by every client from its pinned
vault id (records.md#1.4) and by the server before it stores a descriptor
(at creation and at rotation).

<a id="4"></a>
## 4. Bundle signature

The owner signing key signs
`frame("gv/v1/bundle", vault_id(16) ‖ token_id(16) ‖ scope(u8) ‖ generation(u32) ‖ SHA-256(sealed))`
(records.md#2.4). The owner's own bundle uses the zero token id and scope 0.
Verified by the holder before it opens the seal (records.md#2.5), and by the
server when a token is registered and when a rotation reseals bundles.

<a id="5"></a>
## 5. Record (writer) signature

The generation's writer key for the record's kind signs
`frame("gv/v1/record", vault_id ‖ generation ‖ kind ‖ name_index ‖ version ‖ written_at ‖ tombstone ‖ SHA-256(value_ct) ‖ SHA-256(name_ct))`
(records.md#4). Verified by the server before it stores a record and by
every client before it trusts one, against the descriptor's writer key for
that kind only. Writer keys are per generation and per kind, not per token:
the signature proves a holder of the writer key wrote the record, and the
server's audit row names which credential sent it.

<a id="6"></a>
## 6. Children signature

The owner signing key signs
`frame("gv/v1/children", vault_id(16) ‖ version(u64) ‖ SHA-256(ct))`
(records.md#5.2). Verified by the server on every write and by the owner on
every read (records.md#5.3).

<a id="7"></a>
## 7. Leaked-token report

Whoever holds a token string can revoke it without sending it: the token's
`token_auth` key signs

```
frame("gv/v1/report", token_id(16) ‖ ts(i64))
```

and the reporter sends `POST /v1/tokens/report` with
`{"token_id": hex, "ts": i64, "sig": b64url}` and no `Authorization`. The
server MUST verify the signature against the token's stored `auth_pub` and
MUST refuse a `ts` more than 300 seconds from its clock, answering either
failure, and an unknown token, with the uniform 401. The token string never
crosses the wire (protocol.md#11).

<a id="8"></a>
## 8. Summary

| Signature | Signed by | Verified by | Input | Spec |
|---|---|---|---|---|
| request | owner signing key or `token_auth` | server | the text of §2.1 | §2 |
| descriptor | owner signing key | server; every client | `frame(gv/v1/descriptor, descriptor)` | records.md#1.2 |
| bundle | owner signing key | server; the holder | `frame(gv/v1/bundle, …)` | records.md#2.4 |
| record | the generation's writer key for the kind | server; every client | `frame(gv/v1/record, …)` | records.md#4 |
| children | owner signing key | server; the owner | `frame(gv/v1/children, …)` | records.md#5.2 |
| leaked-token report | `token_auth` | server | `frame(gv/v1/report, token_id ‖ ts)` | §7 |

The protocol has no rekey proof: a rekey is a client-driven sequence of
creations, writes, children updates and deletions, each authenticated as
above (protocol.md#9).
