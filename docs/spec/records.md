# Records

Status: **draft** (docs/spec/README.md#1).

This document defines the byte formats a vault stores and a client verifies:
the generation descriptor, bundles, the record envelope, record signatures,
the children record, and kits. Notation: `‖` is concatenation; integers are
big-endian (`u8`, `u16`, `u32`, `u64`, `i64`); base64url is unpadded;
`frame(label, …)` is `label ‖ 0x00 ‖ …` (keys.md#1). The failure names in
parentheses are those of the registry (README.md#4); an implementation maps
its own errors onto them.

<a id="1"></a>
## 1. Generation descriptor

Every vault generation has five keys: `vault_sk` and `config_sk` (X25519),
`name_key` (32 bytes), and `secret_writer` and `config_writer` (Ed25519
seeds) (keys.md#7). The descriptor is the owner's signed statement of their
public halves. Vectors: `testdata/vectors/v1/descriptors.json`.

<a id="1.1"></a>
### 1.1 Encoding

A descriptor is exactly 189 bytes:

| Offset | Length | Field | Meaning |
|---|---|---|---|
| 0 | 1 | `v` | the descriptor version, 1 |
| 1 | 16 | `vault_id` | the vault (keys.md#5) |
| 17 | 4 | `generation` | `u32`, 1 for a new vault |
| 21 | 32 | `vault_pub` | X25519; secrets are encrypted to it |
| 53 | 32 | `config_pub` | X25519; configs are encrypted to it |
| 85 | 32 | `secret_writer_pub` | Ed25519; verifies secret records |
| 117 | 32 | `config_writer_pub` | Ed25519; verifies config records |
| 149 | 32 | `prev_hash` | SHA-256 of the previous generation's 189 bytes |
| 181 | 8 | `created_at` | `i64`, Unix seconds |

On the wire a descriptor travels as `{"descriptor": b64url(189 bytes),
"sig": b64url(64 bytes)}`.

A reader MUST check the version byte before the length: a descriptor whose
first byte is not 1 is refused as `unknown_version` whatever its length, and
a descriptor of version 1 that is not 189 bytes long is refused as
`bad_length`.

<a id="1.2"></a>
### 1.2 Signature

The owner signing key (keys.md#5) signs
`frame("gv/v1/descriptor", descriptor)`, the 189 bytes prefixed by the label
and `0x00` (signatures.md#3). No other key's signature is valid.

<a id="1.3"></a>
### 1.3 Chain

`prev_hash` is SHA-256 of the previous generation's 189 bytes, and 32 zero
bytes at generation 1. A descriptor `next` follows `prev` exactly when all
three hold, checked in this order:
1. both name the same vault (else `vault_mismatch`);
2. `next.generation` is `prev.generation + 1` (else `generation_mismatch`);
3. `next.prev_hash` is SHA-256 of `prev` (else `chain_break`).

A server MUST refuse a rotation whose new descriptor does not follow the
current one, and a vault creation whose descriptor is not generation 1 with a
zero `prev_hash` (protocol.md#2, protocol.md#8). Two different descriptors
can both follow the same predecessor: a fork is caught by client pins
(protocol.md#12), not by the chain.

<a id="1.4"></a>
### 1.4 Verification from a pinned vault id

A client verifies a descriptor against a vault id it pinned itself (an owner
derives it from its node key; a token holder reads it from its token string)
and an owner signing public key the server presented. In this order:
1. the owner signing key MUST hash to the pinned vault id (keys.md#5), else
   `key_mismatch`;
2. the descriptor MUST decode (§1.1): `unknown_version`, `bad_length`;
3. the owner's signature (§1.2) MUST verify, else `bad_signature`;
4. the descriptor MUST name the pinned vault id, else `vault_mismatch`.

Only then MAY the client encrypt to `vault_pub` or `config_pub`, or accept a
record signed by a writer key the descriptor names. A client that already
verified a generation also applies its pins (protocol.md#12).

<a id="2"></a>
## 2. Bundles

A bundle carries the keys one holder may use, sealed to that holder's X25519
key and signed by the owner. Vectors: `testdata/vectors/v1/bundles.json`
(open direction: sealed boxes are randomised).

<a id="2.1"></a>
### 2.1 Plaintext

```
plaintext = version(1) = 2 ‖ kind(1) ‖ vault_id(16) ‖ token_id(16) ‖ generation(u32) ‖ body
```

The header is 38 bytes. The owner's own bundle uses a token id of 16 zero
bytes. The body is the kind's keys, 32 bytes each, in the order §2.2 lists
them.

<a id="2.2"></a>
### 2.2 Kinds

| Kind | Name | Body | Plaintext length | Held by |
|---|---|---|---|---|
| 1 | names | `name_key` | 70 | `meta` |
| 2 | append | `name_key ‖ secret_writer ‖ config_writer` | 134 | `append` |
| 3 | config | `name_key ‖ config_sk` | 102 | `config` |
| 4 | config-write | `name_key ‖ config_sk ‖ config_writer` | 134 | `config-write` |
| 5 | read | `name_key ‖ vault_sk ‖ config_sk` | 134 | `read` |
| 6 | full | `name_key ‖ vault_sk ‖ config_sk ‖ secret_writer ‖ config_writer` | 198 | the owner, `admin` |
| 7 | child | `node_key` | 70 | a `sealed` entry of the children record (§2.6) |

A scope's bundle MUST be exactly the kind this table gives it. Each kind has
one length: a plaintext of a known kind with any other body length is
refused (`bad_length`), and a kind this client does not know is refused
(`unknown_kind`).

The scope a bundle signature binds is a byte: `meta` 1, `append` 2, `read`
3, `admin` 4, `config` 5, `config-write` 6. The owner's own bundle uses scope
code 0 and the zero token id.

<a id="2.3"></a>
### 2.3 Sealing

A bundle is sealed with libsodium's `crypto_box_seal`: a fresh ephemeral
X25519 key pair `(esk, epk)`, the nonce `BLAKE2b-24(epk ‖ recipient_pk)`, and
`crypto_box` (X25519, XSalsa20-Poly1305), sent as `epk ‖ box`. The seal adds
48 bytes. A token's bundle is sealed to its `token_box` public key
(keys.md#6); the owner's bundle and child keys to the owner box public key
(keys.md#5).

<a id="2.4"></a>
### 2.4 Owner signature

The owner signing key signs:

```
frame("gv/v1/bundle", vault_id(16) ‖ token_id(16) ‖ scope(u8) ‖ generation(u32) ‖ SHA-256(sealed))
```

where `sealed` is the whole sealed box as it travels. On the wire a bundle is
`{"sealed": b64url, "sig": b64url}`. The server verifies this signature
before it stores a bundle, against the token's registered scope (protocol.md#3,
protocol.md#8); only the holder can open the seal.

<a id="2.5"></a>
### 2.5 Opening

A token holder opens its bundle in this order, refusing at the first
failure:
1. the presented owner signing key MUST hash to the vault id in the token
   string (`key_mismatch`);
2. the owner's signature (§2.4) MUST verify for this vault, this token id,
   the token's scope code and the expected generation (`bad_signature`);
3. the seal MUST open with the token's box key (`decrypt_failed`);
4. the version byte MUST be 1 (`unknown_version`), checked before the header
   length; the plaintext MUST hold a whole header (`truncated`);
5. a child key (kind 7) is not a token or owner bundle (`kind_mismatch`);
6. the plaintext MUST name the same vault id, token id and generation
   (`vault_mismatch`, `token_mismatch`, `generation_mismatch`);
7. the kind MUST be known and the body its exact length (`unknown_kind`,
   `bad_length`);
8. the kind MUST be the one its scope gets (`kind_mismatch`);
9. every key it holds MUST have the public half the descriptor names
   (`descriptor_mismatch`).

The owner opens its own bundle the same way, with its own box key, the zero
token id and scope code 0, and MUST refuse any kind other than `full`
(`kind_mismatch`). A bundle whose keys have not passed step 9 MUST NOT be
used to encrypt, decrypt, sign or verify.

<a id="2.6"></a>
### 2.6 Child keys

When a rekey re-roots a child (protocol.md#9), its random node key is sealed
(§2.3) to the parent's owner box key as a kind 7 plaintext naming the
parent's vault id, the zero token id and generation 0, with the 32-byte node
key as its body. It is not signed on its own: it travels as `key_ct` inside
the owner-signed children record (§5). The parent's owner opens it with the
checks of §2.5 steps 3 to 7: the parent's vault id, the zero token id,
generation 0, kind 7 (any other kind is `kind_mismatch`), a 32-byte body
(`bad_length`).

<a id="3"></a>
## 3. Record envelope v3

Secret values and config documents are an envelope, encrypted with age.
Vectors: `testdata/vectors/v1/envelopes.json` (encoding both ways; age
ciphertexts in the open direction).

<a id="3.1"></a>
### 3.1 Plaintext

```
secret = 3 ‖ kind(1) = 1 ‖ vault_id(16) ‖ generation(u32) ‖ version(u64)
         ‖ written_at(i64) ‖ name_len(u16) ‖ name ‖ value
config = 3 ‖ kind(1) = 2 ‖ format(1) ‖ vault_id(16) ‖ generation(u32) ‖ version(u64)
         ‖ written_at(i64) ‖ name_len(u16) ‖ name ‖ body
```

| Field | Length | Meaning |
|---|---|---|
| version | 1 | 1 |
| kind | 1 | 1 secret, 2 config |
| format | 1 | configs only: 1 `toml`, 2 `json`, 3 `yaml`, 4 `text` |
| vault_id | 16 | the vault |
| generation | 4 | the generation whose key encrypted it |
| version | 8 | the record version the writer signed |
| written_at | 8 | the write time the writer signed |
| name_len | 2 | the name's length in bytes, at most 256 |
| name | name_len | the record name, UTF-8 |
| value / body | the rest | exactly the bytes written |

A reader decodes in this order: the version byte (`unknown_version`), the
kind (`unknown_kind`), for a config the format (`unknown_format`), the fixed
fields (`truncated`), the name length, which MUST NOT exceed 256
(`bad_length`), the name itself (`truncated` if it runs past the end), and
its UTF-8 (`bad_encoding`). A missing byte anywhere before the body is
`truncated`. The body is never interpreted.

<a id="3.2"></a>
### 3.2 Encryption

The envelope is encrypted with age v1 (<https://age-encryption.org/v1>) in
the binary format (not armored), to exactly one X25519 recipient: the
descriptor's `vault_pub` for a secret, `config_pub` for a config. The raw
32-byte X25519 keys are age's keys: an implementation that needs age's
Bech32 forms encodes the public key with HRP `age` and the secret key with
HRP `AGE-SECRET-KEY-` (upper case). A writer MUST encrypt only to a key a
verified descriptor names (§1.4). The server refuses a value that does not
begin with `age-encryption.org/v1\n` (`not_age_ciphertext`, http-api.md#5)
and can do nothing else with it.

<a id="3.3"></a>
### 3.3 Opening and bindings

A reader opens a value in this order:
1. it MUST begin with the age v1 header line (`unknown_version`);
2. it MUST decrypt with the generation's `vault_sk` or `config_sk`
   (`decrypt_failed`);
3. the plaintext MUST decode (§3.1);
4. then each binding MUST equal what the record signature binds and the
   server reported, in this order: the kind (`kind_mismatch`), the vault id
   (`vault_mismatch`), the generation (`generation_mismatch`), the version
   (`version_mismatch`), the write time (`written_at_mismatch`) and the name
   (`name_mismatch`).

So a ciphertext cannot be moved between vaults, generations, versions,
names or kinds, even by a server that holds every other part of a genuine
record. The record signature (§4) MUST have verified before the value is
used.

<a id="4"></a>
## 4. Record signatures

Every secret and config record, tombstones included, carries an Ed25519
signature by the generation's writer key for its kind, over:

```
frame("gv/v1/record", vault_id(16) ‖ generation(u32) ‖ kind(u8) ‖ name_index(32)
      ‖ version(u64) ‖ written_at(i64) ‖ tombstone(u8) ‖ SHA-256(value_ct) ‖ SHA-256(name_ct))
```

- `kind` is 1 for a secret and 2 for a config; `name_index` is the record's
  index (keys.md#8.1); `name_ct` is the name ciphertext (keys.md#8.3) and
  `value_ct` the age ciphertext.
- A tombstone has no value: `tombstone` is 1 and it signs SHA-256 of the
  empty string. A value has `tombstone` 0.
- Secret records verify only against the descriptor's `secret_writer_pub`,
  config records only against `config_writer_pub`. The writer keys are held
  as §2.2 gives them: the owner and `admin` hold both, `append` holds both,
  `config-write` holds only the config writer, and `meta`, `read` and
  `config` hold none.
- `version` is the version the writer intends to create: 1 under
  `If-None-Match: *` for a new name, `v + 1` under `If-Match: v`, and the
  next version after a tombstone when `If-None-Match: *` revives it
  (protocol.md#6).

The server MUST verify every record signature against the current
descriptor before it stores the record (`bad_signature`), and MUST refuse a
record for any generation but the current one (`stale_generation`). Every
client MUST verify the signature before it trusts a record's metadata or
contents, and MUST refuse a record whose signed version differs from the
version the server reports for it. Listings carry `value_ct_hash`, and
version histories carry `value_ct_hash` and `name_ct_hash`, so a holder that
cannot decrypt (`meta`, `append`, `config`) can still verify the names,
versions and tombstones it relies on. A client SHALL treat a tombstone flag
that disagrees with the presence of a value as an integrity failure. Vectors:
`testdata/vectors/v1/records.json`.

<a id="5"></a>
## 5. Children record

A node's children record says how to reach each child's key. It is
owner-only: sealed to the owner, signed by the owner, and served at its own
endpoint (`GET` and `PUT /v1/vault/children`, http-api.md#2). Vectors:
`testdata/vectors/v1/children.json`.

<a id="5.1"></a>
### 5.1 Plaintext

The plaintext is compact JSON with fields in this order:

```json
{"v":2,"children":[{"seg":"dev","created_at":1757500100,"mode":{"kind":"derived"}},
                   {"seg":"eu","created_at":1757500300,"mode":{"kind":"sealed","key_ct":"<b64url>"}}]}
```

- `v` is the record version, 2. A reader MUST refuse any other
  (`unknown_version`).
- `children` is sorted by segment (formats.md#3); the canonical form a
  writer produces is compact, fields in the order above. A reader MUST
  accept any order and MUST refuse a segment listed twice, an invalid
  segment, an unknown field or an unknown mode (`bad_encoding`).
- `mode` is `{"kind":"derived"}` (the child key is derived from this node's
  key, keys.md#4) or `{"kind":"sealed","key_ct":<b64url>}`, where `key_ct` is
  a kind 7 box (§2.6).

<a id="5.2"></a>
### 5.2 Sealing and signature

The plaintext is sealed (§2.3) to the node's owner box public key. It is
stored and served as `{"version": u64, "ct": b64url, "sig": b64url}`, where
`sig` is the owner's signature over:

```
frame("gv/v1/children", vault_id(16) ‖ version(u64) ‖ SHA-256(ct))
```

`version` follows the preconditions of any record: 1 under
`If-None-Match: *`, `v + 1` under `If-Match: v`. The server MUST refuse a
children write that is not owner-signed for the version it creates, and
MUST refuse any children read or write by a token (`forbidden`). Conformance:
"the children record is owner-only" (README.md#6).

<a id="5.3"></a>
### 5.3 Opening

The owner opens the record in this order: the signature MUST verify for this
vault and the served version (`bad_signature`); the box MUST open with the
owner box key (`decrypt_failed`); the plaintext MUST parse (§5.1). Rediscovery
and path resolution MUST refuse a record that fails any of these
(protocol.md#10). No token holds the owner box key or the owner signing key,
so no token can read or forge the record.

<a id="6"></a>
## 6. Kits

A kit carries one node key, its path and its pinned server: a recovery kit
for a project root, a delegation kit for any node (whose holder then owns
that subtree). It is TOML with exactly these keys:

| Key | Value |
|---|---|
| `v` | the kit version, 2 |
| `kind` | `"recovery"` or `"delegation"` |
| `path` | the node's path (formats.md#3); a project name for a recovery kit |
| `server` | the pinned server URL: `https://…`, or `http://` to a loopback address |
| `key` | the node key as a `gvk1_` string (formats.md#2.3) |

A writer renders it as `crates/galata-vault/src/owner/kit.rs` does, with a
comment header whose first line names the product:

```toml
# galata-vault recovery kit (v1)
#
# Whoever holds this file owns the project "acme" and every environment in it.
# There is no account and no reset: lose every copy of this key and
# the secrets are gone. Keep it offline or in a password manager,
# and never commit it.
v = 1
kind = "recovery"
path = "acme"
server = "https://vault.example"
key = "gvk1_…"
```

A reader MUST accept any TOML document with exactly these keys (comments and
key order do not matter) and checks, in order:
1. it is TOML with exactly these keys and valid values (`bad_encoding`);
2. `v` is 1; any other `v` is refused (`unknown_version`);
3. `server` is one a client may use (`bad_server`);
4. `key` parses as a `gvk1_` string, with the failures of formats.md#2.5; a
   key under another version digit is refused as `unknown_version`
   (formats.md#2.6);
5. a recovery kit's path is a project (`kind_mismatch`).

The vault id is not stored: it is derived from the key. A kit holds the key
itself, so a writer MUST create the file with mode 0600, and error messages
MUST NOT quote a kit's contents. Vectors: `testdata/vectors/v1/kits.json`
(the parse direction).
