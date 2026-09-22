# Keys

Status: **draft** (docs/spec/README.md#1).

How every key is derived, and the registry of every label that separates
one derivation, hash or signature from another. Conventions and notation are
in [README.md#3](README.md#3).

Vectors: `testdata/vectors/v1/keys.json` and `names.json`.

<a id="1"></a>
## 1. Framing

Every HKDF `info`, every hashed input and every signed input of the protocol
is framed:

```
frame(label, field₀, field₁, …) = label ‖ 0x00 ‖ field₀ ‖ field₁ ‖ …
```

- Every label begins `gv/v1/` and contains no `0x00` byte.
- Each label has exactly one purpose ([§3](#3)); a label is never reused
  for another derivation, hash or signature.
- Fields are fixed-width, except at most the last, so no two framed inputs
  of the same label can be read two ways. The `0x00` keeps a label from
  running into its first field.

The request signature's input is a text form, not a frame: its first line
is the label `gv/v1/sig` ([signatures.md#2](signatures.md#2)).

<a id="2"></a>
## 2. HKDF

Every key derivation is HKDF-SHA256 (RFC 5869) with:

- **salt:** the 15 ASCII bytes `galata-vault/v1`;
- **info:** `frame(label, data)` ([§1](#1)), where `data` is empty unless a
  section says otherwise;
- **output:** 32 bytes.

```
derive(ikm, label, data) = HKDF-SHA256(salt = "galata-vault/v1", ikm, info = label ‖ 0x00 ‖ data, L = 32)
```

The input keying material is always 256 bits from a cryptographically
secure random source (a project key, a token secret, a generation's name
key) or a key derived from one. HKDF's extraction is sound for such input; a
password-hardening function would add nothing, and none is used.

<a id="3"></a>
## 3. Label registry

Every label and context string the protocol, key and seal crates use. The
guard `scripts/check-spec-labels.sh` extracts these strings from
`crates/galata_vault::proto`, `crates/galata_vault::keys` and `crates/galata_vault::seal` and fails if the
code uses one this table does not list, or this table lists one the code no
longer uses.

| Label | Kind | Framed inputs | Output and use |
|---|---|---|---|
| `gv/v1/child` | HKDF info | the child's segment (ASCII) | A child node key from its parent's ([§4](#4)) |
| `gv/v1/owner-sign` | HKDF info | none | A node's owner Ed25519 seed ([§5](#5)) |
| `gv/v1/owner-box` | HKDF info | none | A node's owner X25519 secret ([§5](#5)) |
| `gv/v1/token-auth` | HKDF info | token_id(16) | A token's request-signing Ed25519 seed ([§6](#6)) |
| `gv/v1/token-box` | HKDF info | token_id(16) | A token's bundle-opening X25519 secret ([§6](#6)) |
| `gv/v1/name-index` | HKDF info | none | The HMAC key for name indexes, from the name key ([§8.1](#8.1)) |
| `gv/v1/name-enc` | HKDF info | none | The XChaCha20-Poly1305 key for names, from the name key ([§8.3](#8.3)) |
| `gv/v1/name` | hashed input (AEAD associated data) | vault_id(16) ‖ generation(u32) ‖ kind(u8) | A name ciphertext's associated data ([§8.2](#8.2)) |
| `gv/v1/vault-id` | hashed input | owner_sign_pub(32) | SHA-256; its first 16 bytes are the vault id ([§5](#5)) |
| `gv/v1/descriptor` | signing context | the descriptor (189 bytes) | The owner's signature over a generation descriptor ([records.md#1.2](records.md#1.2)) |
| `gv/v1/bundle` | signing context | vault_id ‖ token_id ‖ scope(u8) ‖ generation(u32) ‖ SHA-256(sealed) | The owner's signature over a sealed bundle ([signatures.md#4](signatures.md#4)) |
| `gv/v1/record` | signing context | vault_id ‖ generation ‖ kind ‖ index ‖ version ‖ written_at ‖ tombstone ‖ SHA-256(value_ct) ‖ SHA-256(name_ct) | A writer key's signature over a record ([records.md#4](records.md#4)) |
| `gv/v1/children` | signing context | vault_id ‖ version(u64) ‖ SHA-256(ct) | The owner's signature over the children record ([records.md#5](records.md#5)) |
| `gv/v1/report` | signing context | token_id(16) ‖ ts(i64) | A token-auth signature reporting the token as leaked ([signatures.md#7](signatures.md#7)) |
| `gv/v1/sig` | text first line | the rest of the request signing text | The request signature's input ([signatures.md#2](signatures.md#2)) |
| `galata-vault/v1` | HKDF salt | not framed | The salt of every derivation above ([§2](#2)) |
| `galata-vault v1 audit row` | BLAKE3 derive-key context | not framed | An audit row's hash, in every row format ([audit.md#2](audit.md#2)) |
| `galata-vault v1 proof-of-work` | BLAKE3 derive-key context | not framed | The proof-of-work hash ([hosted.md#2](hosted.md#2)) |

A new derivation, hash or signature MUST get a new label, added to this
table in the same change as the code that uses it.

The labels age v1 uses internally (`age-encryption.org/v1/X25519`, and the
HKDF infos `header` and `payload`) belong to age and are specified by it
(<https://age-encryption.org/v1>); they are not part of this registry.

<a id="4"></a>
## 4. Key tree

- A **project key** is 32 bytes from a cryptographically secure random
  source. It is the root of the project's tree and the node key of its
  project vault.
- A **child node key** is derived from its parent's:

  ```
  K(path/segment) = derive(K(path), "gv/v1/child", segment)
  ```

  where `segment` is the child's segment as ASCII bytes
  ([formats.md#3](formats.md#3)). A node at `acme/prod/eu` is reached from
  `acme` by deriving `prod`, then `eu`.
- Derivation is one-way: holding a node key gives every key beneath it and
  nothing above or beside it.
- A node key MAY also be replaced by a fresh random key when a rekey
  re-roots the node ([protocol.md#9](protocol.md#9)); its parent then
  records it sealed ([records.md#5](records.md#5)).

Every node is exactly one vault.

<a id="5"></a>
## 5. Owner keys and the vault id

From a node key `K`:

```
owner_sign_seed  = derive(K, "gv/v1/owner-sign")    an Ed25519 seed (RFC 8032)
owner_box_secret = derive(K, "gv/v1/owner-box")     an X25519 secret (RFC 7748)
vault_id         = SHA-256(frame("gv/v1/vault-id", owner_sign_pub))[0..16]
```

- `owner_sign_pub` is the Ed25519 public key of the seed, and
  `owner_box_pub` the X25519 public key of the secret, computed with the
  standard scalar clamping.
- The owner signing key signs requests, descriptors, bundles and the
  children record; the owner box key opens the owner's bundle, sealed child
  keys and the children record.
- **The vault id is bound to the owner key.** Only the holder of the owner
  signing key can sign a creation request for its id
  ([protocol.md#2](protocol.md#2)), so nobody can claim another's vault id,
  even after the vault is deleted. A client that pins the id can check any
  owner key a server presents against it, and MUST refuse one that does not
  hash to it (`key_mismatch`).

<a id="6"></a>
## 6. Token keys

A token is minted on the owner's client: a random 16-byte `token_id` and a
random 32-byte `token_secret` ([formats.md#2.4](formats.md#2.4)). From them:

```
token_auth_seed  = derive(token_secret, "gv/v1/token-auth", token_id)   Ed25519: signs requests
token_box_secret = derive(token_secret, "gv/v1/token-box",  token_id)   X25519: opens the bundle
```

- The two keys are independent, and both are bound to the token id.
- The server stores only `token_id`, `auth_pub` and `box_pub`
  ([http-api.md#2](http-api.md#2)). A token authenticates by signing
  requests with its token-auth key; the token string is never sent.
- Nothing a client sends, and nothing a server stores, derives
  `token_box_secret`: a request log, a TLS terminator or a database copy
  holds nothing that opens a token's bundle.

<a id="7"></a>
## 7. Generation keys

A vault's keys change at every rotation; each set is a generation, numbered
from 1. Every generation has five keys, each 32 bytes from a
cryptographically secure random source:

- `vault_sk`, an X25519 secret: opens secret values (the age recipient
  `vault_pub`);
- `config_sk`, an X25519 secret: opens config documents (the age recipient
  `config_pub`);
- `name_key`, 32 bytes: indexes and encrypts record names ([§8](#8));
- `secret_writer`, an Ed25519 seed: signs secret records;
- `config_writer`, an Ed25519 seed: signs config records.

The owner names the four public keys in the generation's descriptor
([records.md#1](records.md#1)) and hands the private keys out in bundles,
each holding exactly what its scope allows ([records.md#2](records.md#2)).
The name key has no public half; a bundle that holds it is checked by the
records it indexes.

<a id="8"></a>
## 8. Name key

Record names are never sent in plaintext. The server indexes a record by an
HMAC of its name, and holds its name encrypted for display.

<a id="8.1"></a>
### 8.1 Index

```
index_key = derive(name_key, "gv/v1/name-index")
index     = HMAC-SHA256(index_key, kind(u8) ‖ name)
```

- `kind` is 1 for a secret and 2 for a config, so one name can be both
  without their indexes colliding.
- `name` is the name's UTF-8 bytes.
- The name key itself is never used as an HMAC key: both uses go through
  HKDF.
- The index travels as 64 hexadecimal characters. It is stable within a
  generation and changes at rotation.

<a id="8.2"></a>
### 8.2 Associated data

```
aad = frame("gv/v1/name", vault_id(16) ‖ generation(u32) ‖ kind(u8))
```

It binds a name ciphertext to its vault, generation and kind, so a
ciphertext cannot be moved between them.

<a id="8.3"></a>
### 8.3 Name ciphertext

```
enc_key = derive(name_key, "gv/v1/name-enc")
name_ct = nonce(24) ‖ XChaCha20-Poly1305(enc_key, nonce, name, aad)
```

- The nonce is 24 bytes from a cryptographically secure random source, new
  for every encryption.
- A name is at most 256 bytes of UTF-8 ([records.md#3](records.md#3)).
- To open a name, a client MUST decrypt it with the associated data of the
  vault, generation and kind it expects, and MUST then recompute the index
  of the decrypted name and compare it with the index the record was listed
  under. A ciphertext shorter than its nonce, one that does not
  authenticate, or a plaintext that is not UTF-8 is `decrypt_failed`; a name
  whose index differs is `name_mismatch`, which catches a server that swaps
  two records' names.

Name ciphertexts are randomised, so their vectors are in the open direction
(`testdata/vectors/v1/names.json`).
