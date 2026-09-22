# The galata-vault protocol: specification

Status: **draft** (docs/spec/README.md#1).

This directory is the normative specification of the galata-vault protocol:
the bytes a client and a server exchange and store, the checks each side
makes, and the HTTP API. With it and the test vectors in
`testdata/vectors/v1/`, an implementer can build a client that
interoperates with this repository's server and passes every vector.

<a id="1"></a>
## 1. Status and version

- **Protocol version:** 1. Every string prefix, label, path and version
  marker in these documents is the one protocol version 1 uses
  ([stability.md#2](stability.md#2)).
- **Status:** draft, as of 2026-09-15. A draft may still change, but only as
  [stability.md#3](stability.md#3) allows: never by silently changing bytes
  a version marker already names.
- **The draft marker** is removed only at release 1.0, after the external
  review of the protocol and the client cryptography. From then on the
  rules of [stability.md#4](stability.md#4) apply.

<a id="2"></a>
## 2. Documents

| Document | Covers |
|---|---|
| [README.md](README.md) | Status, conventions, the failure-name registry, the test-vector format, the conformance suite, precedence |
| [formats.md](formats.md) | Encodings, base62 and checksummed strings (`gvk1_`, `gvt1_`), paths |
| [keys.md](keys.md) | Framing, HKDF, the label registry, the key tree, owner, token, generation and name keys |
| [records.md](records.md) | Generation descriptors, bundles, record envelopes, record signatures, the children record, kits |
| [signatures.md](signatures.md) | Every signature: its signing input, signer and verifier; the request signature `GV-Sig` |
| [protocol.md](protocol.md) | The flows: creation, minting, opening, reading, writing, listing, rotation, rekey, rediscovery, revocation |
| [http-api.md](http-api.md) | The `/v1` endpoints, authentication, headers, errors, capabilities, forward compatibility |
| [audit.md](audit.md) | Audit rows, their encoding and hash, row formats, the verification algorithm |
| [hosted.md](hosted.md) | Appendix: proof of work, idle expiry and `X-GV-Expires-At`, rate limits |
| [stability.md](stability.md) | Version markers and the stability policy |

Two companion documents are not normative but are written against this
specification:
- [ARCHITECTURE.md](../../ARCHITECTURE.md): the codemap, and the invariants
  of the implementation;
- [docs/threat-model.md](../threat-model.md): actors, what each can and
  cannot do, and what remains possible.

<a id="3"></a>
## 3. Conventions

- **Keywords.** The key words MUST, MUST NOT, REQUIRED, SHALL, SHALL NOT,
  SHOULD, SHOULD NOT, RECOMMENDED, MAY and OPTIONAL are to be interpreted as
  described in BCP 14 (RFC 2119, RFC 8174) when, and only when, they appear
  in all capitals.
- **Notation.**
  - `a ‖ b` is the concatenation of byte strings.
  - `u8`, `u16`, `u32`, `u64` are unsigned and `i64` is signed two's
    complement; all are big-endian unless a section says otherwise. `x(n)` is
    a field of `n` bytes.
  - Bytes written in prose are lowercase hexadecimal.
  - base64url is RFC 4648 §5, without padding ([formats.md#1.3](formats.md#1.3)).
  - `frame(label, fields…)` is defined in [keys.md#1](keys.md#1).
- **Anchors.** Every numbered section has a stable anchor, written on its
  own line before the heading (`<a id="8.1"></a>`). Cite a section as
  `keys.md#8.1`. Test vectors and conformance cases cite anchors, and a test
  checks that every anchor a vector cites exists. Anchors are never
  renumbered; a section that is removed keeps its number as a stub that says
  so.

<a id="4"></a>
## 4. Failure names

Test vectors name the failure an implementation must meet with one of these
names. An implementation maps its own errors onto them; its error types and
messages are its own. Names are only ever added to this registry: none is
renamed, removed or given another meaning.

| Name | Meaning |
|---|---|
| `checksum_mismatch` | A checksummed string's checksum does not match its prefix and body ([formats.md#2.2](formats.md#2.2)). |
| `bad_encoding` | Input that is not valid in its encoding: a character outside base62, hex or base64url; a base62 value too large for its width; text that is not UTF-8, JSON or TOML where one is required; a malformed `GV-Sig` header; a JSON document with a missing, repeated or unknown field where the format is strict; a proof-of-work challenge that does not decode or states a difficulty above the maximum. |
| `bad_length` | A fixed-length field or construct of the wrong length, or longer than its maximum (a base62 or checksummed string with characters past its width, a descriptor of the wrong length, a bundle body that is not its kind's length, an envelope name longer than 256 bytes). |
| `truncated` | Input shorter than its fixed part: a string cut short, a bundle plaintext shorter than its header, an envelope shorter than its fields or name. |
| `unknown_version` | A version marker this implementation does not know: a string or kit under another version digit, a descriptor, bundle, envelope or children-record version byte, a kit `v`, `GV-Sig v=1`, or a value that does not start with the age v1 header. |
| `unknown_kind` | A kind code this implementation does not know: a bundle kind, a record kind. |
| `unknown_format` | A config format code this implementation does not know ([records.md#3](records.md#3)). |
| `kind_mismatch` | A known kind other than the one expected: a string without the expected prefix, a bundle whose kind is not the scope's, a child key where a bundle is expected or the reverse, a secret envelope where a config is expected, a recovery kit for a path below a project. |
| `bad_signature` | An Ed25519 signature that does not verify under the key that must have made it, under the rules of [signatures.md#1](signatures.md#1); also a proof-of-work challenge whose authentication tag does not match ([hosted.md#2](hosted.md#2)). |
| `key_mismatch` | A public key that does not hash to the pinned vault id ([keys.md#5](keys.md#5)). |
| `vault_mismatch` | A descriptor, bundle, envelope or child key that names another vault than the one expected. |
| `token_mismatch` | A bundle that names another token than its holder. |
| `generation_mismatch` | A bundle, envelope or descriptor that names another generation than the one expected, or a descriptor that is not the generation after its predecessor. |
| `version_mismatch` | An envelope that names another record version than the one expected. |
| `written_at_mismatch` | An envelope that names another write time than the one expected. |
| `name_mismatch` | A decrypted name that does not match the index it was listed under, or an envelope that names another record name. |
| `descriptor_mismatch` | A key in a bundle whose public key is not the one the verified descriptor names. |
| `decrypt_failed` | A ciphertext that does not open with the key given: an AEAD, a sealed box or an age file. |
| `chain_break` | A hash link that does not hold: an audit row that is out of sequence, does not link to the row before it, does not hash to its own hash, or ends elsewhere than the server's head; a descriptor that does not link to its predecessor's hash. |
| `rollback` | A server whose audit head is behind the head this client verified before ([audit.md#5](audit.md#5)). |
| `fork` | A server whose audit row at a position this client verified differs from the one it verified. |
| `unverifiable_newer_format` | An audit row in a row format newer than this implementation knows. Not a verdict on the row: the rows before it stand as verified, and the rest are neither verified nor tampered ([audit.md#4](audit.md#4)). |
| `unknown_value` | An audit row, in a known row format, naming an action or actor kind this implementation does not know; the row cannot be hashed, so verification refuses ([audit.md#4](audit.md#4)). |
| `bad_path` | A string that is not a path ([formats.md#3](formats.md#3)). |
| `bad_server` | A server URL a client must not use: not `https://`, and not `http://` to a loopback address. |
| `bad_proof` | A proof-of-work nonce that does not give the challenge's difficulty ([hosted.md#2](hosted.md#2)). |
| `expired` | A proof-of-work challenge opened after its expiry time. |

<a id="5"></a>
## 5. Test vectors

The vectors in `testdata/vectors/v1/` are one JSON file per construct. They
cover every deterministic construct in both directions (encodings,
derivations, indexes, signing inputs, Ed25519 signatures, descriptor bytes,
envelope plaintexts, audit hashes), and every randomised construction (age
files, sealed boxes, name ciphertexts) in the open direction: fixed
ciphertext and key in, the plaintext or the failure out. Negative cases name
their failure from [§4](#4).

<a id="5.1"></a>
### 5.1 File format

Each file is a JSON object, and `testdata/vectors/schema.json` is its JSON
Schema:

```json
{
  "suite": "galata-vault test vectors",
  "protocol": 2,
  "construct": "envelopes",
  "spec": "records.md#3",
  "generator": "scripts/vectors (independent Python: …)",
  "cases": [
    {
      "id": "envelopes-023",
      "description": "a secret opens and every binding matches",
      "spec": "records.md#3.3",
      "op": "open",
      "inputs": { "…": "…" },
      "expect": "success",
      "outputs": { "…": "…" }
    }
  ]
}
```

- `construct` is the file's name; `spec` is the section the file covers.
- `id` is `<construct>-<three digits>`, unique in the file.
- `spec` in a case is the section that case exercises.
- `op` is one of the construct's operations ([§5.2](#5.2)); `inputs` are its
  inputs.
- `expect` is `success` or a failure name from [§4](#4).
- `outputs` is REQUIRED when `expect` is `success`, and holds every output
  the operation produces. On a failure it is OPTIONAL, and holds what an
  implementation still reports (`unverifiable_newer_format` reports the
  verified prefix).

An implementation passes a case when it meets exactly the expected failure
name, or succeeds with exactly the expected outputs. Byte strings are
lowercase hex, text is a JSON string, integers are JSON numbers, and a field
that is absent in the protocol is `null`.

<a id="5.2"></a>
### 5.2 Operations

Inputs and outputs of each construct's operations. Every name below is a
field of `inputs` or `outputs`.

**strings** ([formats.md#2](formats.md#2))

| Op | Inputs | Outputs |
|---|---|---|
| `base62` | `bytes` | `string`: fixed-width base62 |
| `base62_decode` | `string`, `length` (bytes) | `bytes` |
| `checksum` | `prefix`, `body` | `checksum`: six base62 characters |
| `encode_key` / `decode_key` | `key` / `string` | `string` / `key` |
| `encode_token` / `decode_token` | `token_id`, `vault_id`, `secret` / `string` | `string` / `token_id`, `vault_id`, `secret` |

**paths** ([formats.md#3](formats.md#3))

| Op | Inputs | Outputs |
|---|---|---|
| `parse` | `path` | `segments`, `depth`, `project` |

**keys** ([keys.md](keys.md))

| Op | Inputs | Outputs |
|---|---|---|
| `hkdf` | `ikm`, `label`, `data` | `info` (the framed info), `okm` |
| `node` | `root_key`, `path` | `node_key`, `gvk2`, `owner_sign_seed`, `owner_sign_pub`, `owner_box_secret`, `owner_box_pub`, `vault_id` |
| `vault_id` | `owner_sign_pub` | `vault_id` |
| `token` | `token_id`, `vault_id`, `secret` | `token` (the `gvt1_` string), `auth_seed`, `auth_pub`, `box_secret`, `box_pub` |
| `name_keys` | `name_key` | `index_key`, `enc_key` |

**names** ([keys.md#8](keys.md#8))

| Op | Inputs | Outputs |
|---|---|---|
| `index` | `name_key`, `kind` (`secret` or `config`), `name` | `index` |
| `aad` | `vault_id`, `generation`, `kind` | `aad` |
| `open` | `name_key`, `vault_id`, `generation`, `kind`, `index`, `name_ct` | `name` |

**descriptors** ([records.md#1](records.md#1))

| Op | Inputs | Outputs |
|---|---|---|
| `encode` | `owner_node_key`, `generation`, `vault_pub`, `config_pub`, `secret_writer_pub`, `config_writer_pub`, `prev_hash`, `created_at` | `vault_id`, `descriptor`, `hash`, `signing_input`, `sig` |
| `verify` | `vault_id` (pinned), `owner_sign_pub`, `descriptor`, `sig` | the descriptor's fields: `generation`, `vault_pub`, `config_pub`, `secret_writer_pub`, `config_writer_pub`, `prev_hash`, `created_at` |
| `follows` | `prev`, `next` (descriptor bytes) | none |

**bundles** ([records.md#2](records.md#2))

| Op | Inputs | Outputs |
|---|---|---|
| `open_token` | `token_id`, `vault_id`, `token_secret`, `owner_sign_pub`, `scope`, `generation`, `sealed`, `sig`, and optionally `descriptor` (`generation` and the four public keys) | `kind`, `name_key`, and each key the kind holds: `vault_sk`, `config_sk`, `secret_writer`, `config_writer` |
| `open_owner` | `owner_node_key`, `generation`, `sealed`, `sig` | as `open_token` |
| `open_child` | `owner_node_key` (the parent's), `sealed` | `node_key` |

**envelopes** ([records.md#3](records.md#3))

| Op | Inputs | Outputs |
|---|---|---|
| `encode` | `kind`, `format` (`null` for a secret), `vault_id`, `generation`, `version`, `written_at`, `name`, `body` | `plaintext` |
| `decode` | `plaintext` | `kind`, `format`, `vault_id`, `generation`, `version`, `written_at`, `name`, `body` |
| `open` | `open_as` (`secret` or `config`), `secret_key`, `value_ct`, and the expected `vault_id`, `generation`, `version`, `written_at`, `name` | `body`, `format` |

**records** ([records.md#4](records.md#4))

| Op | Inputs | Outputs |
|---|---|---|
| `sign` | `writer_seed`, `vault_id`, `generation`, `kind`, `name_index`, `version`, `written_at`, `name_ct`, `value_ct` (`null` for a tombstone) | `writer_pub`, `tombstone`, `value_ct_hash`, `name_ct_hash`, `signing_input`, `sig` |
| `verify` | `writer_pub`, the fields of `sign` except the seed, `sig` | none |

**children** ([records.md#5](records.md#5))

| Op | Inputs | Outputs |
|---|---|---|
| `encode` | `children` (entries) | `plaintext` (canonical JSON text) |
| `parse` | `plaintext` | `plaintext` (canonical) |
| `sign` | `owner_node_key`, `version`, `ct` | `signing_input`, `sig` |
| `open` | `owner_node_key`, `version`, `ct`, `sig` | `plaintext` (canonical) |

**kits** ([records.md#6](records.md#6))

| Op | Inputs | Outputs |
|---|---|---|
| `parse` | `text` | `kind`, `path`, `server`, `key` (the node key's bytes) |

**signatures** ([signatures.md](signatures.md))

| Op | Inputs | Outputs |
|---|---|---|
| `request` | `signer` (`owner` or `token`), `node_key` or `token_id` and `token_secret`, `vault_id`, `method`, `path`, `body`, `ts`, `nonce`, `if_match`, `if_none_match` | `signing_input` (text), `sig`, `header` |
| `header` | `header` | `actor`, `token`, `vault_id`, `ts`, `nonce`, `sig` |
| `descriptor` | `owner_node_key`, `descriptor` | `signing_input`, `sig` |
| `bundle` | `owner_node_key`, `token_id`, `scope_code`, `generation`, `sealed` | `signing_input`, `sig` |
| `children` | `owner_node_key`, `version`, `ct` | `signing_input`, `sig` |
| `report` | `token_id`, `vault_id`, `token_secret`, `ts` | `signing_input`, `sig` |
| `verify` | `public_key`, `message`, `sig` | none |

**audit** ([audit.md](audit.md))

| Op | Inputs | Outputs |
|---|---|---|
| `row_hash` | `row` (as served) | `encoding` (the bytes hashed), `hash` |
| `verify` | `known` (a head, or `null`), `page` (`rows` and `head`, as served) | `head` (the last verified head), `verified` (rows verified), `unverifiable_from` (`seq` of the first unverifiable row, or `null`) |

**pow** ([hosted.md#2](hosted.md#2))

| Op | Inputs | Outputs |
|---|---|---|
| `issue` | `server_key`, `id`, `expires_at`, `difficulty` | `challenge` |
| `open` | `challenge`, `server_key`, `now` | `id`, `expires_at`, `difficulty` |
| `hash` | `challenge`, `nonce` | `hash`, `zero_bits` |
| `verify` | `challenge`, `difficulty`, `nonce` | none |

<a id="5.3"></a>
### 5.3 The generator

The vectors are generated by `scripts/vectors/`, an independent Python
implementation of the protocol that shares no code with the Rust crates.

- **What it uses.** SHA-256, HMAC, CRC-32 and BLAKE2b from the Python
  standard library, with HKDF written out from RFC 5869; Ed25519, X25519 and
  ChaCha20-Poly1305 from `cryptography` (OpenSSL); XChaCha20-Poly1305 and the
  sealed box from PyNaCl (libsodium). BLAKE3 and age v1 (the X25519
  recipient and the STREAM payload) are written out from their
  specifications. It does not wrap the Rust `age` crate.
- **Checked before it generates.** Before writing any file it decrypts every
  vector of the vendored C2SP CCTV age subset (`testdata/cctv/age/`) and
  requires the outcome each one expects. A disagreement stops generation.
  The BLAKE3 implementation is checked against published values and against
  the audit hashes committed before it existed.
- **Randomness.** Every randomised construction takes its randomness (age
  file keys, ephemeral keys and nonces, sealed-box ephemeral keys, name
  nonces) from fixed seeds, so the files regenerate byte for byte.
- **Commands.**

  ```sh
  uv run --with cryptography --with pynacl scripts/vectors/generate.py          # write the files
  uv run --with cryptography --with pynacl scripts/vectors/generate.py --check  # regenerate and diff
  ```

  CI and `scripts/check-all.sh` run `--check`, which fails, naming the file,
  if a committed file differs from what the generator produces.

<a id="5.4"></a>
### 5.4 Who runs them

Every vector runs in the Rust crate that owns its construct, and again,
every file, through the Python wheel.

| Constructs | Runs in |
|---|---|
| `strings`, `paths`, `audit`, `pow` | `galata_vault::proto` (`crates/galata_vault::proto/tests/vectors.rs`) |
| `keys`, `names`, `descriptors`, `bundles`, `records`, `signatures`, `children` | `galata_vault::keys` (`crates/galata_vault::keys/tests/vectors.rs`) |
| `envelopes` | `galata_vault::seal` (`crates/galata_vault::seal/tests/vectors.rs`) |
| `kits` | `galata-vault` (`crates/galata-vault/tests/vectors.rs`) |
| every file | the Python wheel, through `galata_vault._vectors` (`crates/gv-py/tests/test_vectors.py`) |

- Signing inputs are checked in the crate that holds the signing key, so
  each signature case also reproduces its deterministic Ed25519 signature
  (RFC 8032) byte for byte.
- The runners are compiled only with the cargo feature `vectors`. They are
  pure: inputs in, outputs out, no key kept between calls, no I/O. The
  wheel's `galata_vault._vectors` is private and unsupported; it exists so
  the wheel that ships is the build that is tested.
- The vector tests read `testdata/` at the repository root, so they run in
  the workspace only, and are excluded from the crates' packages.

<a id="6"></a>
## 6. Conformance suite

`crates/gv-conformance` (`publish = false`) checks a server's behaviour
against this specification as a black box.

- **Targets.** `gv-conformance --server <url>` runs over HTTP;
  `gv-conformance --embedded <dir>` runs through the SDK's in-process
  backend on a data directory (a build with the crate's `embedded`
  feature, as `scripts/conformance.sh` makes).
- **Safety.** It refuses a URL whose host is not a loopback address unless
  given `--allow-remote`, before sending any request, because it consumes
  quota and proof of work. It creates its own vaults from random keys and
  deletes them afterwards. It reads the proof-of-work difficulty from the
  server's capabilities.
- **Output.** One line per case: its id, its anchor, then `pass`, `FAIL`
  or `skip`, with the case's title and what it found (for `FAIL`, the
  reason; for `skip`, why it does not apply). Then a summary. It exits 1 if
  any case fails, and 2 on a usage error or a refused target.

<a id="6.1"></a>
### 6.1 Cases

| Id | Anchor | Checks |
|---|---|---|
| C01 | http-api.md#6 | The capabilities: unauthenticated, JSON, the same for every caller, listing protocol `"1"` |
| C02 | protocol.md#2 | The vault lifecycle: creation, status, deletion, and the uniform 401 after it |
| C03 | http-api.md#4.2 | A write without a precondition is 428 `precondition_required` |
| C04 | http-api.md#4.2 | A stale `If-Match`, and `If-None-Match: *` on an existing record, are 412 `precondition_failed`, and nothing is stored |
| C05 | protocol.md#6 | A signed version other than the one the server assigns is 409 `version_mismatch` |
| C06 | protocol.md#7 | History and tombstones: every retained version listed, an earlier version readable, the latest a 404 after a delete |
| C07 | protocol.md#7 | Listing and pagination: metadata only, the tombstone flag, a cursor |
| C08 | http-api.md#2 | Server-side scope policy, for every scope |
| C09 | http-api.md#6 | Quotas as advertised: a value over `max_value_bytes` is refused with `value_too_large` |
| C10 | http-api.md#3 | Uniform 401: a bearer credential, a bad signature, an unknown token and an unknown vault get the same answer |
| C11 | http-api.md#4.4 | Responses a browser will not render: JSON, `nosniff`, `default-src 'none'`, `no-store`, even for `Accept: text/html` (HTTP only) |
| C12 | http-api.md#5 | Error bodies are exactly `{error, message}`, with a documented code and its status |
| C13 | http-api.md#7.1 | A request body with an unknown field is refused with `invalid_request`, and nothing changes |
| C14 | http-api.md#1 | Unknown protocol versions in the path (`/v0`, `/v2`) are 404 |
| C15 | http-api.md#4.1 | A credential in the query string is refused with 400 `credential_in_query` (HTTP only) |
| C16 | protocol.md#8 | A rotation that revokes a token: the new generation verifies, the revoked token is refused |
| C17 | records.md#5 | The children record is owner-only |

The embedded target has no HTTP layer, so it reports C11 and C15 as `skip`,
not applicable; every other case runs on both targets.

<a id="7"></a>
## 7. Precedence

- **The specification is the source of truth.** Where the code and this
  specification disagree, one of them has a defect. It SHALL be resolved by
  a change that updates both.
- **Bytes change only under a new marker.** Any change to bytes a vector
  covers MUST come with a new version marker for the affected format
  ([stability.md#2](stability.md#2)); an existing format is never changed
  silently.
- **Enforcement does not outrank.** The vectors and the conformance suite
  enforce this specification; neither outranks it. A vector that disagrees
  with the text is itself a defect.

These checks turn a drift between the text and the code into a failing
build:

| Check | Holds |
|---|---|
| `scripts/check-spec-labels.sh` | The label registry ([keys.md#3](keys.md#3)) is exactly the set of labels and contexts in the protocol, keys and seal crates, in both directions |
| `crates/galata_vault::proto/tests/spec_tables.rs` | The error-code table ([http-api.md#5](http-api.md#5)) is exactly `ErrorCode`, with each code's status and retry class; every anchor a vector cites exists |
| `crates/galata_vault::server_core/tests/route_table.rs` | The endpoint table ([http-api.md#2](http-api.md#2)) is exactly the server's route table, by method, path and authentication scheme |
| `scripts/check-response-types.sh` | In `galata_vault::proto`, only request bodies, the audit row, and types that never cross the wire as a response (the children record's plaintext, the MCP's configuration) refuse unknown fields ([http-api.md#7](http-api.md#7)) |
| The vector regenerate-and-diff ([§5.3](#5.3)) | The committed vectors are what the independent generator produces |
| The vector tests ([§5.4](#5.4)) | The Rust crates and the Python wheel agree with every vector |
| The conformance suite ([§6](#6)) | A server built from this repository behaves as specified, over HTTP and embedded |

<a id="8"></a>
## 8. Coverage

Every normative rule in these documents is enforced by a vector, a
conformance case or a guard, except the rules below, which are checked by
review.

Rules marked *(unit test)* or *(adversarial test)* are exercised by a
crate's own tests or by the malicious-server harness; this list does not
count those as enforcement.

**formats.md**
- [#1.1](formats.md#1.1)–[#1.4](formats.md#1.4): integer and time
  encodings; exact hex lengths (upper case MAY be accepted); unpadded
  base64url that decodes to an exact length; the general rule that hashed or
  signed formats refuse unknown fields (the children and audit parts have
  vectors).
- [#2.2](formats.md#2.2): the checksum catches every single-character
  substitution *(unit test)*.
- [#2.3](formats.md#2.3)–[#2.5](formats.md#2.5): the scanner patterns
  (MAY); outer whitespace MAY be trimmed, and inner whitespace MUST NOT be
  accepted.
- [#2.6](formats.md#2.6): a refusal of another version digit SHOULD name
  the digit and MUST NOT quote the string.
- [#3](formats.md#3): a path MUST NOT be sent to a server.

**keys.md**
- [#1](keys.md#1): one purpose per label, and fixed-width fields except at
  most the last. The label guard checks which labels exist, not how they are
  framed.
- [#2](keys.md#2), [#4](keys.md#4), [#6](keys.md#6), [#7](keys.md#7): key
  material is random or derived from random 256-bit material; a rekeyed node
  MAY get a fresh random key; nothing on the wire or in storage derives a
  token's box secret *(adversarial test)*.
- [#3](keys.md#3): a new label lands in the same change as the code that
  uses it. The guard checks the set, not the timing.
- [#8.3](keys.md#8.3): a fresh random nonce for every name encryption.

**records.md**
- [#1.3](records.md#1.3): the server refuses a creation descriptor that is
  not generation 1 with a zero `prev_hash`, and a rotation descriptor that
  does not follow the current one.
- [#1.4](records.md#1.4): no key is used before the descriptor verifies.
- [#2.4](records.md#2.4): the server verifies a bundle's owner signature
  before storing it.
- [#2.5](records.md#2.5): the order of checks when an input has several
  faults.
- [#3.2](records.md#3.2): exactly one binary age recipient, named by a
  verified descriptor.
- [#3.3](records.md#3.3), [#4](records.md#4): a record's signature verifies
  before its value is used; the server's `stale_generation` and signature
  refusals; a tombstone flag that disagrees with the value is an integrity
  failure *(adversarial test)*.
- [#5.2](records.md#5.2): the server refuses an owner write of the children
  record whose signature does not verify (C17 checks only that tokens are
  refused).
- [#6](records.md#6): kit files are written with mode 0600, and error
  messages never quote a kit.

**signatures.md**
- [#1](signatures.md#1): a signature with a small-order `R` is refused (the
  non-canonical `s`, identity-key and non-point cases have vectors).
- [#2.1](signatures.md#2.1): a fresh random nonce for every request.
- [#2.3](signatures.md#2.3): the server's order of checks; a nonce is spent
  only after the signature verifies, and is kept until `ts` + 600 s; vault
  expiry is checked before the nonce; `token_expired` only after proof of
  possession.
- [#7](signatures.md#7): the server's handling of a leak report (its signing
  input has vectors).

**audit.md**
- [#1](audit.md#1): which operations append a row, in the same transaction
  as the action.
- [#3](audit.md#3): action codes are never reused or renumbered.
- [#5](audit.md#5): the stored head moves only when verification succeeds,
  and only to the last verified row *(unit and adversarial tests)*; the
  1000-row page limit.

**protocol.md**
- [#2](protocol.md#2): a client refuses a server without protocol `"1"`
  before sending anything authenticated *(unit test)*; proof of work only
  when the capabilities ask; the empty children record written under
  `If-None-Match: *`.
- [#3](protocol.md#3): the server's mint refusals, and the TTL defaults and
  maximums.
- [#4.1](protocol.md#4.1), [#4.2](protocol.md#4.2): the client's opening
  checks and their order, and `unsupported_by_client` for an unknown scope
  *(unit and adversarial tests)*.
- [#5](protocol.md#5), [#6](protocol.md#6): the client's read checks; no
  blind retry after a failed precondition; the server's
  `not_age_ciphertext`, `stale_generation` and `bad_signature` refusals.
- [#8](protocol.md#8): the client's rotation steps, `incomplete_rotation`,
  and a body limit that fits the largest batch.
- [#9](protocol.md#9), [#11](protocol.md#11), [#12](protocol.md#12): the
  rekey steps; journaling inside the transaction, and a 503 when the journal
  fails; every pin rule *(adversarial test)*.

**http-api.md**
- [#1](http-api.md#1): a known path with another method is 400; an
  oversized body is 413 `value_too_large`; what `/healthz` and `/readyz`
  answer.
- [#3.1](http-api.md#3.1)–[#3.3](http-api.md#3.3): the nonce is spent only
  after the signature and skew verify; `token_expired` only after proof of
  possession; a refused scope appends a `refused` audit row.
- [#4.2](http-api.md#4.2): both precondition headers at once, or an
  `If-None-Match` other than `*`, is `invalid_request`; a quoted or weak
  `If-Match` is accepted.
- [#4.5](http-api.md#4.5), [#4.6](http-api.md#4.6): `X-GV-Expires-At` and
  `Retry-After` *(galata_vault::server tests)*.
- [#5.1](http-api.md#5.1): codes are only ever added. The error-table test
  catches a removal or a rename, not a reuse.
- [#6.1](http-api.md#6.1), [#6.3](http-api.md#6.3): `server` absent by
  default, a missing `protocols` read as `["1"]`, a 404 read as an older
  server, and the document fetched once per handle *(unit tests)*; ancestors
  kept alive only when expiry is announced.
- [#7.1](http-api.md#7.1): a new request field is sent only when advertised
  (no such field exists yet).
- [#7.3](http-api.md#7.3): which operations refuse with
  `unsupported_by_client`, the status-class kind of an unknown code, and the
  report of unverifiable audit rows *(unit tests)*.

**hosted.md** (no server in this repository implements the appendix, so
nothing here is covered by a server test)
- [#2](hosted.md#2): with `proof_of_work` null, `/v1/challenges` is 404
  *(galata_vault::server tests)*; the challenge encoding, difficulty and
  expiry have vectors, and the SDK's own admission exercises solving one
  *(galata-vault tests)*.
- [#3](hosted.md#3): that no answer carries `X-GV-Expires-At` and no vault
  expires *(galata_vault::server tests)*; the client's handling of a server
  that announces an expiry *(galata_vault::cli tests)*.
- [#4](hosted.md#4): not covered. No server here limits a request, and
  client addresses reach no database, log or metric
  *(galata_vault::server tests)*.

**stability.md**
- [#2](stability.md#2): a byte change comes with a new marker. The
  regenerate-and-diff catches the byte change, not a missing marker.
- [#3](stability.md#3)–[#5](stability.md#5): the draft rule, the 1.x read
  guarantees, dropping a read only in a major release, and the changelog
  rule.
