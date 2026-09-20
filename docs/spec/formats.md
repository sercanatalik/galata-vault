# Formats

Status: **draft** (docs/spec/README.md#1).

How values are encoded, the checksummed strings that carry node keys and
tokens, and paths. Conventions and notation are in
[README.md#3](README.md#3).

<a id="1"></a>
## 1. Encodings

<a id="1.1"></a>
### 1.1 Integers

Fixed-width integers inside byte encodings are big-endian: `u8`, `u16`,
`u32`, `u64`, and `i64` in two's complement. The one exception is the
proof-of-work nonce, which is hashed little-endian ([hosted.md#2](hosted.md#2)).
Times are `i64` Unix seconds. In JSON, integers are numbers.

<a id="1.2"></a>
### 1.2 Hex

Fixed-size identifiers (vault ids, token ids, name indexes, hashes) travel in
JSON as lowercase hexadecimal of their exact length: 32 characters for a
16-byte id, 64 for a 32-byte index or hash. A reader MUST refuse any other
length or any character outside `0-9a-f`; it MAY accept upper case.

<a id="1.3"></a>
### 1.3 base64url

Public keys, signatures, ciphertexts and sealed bundles travel in JSON as
base64url (RFC 4648 §5) without padding. A reader MUST refuse padding and
characters outside the alphabet. A 32-byte key or a 64-byte signature MUST
decode to exactly that length.

<a id="1.4"></a>
### 1.4 JSON

Every HTTP body and the children record's plaintext are JSON (RFC 8259) in
UTF-8. Field names are exactly as these documents give them. Which bodies
refuse a field they do not know, and which ignore it, is set by
[http-api.md#7](http-api.md#7); formats that are hashed or signed (the audit
row, the children record) refuse unknown fields.

<a id="2"></a>
## 2. Base62 and checksummed strings

A node key and a token are shown to people, pasted and scanned for, so they
travel as a prefix, a fixed-width base62 body and a checksum. The body is
alphanumeric and the prefix ends in `_`, so a double-click selects the
whole string.

Vectors: `testdata/vectors/v1/strings.json`.

<a id="2.1"></a>
### 2.1 Alphabet and fixed width

- **Alphabet:** `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`,
  in that order: `0` is 0, `A` is 10, `a` is 36.
- **Width:** `n` bytes are encoded in exactly `width(n)` characters, the
  smallest `w` with 62^w ≥ 256^n: 6 for 4 bytes, 43 for 32, 86 for 64, and
  0 for none.
- **Encoding:** the bytes are read as one big-endian unsigned integer and
  written in base62, most significant digit first, left-padded with `0` to
  the width.
- **Decoding:** a decoder MUST refuse a string of any other width
  (`truncated` if it is shorter, `bad_length` if longer), a character outside
  the alphabet (`bad_encoding`), and a value of 256^n or more, which the
  width can hold but `n` bytes cannot (`bad_encoding`).

<a id="2.2"></a>
### 2.2 Checksum

The checksum is CRC-32 (the IEEE polynomial, as computed by zlib's `crc32`)
over the ASCII text `prefix ‖ body`, taken as a 4-byte big-endian value and
encoded in base62 as six characters ([§2.1](#2.1)).

A one-character typo changes one byte of that text, an error burst of at
most 8 bits, and CRC-32 detects every burst of 32 bits or fewer, so every
single-character substitution is caught before any request or storage
lookup. The checksum detects accidents. It is not a security property: anyone
can compute it.

<a id="2.3"></a>
### 2.3 Node keys: `gvk1_`

```
gvk1_ ‖ base62(node key, 32 bytes: 43 characters) ‖ checksum (6 characters)
```

49 characters after the prefix, 54 in all. A node key is a project key or
any key derived beneath one ([keys.md#4](keys.md#4)). Secret scanners MAY
match `gvk1_[0-9A-Za-z]{49}`; a match is only a candidate until its checksum
verifies.

<a id="2.4"></a>
### 2.4 Tokens: `gvt1_`

```
gvt1_ ‖ base62(token_id(16) ‖ vault_id(16) ‖ token_secret(32): 86 characters) ‖ checksum (6 characters)
```

92 characters after the prefix, 97 in all. The token carries the vault id so
that its holder can pin its vault before the first request
([protocol.md#4](protocol.md#4)). Scanners MAY match
`gvt1_[0-9A-Za-z]{92}`, subject to the checksum.

<a id="2.5"></a>
### 2.5 Parsing

A parser MUST check, in this order, and stop at the first failure:

1. **Version.** A string of the expected kind under another version digit
   (`gvk2_…` where `gvk1_…` is expected) is refused as `unknown_version`
   ([§2.6](#2.6)).
2. **Prefix.** A string that does not begin with the expected prefix is
   refused as `kind_mismatch`, whether it is the other kind's string or has
   no prefix at all.
3. **Length.** The rest MUST be ASCII and exactly `width(n) + 6`
   characters: shorter is `truncated`, longer is `bad_length`.
4. **Checksum characters.** A checksum character outside the alphabet is
   `bad_encoding`.
5. **Checksum.** A checksum that does not match `prefix ‖ body` is
   `checksum_mismatch`.
6. **Body.** The body decodes as in [§2.1](#2.1): a character outside the
   alphabet, or a value too large for `n` bytes, is `bad_encoding`. (With a
   checksum that matches, only a string built to be wrong reaches this
   step.)

The checksum is checked before the body is decoded, so a mistyped string is
reported as mistyped. An implementation MAY trim surrounding whitespace
before parsing, as a convenience; it MUST NOT accept whitespace inside the
string.

<a id="2.6"></a>
### 2.6 Other version digits

The digit in a prefix is the string format's version. A string of the
expected kind under a digit this implementation does not know MUST be
refused as `unknown_version` by its prefix and MUST NOT be reinterpreted.
The refusal SHOULD name the digit it found and MUST NOT quote the string.

<a id="3"></a>
## 3. Paths

A path names a node of a project's key tree: `acme`, `acme/prod`,
`acme/prod/eu`.

- A path is one to four segments joined by `/`. The first segment names the
  project.
- A segment matches `[a-z0-9][a-z0-9-]{0,62}`: lower-case ASCII letters,
  digits and `-`, not starting with `-`, at most 63 characters.
- Anything else is refused as `bad_path`: an empty path, an empty segment
  (a leading, trailing or doubled `/`), an upper-case letter, any other
  character, a segment of 64 characters or more, or more than four segments.
- A path is a derivation input and a display name. A client MUST NOT send it
  to a server: nothing on a server names a project, a path or a node.

The rules are narrow on purpose, so that `Prod` and `prod` cannot become two
different vaults.

Vectors: `testdata/vectors/v1/paths.json`.
