# C2SP CCTV age vectors (vendored subset)

The independent vector generator in `scripts/vectors/` implements age v1
(the X25519 recipient and the STREAM payload) from the age specification,
<https://age-encryption.org/v1>. Before it generates anything it decrypts
every file here and checks the outcome each one expects
(`docs/spec/README.md#5`).

- **Source:** <https://github.com/C2SP/CCTV>, directory `age/testdata`.
- **Commit:** `4448f2097b2daa812c91a26141f9f36c2096b9ca` (2026-08-29,
  "age: add armor carriage return test vectors").
- **License:** Zero-Clause BSD, CC0 1.0 or Unlicense, at the user's choice;
  see [LICENSE](LICENSE) and [UPSTREAM-README.md](UPSTREAM-README.md), which
  also documents the file format.
- **Subset:** every file whose only identity is an X25519 one and which is
  not ASCII-armored: the `x25519*`, `stream_*`, `hmac_*` and `stanza_*`
  files, `header_crlf`, `version_unsupported` and `empty` (67 files). The
  `armor_*`, `scrypt*` and `hybrid*` files are left out: galata-vault stores
  binary age with one X25519 recipient, and uses neither passphrases, the
  armor nor the post-quantum hybrid recipient.
- **Outcomes covered:** `success`, `no match`, `HMAC failure`,
  `header failure` and `payload failure`.

The files are unchanged. To refresh them, copy the same subset from a newer
CCTV commit and update the commit above.
