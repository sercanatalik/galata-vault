"""An independent implementation of the galata-vault protocol, for test vectors.

It shares no code with the Rust crates. Hashes, HMAC, HKDF and CRC-32 come
from the Python standard library (HKDF is written out from RFC 5869);
BLAKE3 is written out from its specification (`blake3.py`); Ed25519, X25519
and ChaCha20-Poly1305 come from `cryptography` (OpenSSL); XChaCha20-Poly1305
and the sealed box come from PyNaCl (libsodium); age v1 is written out from
its specification (`age.py`) and checked against C2SP CCTV before anything is
generated. See `docs/spec/README.md#5`.
"""
