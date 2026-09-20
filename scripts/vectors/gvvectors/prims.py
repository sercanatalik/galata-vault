"""Primitives, from the specification: framing, HKDF, base62 and checksummed
strings, base64url, Ed25519, X25519, the AEADs and the sealed box."""

from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import struct
import zlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import nacl.bindings

SALT = b"galata-vault/v1"
ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


# ------------------------------------------------------------------ bytes


def u8(n: int) -> bytes:
    return struct.pack(">B", n)


def u16(n: int) -> bytes:
    return struct.pack(">H", n)


def u32(n: int) -> bytes:
    return struct.pack(">I", n)


def u64(n: int) -> bytes:
    return struct.pack(">Q", n)


def i64(n: int) -> bytes:
    return struct.pack(">q", n)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def seed(label: str) -> bytes:
    """Fixed test material: SHA-256 of a label."""
    return sha256(("galata-vault test " + label).encode())


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def frame(label: str, *parts: bytes) -> bytes:
    """`label ‖ 0x00 ‖ part₀ ‖ part₁ ‖ …` (keys.md#1)."""
    assert label.startswith("gv/v1/") and "\0" not in label
    return label.encode() + b"\x00" + b"".join(parts)


# ------------------------------------------------------------------ HKDF


def hkdf(ikm: bytes, info: bytes, salt: bytes = SALT, length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256, written out."""
    prk = _hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = _hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive(ikm: bytes, label: str, data: bytes = b"") -> bytes:
    """A derivation: HKDF(ikm, salt "galata-vault/v1", info = frame(label, data))."""
    return hkdf(ikm, frame(label, data))


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    return _hmac.new(key, data, hashlib.sha256).digest()


# ------------------------------------------------------------------ base62


def width_for(n_bytes: int) -> int:
    """The smallest width w with 62^w ≥ 256^n, by exact integer comparison."""
    w = 0
    while 62**w < 256**n_bytes:
        w += 1
    return w


def base62(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    digits = []
    for _ in range(width_for(len(data))):
        n, r = divmod(n, 62)
        digits.append(ALPHABET[r])
    assert n == 0
    return "".join(reversed(digits))


def base62_digits(value: int, width: int) -> str:
    """`value` in exactly `width` base62 digits, whatever it fits in: for
    building strings a decoder must refuse (overflow)."""
    digits = []
    for _ in range(width):
        value, r = divmod(value, 62)
        digits.append(ALPHABET[r])
    return "".join(reversed(digits))


def crc_checksum(prefix: str, body: str) -> str:
    crc = zlib.crc32((prefix + body).encode()) & 0xFFFFFFFF
    return base62(crc.to_bytes(4, "big"))


def checked(prefix: str, data: bytes) -> str:
    body = base62(data)
    return prefix + body + crc_checksum(prefix, body)


# ------------------------------------------------------------------ keys


def ed_pub(seed_: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed_).public_key().public_bytes_raw()


def ed_sign(seed_: bytes, message: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed_).sign(message)


def ed_verify(public: bytes, message: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(sig, message)
        return True
    except Exception:
        return False


def x_pub(secret: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(secret).public_key().public_bytes_raw()


def x_shared(secret: bytes, public: bytes) -> bytes:
    """X25519, or 32 zero bytes where the library refuses a low-order point
    (the caller treats all zeros as the refusal it is)."""
    try:
        return X25519PrivateKey.from_private_bytes(secret).exchange(
            X25519PublicKey.from_public_bytes(public)
        )
    except ValueError:
        return bytes(32)


# ------------------------------------------------------------------ AEADs


def chacha_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    return ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad or None)


def chacha_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes = b"") -> bytes:
    """Raises on failure."""
    return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad or None)


def xchacha_seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """XChaCha20-Poly1305 (libsodium's IETF construction, through PyNaCl)."""
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, key)


def xchacha_open(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return nacl.bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, key)


def sealed_box(recipient_pub: bytes, plaintext: bytes, ephemeral_secret: bytes) -> bytes:
    """libsodium's `crypto_box_seal`, with the ephemeral key given so the
    output is reproducible: `epk ‖ crypto_box(m, nonce = BLAKE2b-24(epk ‖ pk),
    pk, esk)`. Checked below against libsodium's own opener."""
    epk = x_pub(ephemeral_secret)
    nonce = hashlib.blake2b(epk + recipient_pub, digest_size=24).digest()
    return epk + nacl.bindings.crypto_box(plaintext, nonce, recipient_pub, ephemeral_secret)


def sealed_box_open(recipient_secret: bytes, sealed: bytes) -> bytes:
    """libsodium's `crypto_box_seal_open`. Raises on failure."""
    pk = x_pub(recipient_secret)
    return nacl.bindings.crypto_box_seal_open(sealed, pk, recipient_secret)
