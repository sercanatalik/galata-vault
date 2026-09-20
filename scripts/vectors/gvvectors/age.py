"""age v1, written out from its specification (https://age-encryption.org/v1):
the header, the X25519 recipient stanza and the STREAM payload. Binary files
only (no ASCII armor), X25519 identities only.

`decrypt` classifies every failure the way C2SP CCTV's age vectors do, and is
checked against them (`cctv.py`) before any vector is generated. `encrypt`
takes its randomness (the file key, the ephemeral X25519 secret, the payload
nonce) as arguments, so the vectors it produces are reproducible."""

from __future__ import annotations

import base64
import hashlib
import hmac

from . import prims

VERSION_LINE = b"age-encryption.org/v1"
X25519_LABEL = b"age-encryption.org/v1/X25519"
CHUNK = 64 * 1024
TAG = 16
COLUMNS = 64
B64_ALPHABET = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")


class AgeError(Exception):
    outcome = "error"


class HeaderFailure(AgeError):
    outcome = "header failure"


class NoMatch(AgeError):
    outcome = "no match"


class HmacFailure(AgeError):
    outcome = "HMAC failure"


class PayloadFailure(AgeError):
    outcome = "payload failure"

    def __init__(self, message: str, released: bytes):
        super().__init__(message)
        self.released = released


# ------------------------------------------------------------------ base64


def b64decode_canonical(text: bytes) -> bytes:
    """Standard alphabet, no padding, and canonical: re-encoding gives back
    the same text (no stray low bits)."""
    if not all(c in B64_ALPHABET for c in text) or len(text) % 4 == 1:
        raise HeaderFailure("not canonical unpadded base64")
    data = base64.b64decode(text + b"=" * (-len(text) % 4), validate=True)
    if b64encode(data) != text:
        raise HeaderFailure("not canonical base64")
    return data


def b64encode(data: bytes) -> bytes:
    return base64.b64encode(data).rstrip(b"=")


# ------------------------------------------------------------------ header


class Stanza:
    def __init__(self, args: list[bytes], body: bytes):
        self.type = args[0]
        self.args = args[1:]
        self.body = body


def _line(data: bytes, pos: int) -> tuple[bytes, int]:
    end = data.find(b"\n", pos)
    if end < 0:
        raise HeaderFailure("the header is not terminated")
    line = data[pos:end]
    if b"\r" in line:
        raise HeaderFailure("a header line holds a carriage return")
    return line, end + 1


def parse_header(data: bytes) -> tuple[list[Stanza], bytes, bytes, int]:
    """The stanzas, the bytes the MAC covers, the MAC, and where the payload
    starts."""
    line, pos = _line(data, 0)
    if line != VERSION_LINE:
        raise HeaderFailure("unsupported version line")
    stanzas: list[Stanza] = []
    while True:
        start = pos
        line, pos = _line(data, pos)
        if line.startswith(b"---"):
            if not line.startswith(b"--- "):
                raise HeaderFailure("the MAC line has no space")
            mac_text = line[4:]
            if len(mac_text) != 43:
                raise HeaderFailure("the MAC is not 32 bytes")
            mac = b64decode_canonical(mac_text)
            return stanzas, data[:start + 3], mac, pos
        if not line.startswith(b"-> "):
            raise HeaderFailure("a stanza does not start with '-> '")
        args = line[3:].split(b" ")
        for arg in args:
            if not arg or any(c < 0x21 or c > 0x7E for c in arg):
                raise HeaderFailure("an empty or non-printable stanza argument")
        body_text = b""
        while True:
            body_line, pos = _line(data, pos)
            if len(body_line) > COLUMNS:
                raise HeaderFailure("a stanza body line is too long")
            body_text += body_line
            if len(body_line) < COLUMNS:
                break
        stanzas.append(Stanza(args, b64decode_canonical(body_text)))


def _unwrap_x25519(stanza: Stanza, identity: bytes, recipient: bytes) -> bytes | None:
    """The file key, or None when this stanza is not for this identity.
    A malformed X25519 stanza is a header failure."""
    if len(stanza.args) != 1:
        raise HeaderFailure("an X25519 stanza takes one argument")
    share = b64decode_canonical(stanza.args[0])
    if len(share) != 32:
        raise HeaderFailure("an X25519 share is 32 bytes")
    if len(stanza.body) != 32:
        raise HeaderFailure("a wrapped file key is 32 bytes")
    shared = prims.x_shared(identity, share)
    if shared == bytes(32):
        raise HeaderFailure("the X25519 shared secret is zero")
    wrap_key = prims.hkdf(shared, X25519_LABEL, salt=share + recipient)
    try:
        return prims.chacha_open(wrap_key, bytes(12), stanza.body)
    except Exception:
        return None


def _mac_key(file_key: bytes) -> bytes:
    return prims.hkdf(file_key, b"header", salt=b"")


def decrypt(data: bytes, identity: bytes) -> bytes:
    stanzas, mac_input, mac, pos = parse_header(data)
    recipient = prims.x_pub(identity)
    file_key = None
    for stanza in stanzas:
        if stanza.type != b"X25519":
            continue  # another recipient type: not for us
        file_key = _unwrap_x25519(stanza, identity, recipient)
        if file_key is not None:
            break
    if file_key is None:
        raise NoMatch("no stanza unwraps with this identity")
    if not hmac.compare_digest(prims.hmac_sha256(_mac_key(file_key), mac_input), mac):
        raise HmacFailure("the header MAC does not match")
    nonce = data[pos:pos + 16]
    if len(nonce) < 16:
        raise HeaderFailure("the payload nonce is missing")
    return _stream_open(prims.hkdf(file_key, b"payload", salt=nonce), data[pos + 16:])


def _stream_nonce(counter: int, last: bool) -> bytes:
    return counter.to_bytes(11, "big") + (b"\x01" if last else b"\x00")


def _stream_open(key: bytes, ct: bytes) -> bytes:
    """STREAM, reading one encrypted chunk (64 KiB + tag) at a time and
    releasing each chunk's plaintext as soon as it authenticates:

    - a chunk shorter than full length ends the payload: it must open as the
      final chunk, and it may be empty only if it is the first;
    - a full-length chunk opens as a non-final chunk, or else as the final
      one (a payload whose length is a multiple of 64 KiB);
    - after the final chunk nothing may follow, and the payload must end with
      a final chunk.

    On failure, `PayloadFailure.released` is every plaintext byte released
    before it."""
    released = b""
    size = CHUNK + TAG
    pos, counter = 0, 0
    while True:
        chunk = ct[pos:pos + size]
        if not chunk:
            raise PayloadFailure("the payload ends without a final chunk", released)
        if len(chunk) < size:
            if len(chunk) < TAG:
                raise PayloadFailure("a chunk is shorter than its tag", released)
            if len(chunk) == TAG and counter > 0:
                raise PayloadFailure("the final chunk is empty", released)
            try:
                released += prims.chacha_open(key, _stream_nonce(counter, True), chunk)
            except Exception:
                raise PayloadFailure("the final chunk does not open", released) from None
            return released
        try:
            released += prims.chacha_open(key, _stream_nonce(counter, False), chunk)
        except Exception:
            try:
                released += prims.chacha_open(key, _stream_nonce(counter, True), chunk)
            except Exception:
                raise PayloadFailure("a chunk does not open", released) from None
            if pos + size != len(ct):
                raise PayloadFailure("data follows the final chunk", released)
            return released
        pos += size
        counter += 1


# ------------------------------------------------------------------ encrypt


def encrypt(recipient: bytes, plaintext: bytes, *, file_key: bytes,
            ephemeral_secret: bytes, nonce: bytes) -> bytes:
    """One X25519 recipient; the randomness given."""
    assert len(file_key) == 16 and len(nonce) == 16
    share = prims.x_pub(ephemeral_secret)
    shared = prims.x_shared(ephemeral_secret, recipient)
    wrap_key = prims.hkdf(shared, X25519_LABEL, salt=share + recipient)
    body = b64encode(prims.chacha_seal(wrap_key, bytes(12), file_key))
    lines = [body[i:i + COLUMNS] for i in range(0, len(body), COLUMNS)]
    if not lines or len(lines[-1]) == COLUMNS:
        lines.append(b"")
    header = VERSION_LINE + b"\n" + b"-> X25519 " + b64encode(share) + b"\n"
    header += b"".join(line + b"\n" for line in lines) + b"---"
    mac = prims.hmac_sha256(_mac_key(file_key), header)
    out = header + b" " + b64encode(mac) + b"\n" + nonce
    key = prims.hkdf(file_key, b"payload", salt=nonce)
    chunks = [plaintext[i:i + CHUNK] for i in range(0, len(plaintext), CHUNK)] or [b""]
    for counter, chunk in enumerate(chunks):
        out += prims.chacha_seal(key, _stream_nonce(counter, counter == len(chunks) - 1), chunk)
    return out


def payload_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()
