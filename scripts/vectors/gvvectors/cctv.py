"""Run the vendored C2SP CCTV age vectors (`testdata/cctv/age/testdata`)
against `age.py`. Every file must produce exactly the outcome it expects, and
the plaintext it releases (all of it on success, what decrypted before the
failure on a payload failure) must hash to its `payload`."""

from __future__ import annotations

import hashlib
import pathlib
import zlib

from . import age

BECH32_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _bech32_polymod(values: list[int]) -> int:
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        b = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((b >> i) & 1) else 0
    return chk


def bech32_decode(text: str) -> tuple[str, bytes]:
    """BIP 173 Bech32 (not Bech32m), 8-bit payload."""
    text = text.lower()
    hrp, _, data = text.rpartition("1")
    values = [BECH32_CHARSET.index(c) for c in data]
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    if _bech32_polymod(expanded + values) != 1:
        raise ValueError("bad bech32 checksum")
    acc, bits, out = 0, 0, bytearray()
    for v in values[:-6]:
        acc = (acc << 5) | v
        bits += 5
        if bits >= 8:
            bits -= 8
            out.append((acc >> bits) & 0xFF)
    if bits >= 5 or (acc & ((1 << bits) - 1)):
        raise ValueError("bad bech32 padding")
    return hrp, bytes(out)


def parse(path: pathlib.Path):
    raw = path.read_bytes()
    head, _, body = raw.partition(b"\n\n")
    fields: dict[str, list[str]] = {}
    for line in head.decode().splitlines():
        key, _, value = line.partition(": ")
        fields.setdefault(key, []).append(value)
    if fields.get("compressed") == ["zlib"]:
        body = zlib.decompress(body)
    return fields, body


def run(directory: pathlib.Path) -> tuple[int, dict[str, int]]:
    """Check every vector; raise on the first disagreement. Returns the count
    and how many of each outcome were covered."""
    files = sorted(p for p in directory.iterdir() if p.is_file())
    if not files:
        raise SystemExit(f"no CCTV age vectors in {directory}")
    covered: dict[str, int] = {}
    for path in files:
        fields, body = parse(path)
        assert "armored" not in fields and "passphrase" not in fields, path.name
        expect = fields["expect"][0]
        identities = [bech32_decode(i)[1] for i in fields.get("identity", [])]
        got, released = "success", b""
        try:
            if not identities:
                age.parse_header(body)
                raise age.NoMatch("no identity")
            last: age.AgeError | None = None
            for identity in identities:
                try:
                    released = age.decrypt(body, identity)
                    last = None
                    break
                except age.NoMatch as e:
                    last = e
            if last is not None:
                raise last
        except age.PayloadFailure as e:
            got, released = e.outcome, e.released
        except age.AgeError as e:
            got = e.outcome
        if got != expect:
            raise SystemExit(f"CCTV {path.name}: expected {expect!r}, age.py gave {got!r}")
        if "payload" in fields:
            digest = hashlib.sha256(released).hexdigest()
            if digest != fields["payload"][0]:
                raise SystemExit(f"CCTV {path.name}: the released plaintext does not match its payload hash")
        covered[expect] = covered.get(expect, 0) + 1
    return len(files), covered
