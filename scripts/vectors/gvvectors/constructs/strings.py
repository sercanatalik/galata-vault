"""Base62, the checksum, and `gvk1_` / `gvt1_` strings (formats.md#2)."""

from .. import proto
from ..prims import base62, checked, crc_checksum, sha256

ENC, CHK, KEY, TOK, PARSE, OTHER = (
    "formats.md#2.1", "formats.md#2.2", "formats.md#2.3", "formats.md#2.4",
    "formats.md#2.5", "formats.md#2.6",
)


def _typo(text: str, i: int) -> str:
    return text[:i] + ("1" if text[i] != "1" else "2") + text[i + 1:]


def _swap(text: str) -> str:
    for i in range(len(text) - 1):
        if text[i] != text[i + 1]:
            return text[:i] + text[i + 1] + text[i] + text[i + 2:]
    raise AssertionError


def build(f):
    samples = [
        ("no bytes", b""), ("one zero byte", b"\0"), ("one 0xff byte", b"\xff"),
        ("the largest 4-byte value (a checksum's width)", b"\xff" * 4),
        ("16 zero bytes", bytes(16)), ("32 bytes 0x00..0x1f", bytes(range(32))),
        ("32 bytes of 0xff", b"\xff" * 32), ("64 bytes", sha256(b"a") + sha256(b"b")),
    ]
    for what, data in samples:
        f.add("base62", ENC, f"base62 of {what}: fixed width, left-padded with 0",
              {"bytes": data.hex()}, outputs={"string": base62(data)})
    body = base62(bytes(range(32)))
    f.add("base62_decode", ENC, "a 32-byte value decodes", {"string": body, "length": 32},
          outputs={"bytes": bytes(range(32)).hex()})
    small = bytes(31) + b"\x01"
    f.add("base62_decode", ENC, "leading zero bytes are kept", {"string": base62(small), "length": 32},
          outputs={"bytes": small.hex()})
    f.add("base62_decode", ENC, "one character short of the width", {"string": body[1:], "length": 32},
          "truncated")
    f.add("base62_decode", ENC, "one character past the width", {"string": "0" + body, "length": 32},
          "bad_length")
    f.add("base62_decode", ENC, "a character outside the alphabet",
          {"string": "-" + body[1:], "length": 32}, "bad_encoding")
    f.add("base62_decode", ENC, "the right width, but a value of 256^32 or more",
          {"string": "z" * 43, "length": 32}, "bad_encoding")
    f.add("checksum", CHK, "the checksum is CRC-32 of the text prefix ‖ body, in 6 base62 characters",
          {"prefix": "gvk1_", "body": body}, outputs={"checksum": crc_checksum("gvk1_", body)})

    root = bytes(range(32))
    keys = [
        ("0x00..0x1f", root), ("of all zero bytes", bytes(32)), ("of all 0xff bytes", b"\xff" * 32),
        ("acme/prod under the first test root", proto.node_key(root, "acme/prod")),
    ]
    for what, k in keys:
        s = checked("gvk1_", k)
        f.add("encode_key", KEY, f"the node key {what}", {"key": k.hex()}, outputs={"string": s})
        f.add("decode_key", KEY, f"the node key {what} parses", {"string": s}, outputs={"key": k.hex()})

    s = checked("gvk1_", root)
    b, c = s[5:48], s[48:]
    token = proto.Token(bytes(range(16)), proto.Owner(proto.node_key(root, "acme/prod")).vault_id,
                        sha256(b"galata-vault test token secret"))
    f.add("decode_key", PARSE, "one body character mistyped", {"string": "gvk1_" + _typo(b, 10) + c},
          "checksum_mismatch")
    f.add("decode_key", PARSE, "one checksum character mistyped", {"string": "gvk1_" + b + _typo(c, 3)},
          "checksum_mismatch")
    f.add("decode_key", PARSE, "two adjacent body characters swapped", {"string": "gvk1_" + _swap(b) + c},
          "checksum_mismatch")
    f.add("decode_key", PARSE, "the last character cut off", {"string": s[:-1]}, "truncated")
    f.add("decode_key", PARSE, "cut off in the middle", {"string": s[:30]}, "truncated")
    f.add("decode_key", PARSE, "one character too many", {"string": s + "0"}, "bad_length")
    f.add("decode_key", PARSE, "a checksum character outside the alphabet",
          {"string": "gvk1_" + b + "-" + c[1:]}, "bad_encoding")
    bad_body = "-" + b[1:]
    f.add("decode_key", PARSE, "a body character outside the alphabet, under a checksum that matches it",
          {"string": "gvk1_" + bad_body + crc_checksum("gvk1_", bad_body)}, "bad_encoding")
    over = "z" * 43
    f.add("decode_key", PARSE, "a body above 2^256, under a checksum that matches it",
          {"string": "gvk1_" + over + crc_checksum("gvk1_", over)}, "bad_encoding")
    f.add("decode_key", OTHER, "a key with another version digit", {"string": checked("gvk2_", root)},
          "unknown_version")
    f.add("decode_key", PARSE, "a token where a node key is expected", {"string": token.string},
          "kind_mismatch")
    f.add("decode_key", PARSE, "the body and checksum with no prefix", {"string": s[5:]}, "kind_mismatch")

    tokens = [
        ("the first test token", token),
        ("all 0xff id, zero vault and secret", proto.Token(b"\xff" * 16, bytes(16), bytes(32))),
        ("a random-looking token", proto.Token(sha256(b"id")[:16], sha256(b"vault")[:16], sha256(b"secret"))),
    ]
    for what, t in tokens:
        f.add("encode_token", TOK, f"{what}: token_id ‖ vault_id ‖ secret",
              {"token_id": t.id.hex(), "vault_id": t.vault_id.hex(), "secret": t.secret.hex()},
              outputs={"string": t.string})
        f.add("decode_token", TOK, f"{what} parses", {"string": t.string},
              outputs={"token_id": t.id.hex(), "vault_id": t.vault_id.hex(), "secret": t.secret.hex()})
    ts = token.string
    tb, tc = ts[5:91], ts[91:]
    f.add("decode_token", PARSE, "one token character mistyped", {"string": "gvt1_" + _typo(tb, 40) + tc},
          "checksum_mismatch")
    f.add("decode_token", PARSE, "a token with its checksum cut off", {"string": ts[:91]}, "truncated")
    f.add("decode_token", OTHER, "a token with another version digit",
          {"string": checked("gvt2_", bytes(range(48)))}, "unknown_version")
    f.add("decode_token", PARSE, "a node key where a token is expected", {"string": s}, "kind_mismatch")
