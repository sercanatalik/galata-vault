"""BLAKE3, written out from its specification (the BLAKE3 paper, section 2):
hash, keyed hash and key derivation, 32-byte output. Slow, and only for the
short inputs the vectors hash (audit rows, proof-of-work challenges).

Checked at import time against the known-answer values quoted in `SELF_TEST`
and, by the audit generator, against the format 2 row hashes committed
before this implementation existed."""

from __future__ import annotations

import struct

IV = (
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
)
PERMUTATION = (2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8)
CHUNK_START, CHUNK_END, PARENT, ROOT = 1, 2, 4, 8
KEYED_HASH, DERIVE_KEY_CONTEXT, DERIVE_KEY_MATERIAL = 16, 32, 64
BLOCK_LEN, CHUNK_LEN = 64, 1024
MASK = 0xFFFFFFFF


def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & MASK


def _g(s: list[int], a: int, b: int, c: int, d: int, x: int, y: int) -> None:
    s[a] = (s[a] + s[b] + x) & MASK
    s[d] = _rotr(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b] + y) & MASK
    s[d] = _rotr(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & MASK
    s[b] = _rotr(s[b] ^ s[c], 7)


def _compress(cv: list[int], block: list[int], counter: int, block_len: int, flags: int) -> list[int]:
    s = list(cv) + list(IV[:4]) + [counter & MASK, (counter >> 32) & MASK, block_len, flags]
    m = list(block)
    for r in range(7):
        _g(s, 0, 4, 8, 12, m[0], m[1])
        _g(s, 1, 5, 9, 13, m[2], m[3])
        _g(s, 2, 6, 10, 14, m[4], m[5])
        _g(s, 3, 7, 11, 15, m[6], m[7])
        _g(s, 0, 5, 10, 15, m[8], m[9])
        _g(s, 1, 6, 11, 12, m[10], m[11])
        _g(s, 2, 7, 8, 13, m[12], m[13])
        _g(s, 3, 4, 9, 14, m[14], m[15])
        if r < 6:
            m = [m[i] for i in PERMUTATION]
    for i in range(8):
        s[i] ^= s[i + 8]
        s[i + 8] ^= cv[i]
    return s


def _words(block: bytes) -> list[int]:
    return list(struct.unpack("<16I", block.ljust(BLOCK_LEN, b"\0")))


def _chunk_output(key: list[int], chunk: bytes, counter: int, flags: int):
    """The last block of a chunk, uncompressed: (cv, block, counter, len, flags)."""
    cv = list(key)
    blocks = [chunk[i:i + BLOCK_LEN] for i in range(0, len(chunk), BLOCK_LEN)] or [b""]
    for i, block in enumerate(blocks):
        f = flags | (CHUNK_START if i == 0 else 0)
        if i == len(blocks) - 1:
            return cv, _words(block), counter, len(block), f | CHUNK_END
        cv = _compress(cv, _words(block), counter, BLOCK_LEN, f)[:8]
    raise AssertionError


def _hash(key: list[int], data: bytes, flags: int) -> bytes:
    chunks = [data[i:i + CHUNK_LEN] for i in range(0, len(data), CHUNK_LEN)] or [b""]
    outputs = [_chunk_output(key, c, n, flags) for n, c in enumerate(chunks)]

    def cv_of(output) -> list[int]:
        cv, block, counter, block_len, f = output
        return _compress(cv, block, counter, block_len, f)[:8]

    # Merge the tree: the left subtree is the largest power of two of chunks.
    def subtree(outs):
        if len(outs) == 1:
            return outs[0]
        left_n = 1 << ((len(outs) - 1).bit_length() - 1)
        left, right = subtree(outs[:left_n]), subtree(outs[left_n:])
        block = cv_of(left) + cv_of(right)
        return key, block, 0, BLOCK_LEN, flags | PARENT

    cv, block, counter, block_len, f = subtree(outputs)
    words = _compress(cv, block, counter, block_len, f | ROOT)
    return struct.pack("<16I", *words)[:32]


def hash(data: bytes) -> bytes:  # noqa: A001 (the algorithm's name)
    return _hash(list(IV), data, 0)


def keyed_hash(key: bytes, data: bytes) -> bytes:
    assert len(key) == 32
    return _hash(list(struct.unpack("<8I", key)), data, KEYED_HASH)


def derive_key(context: str, material: bytes) -> bytes:
    context_key = _hash(list(IV), context.encode(), DERIVE_KEY_CONTEXT)
    return _hash(list(struct.unpack("<8I", context_key)), material, DERIVE_KEY_MATERIAL)


# Published BLAKE3 values: the empty string and "abc" (both one block).
SELF_TEST = {
    b"": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    b"abc": "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85",
}
for _msg, _want in SELF_TEST.items():
    assert hash(_msg).hex() == _want, f"BLAKE3 self-test failed for {_msg!r}"
