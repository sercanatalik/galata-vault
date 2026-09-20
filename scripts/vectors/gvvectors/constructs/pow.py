"""Proof of work (hosted.md#2): the challenge a hosted server issues and
opens, the hash a client grinds, and verification."""

from .. import proto
from ..prims import seed


def build(f):
    key = seed("pow server key")
    cid = seed("pow challenge id")[:16]
    for difficulty, expires in [(8, 1_757_500_600), (24, 1_757_600_000), (0, 1)]:
        f.add("issue", "hosted.md#2.1", f"a challenge of difficulty {difficulty}",
              {"server_key": key.hex(), "id": cid.hex(), "expires_at": expires, "difficulty": difficulty},
              outputs={"challenge": proto.pow_challenge(key, cid, expires, difficulty)})
    challenge = proto.pow_challenge(key, cid, 1_757_500_600, 8)

    def open_(desc, text, now, expect="success", outputs=None, k=key):
        f.add("open", "hosted.md#2.1", desc, {"challenge": text, "server_key": k.hex(), "now": now}, expect, outputs)

    open_("a challenge opens before it expires", challenge, 1_757_500_000,
          outputs={"id": cid.hex(), "expires_at": 1_757_500_600, "difficulty": 8})
    open_("at its expiry time it still opens", challenge, 1_757_500_600,
          outputs={"id": cid.hex(), "expires_at": 1_757_500_600, "difficulty": 8})
    open_("one second after it expires", challenge, 1_757_500_601, "expired")
    open_("issued under another server key", challenge, 0, "bad_signature", k=seed("another server key"))
    raw = proto.pow_challenge(key, cid, 1_757_500_600, 9)  # a genuine one, then the difficulty edited
    lowered = proto.pow_challenge(key, cid, 1_757_500_600, 8)
    open_("the difficulty edited without the key", raw[:33] + lowered[33:36] + raw[36:], 0, "bad_signature")
    open_("a difficulty above 40, correctly tagged", proto.pow_challenge(key, cid, 1_757_500_600, 41), 0,
          "bad_encoding")
    open_("not base64url", "!!", 0, "bad_encoding")
    open_("one byte short", challenge[:-2], 0, "bad_encoding")

    for nonce in [0, 1, 2**64 - 1]:
        h = proto.pow_hash(challenge, nonce)
        f.add("hash", "hosted.md#2.2", f"the work hash for nonce {nonce}", {"challenge": challenge, "nonce": nonce},
              outputs={"hash": h.hex(), "zero_bits": proto.zero_bits(h)})
    for difficulty in [4, 8, 12]:
        nonce = next(n for n in range(1 << 20) if proto.zero_bits(proto.pow_hash(challenge, n)) >= difficulty)
        f.add("verify", "hosted.md#2.2", f"the first nonce with {difficulty} leading zero bits",
              {"challenge": challenge, "difficulty": difficulty, "nonce": nonce}, outputs={})
        worse = next(n for n in range(1 << 20) if proto.zero_bits(proto.pow_hash(challenge, n)) < difficulty)
        f.add("verify", "hosted.md#2.2", f"a nonce with fewer than {difficulty} leading zero bits",
              {"challenge": challenge, "difficulty": difficulty, "nonce": worse}, "bad_proof")
    f.add("verify", "hosted.md#2.2", "difficulty 0 accepts any nonce",
          {"challenge": challenge, "difficulty": 0, "nonce": 12345}, outputs={})
