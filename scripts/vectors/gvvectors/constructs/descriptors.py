"""Generation descriptors (records.md#1): encoding, the owner's signature,
verification from a pinned vault id, and the chain."""

from .. import proto
from ..prims import ed_pub, ed_sign, sha256, x_pub


def _pubs(g: proto.Generation):
    return x_pub(g.vault_sk), x_pub(g.config_sk), ed_pub(g.secret_writer), ed_pub(g.config_writer)


def build(f):
    root = bytes(range(32))
    owner = proto.Owner(proto.node_key(root, "acme/prod"))
    other = proto.Owner(proto.node_key(root, "acme/dev"))
    g1, g2 = proto.Generation(""), proto.Generation(" generation 2")
    d1 = proto.descriptor(owner.vault_id, 1, *_pubs(g1), bytes(32), 1_757_500_000)
    d2 = proto.descriptor(owner.vault_id, 2, *_pubs(g2), sha256(d1), 1_757_600_000)

    for what, gen, g, prev, created in [
        ("generation 1, with a zero previous hash", 1, g1, bytes(32), 1_757_500_000),
        ("generation 2, linked to generation 1", 2, g2, sha256(d1), 1_757_600_000),
    ]:
        vp, cp, sw, cw = _pubs(g)
        enc = proto.descriptor(owner.vault_id, gen, vp, cp, sw, cw, prev, created)
        f.add("encode", "records.md#1.1", f"{what}: bytes, hash and owner signature",
              {"owner_node_key": owner.node.hex(), "generation": gen, "vault_pub": vp.hex(),
               "config_pub": cp.hex(), "secret_writer_pub": sw.hex(), "config_writer_pub": cw.hex(),
               "prev_hash": prev.hex(), "created_at": created},
              outputs={"vault_id": owner.vault_id.hex(), "descriptor": enc.hex(), "hash": sha256(enc).hex(),
                       "signing_input": proto.descriptor_input(enc).hex(),
                       "sig": owner.sign(proto.descriptor_input(enc)).hex()})

    def fields(enc: bytes) -> dict:
        return {"generation": int.from_bytes(enc[17:21], "big"), "vault_pub": enc[21:53].hex(),
                "config_pub": enc[53:85].hex(), "secret_writer_pub": enc[85:117].hex(),
                "config_writer_pub": enc[117:149].hex(), "prev_hash": enc[149:181].hex(),
                "created_at": int.from_bytes(enc[181:189], "big", signed=True)}

    def verify(desc, pinned, sign_pub, enc, sig, expect="success"):
        f.add("verify", "records.md#1.4", desc,
              {"vault_id": pinned.hex(), "owner_sign_pub": sign_pub.hex(), "descriptor": enc.hex(),
               "sig": sig.hex()}, expect, fields(enc) if expect == "success" else None)

    sig1 = owner.sign(proto.descriptor_input(d1))
    verify("generation 1 verifies from its pinned vault id", owner.vault_id, owner.sign_pub, d1, sig1)
    verify("generation 2 verifies", owner.vault_id, owner.sign_pub, d2, owner.sign(proto.descriptor_input(d2)))
    theirs = proto.descriptor(other.vault_id, 1, *_pubs(g1), bytes(32), 1_757_500_000)
    verify("another vault's owner key, correctly signed, for this pinned vault", owner.vault_id,
           other.sign_pub, theirs, other.sign(proto.descriptor_input(theirs)), "key_mismatch")
    verify("the right owner key for another pinned vault", other.vault_id, owner.sign_pub, d1, sig1,
           "key_mismatch")
    verify("signed by this vault's owner, but naming another vault", owner.vault_id, owner.sign_pub,
           theirs, owner.sign(proto.descriptor_input(theirs)), "vault_mismatch")
    verify("a flipped signature bit", owner.vault_id, owner.sign_pub, d1,
           sig1[:5] + bytes([sig1[5] ^ 1]) + sig1[6:], "bad_signature")
    verify("signed by the generation's secret writer key", owner.vault_id, owner.sign_pub, d1,
           ed_sign(g1.secret_writer, proto.descriptor_input(d1)), "bad_signature")
    verify("signed over the bytes without the label", owner.vault_id, owner.sign_pub, d1,
           owner.sign(d1), "bad_signature")
    v0 = bytes([0]) + d1[1:]
    verify("version byte 0, correctly signed", owner.vault_id, owner.sign_pub, v0,
           owner.sign(proto.descriptor_input(v0)), "unknown_version")
    later = bytes([2]) + d1[1:] + b"\x00"
    verify("version byte 2 and one byte longer, correctly signed", owner.vault_id, owner.sign_pub, later,
           owner.sign(proto.descriptor_input(later)), "unknown_version")
    short = d1[:-1]
    verify("one byte short, correctly signed", owner.vault_id, owner.sign_pub, short,
           owner.sign(proto.descriptor_input(short)), "bad_length")

    def follows(desc, prev, nxt, expect="success"):
        f.add("follows", "records.md#1.3", desc, {"prev": prev.hex(), "next": nxt.hex()}, expect,
              {} if expect == "success" else None)

    follows("generation 2 follows generation 1", d1, d2)
    follows("generation 1 does not follow generation 2", d2, d1, "generation_mismatch")
    skip = proto.descriptor(owner.vault_id, 3, *_pubs(g2), sha256(d1), 1_757_600_000)
    follows("a skipped generation", d1, skip, "generation_mismatch")
    fork = proto.descriptor(owner.vault_id, 2, *_pubs(g2), sha256(b"another generation 1"), 1_757_600_000)
    follows("the right generation, linked to another predecessor", d1, fork, "chain_break")
    moved = proto.descriptor(other.vault_id, 2, *_pubs(g2), sha256(d1), 1_757_600_000)
    follows("another vault's generation 2", d1, moved, "vault_mismatch")
