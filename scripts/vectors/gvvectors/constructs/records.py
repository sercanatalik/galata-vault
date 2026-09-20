"""Record signatures (records.md#4): what a generation's writer key signs,
and verification without decrypting."""

from .. import proto
from ..prims import ed_pub, ed_sign, seed, sha256


def build(f):
    root = bytes(range(32))
    vault = proto.Owner(proto.node_key(root, "acme/prod")).vault_id
    g = proto.Generation("")
    nk = g.name_key
    name_ct = seed("name ct")
    value_ct = b"age-encryption.org/v1\n" + seed("value ct")

    def ctx(kind="secret", name="DATABASE_URL", version=3, at=1_757_500_123, value=value_ct, gen=1, vid=vault,
            nct=name_ct):
        return {"vault_id": vid.hex(), "generation": gen, "kind": kind,
                "name_index": proto.name_index(nk, kind, name).hex(), "version": version, "written_at": at,
                "name_ct": nct.hex(), "value_ct": None if value is None else value.hex()}

    def input_of(c):
        return proto.record_input(bytes.fromhex(c["vault_id"]), c["generation"], c["kind"],
                                  bytes.fromhex(c["name_index"]), c["version"], c["written_at"],
                                  bytes.fromhex(c["name_ct"]),
                                  None if c["value_ct"] is None else bytes.fromhex(c["value_ct"]))

    for desc, writer, c in [
        ("a secret value, by the secret writer key", g.secret_writer, ctx()),
        ("a secret tombstone: the hash of an empty value, tombstone 1", g.secret_writer, ctx(value=None)),
        ("a config document, by the config writer key", g.config_writer, ctx(kind="config", name="app")),
    ]:
        si = input_of(c)
        value = b"" if c["value_ct"] is None else bytes.fromhex(c["value_ct"])
        f.add("sign", "records.md#4", desc, {"writer_seed": writer.hex(), **c},
              outputs={"writer_pub": ed_pub(writer).hex(), "tombstone": c["value_ct"] is None,
                       "value_ct_hash": sha256(value).hex(), "name_ct_hash": sha256(name_ct).hex(),
                       "signing_input": si.hex(), "sig": ed_sign(writer, si).hex()})

    good = ctx()
    sig = ed_sign(g.secret_writer, input_of(good))

    def verify(desc, writer_pub, c, s, expect="success"):
        f.add("verify", "records.md#4", desc, {"writer_pub": writer_pub.hex(), **c, "sig": s.hex()}, expect,
              {} if expect == "success" else None)

    sw, cw = ed_pub(g.secret_writer), ed_pub(g.config_writer)
    verify("a secret verifies under the secret writer key", sw, good, sig)
    verify("a secret signed by the config writer key", sw, good, ed_sign(g.config_writer, input_of(good)),
           "bad_signature")
    verify("a genuine secret checked against the config writer key", cw, good, sig, "bad_signature")
    verify("the server reports another version", sw, ctx(version=4), sig, "bad_signature")
    verify("presented as a tombstone", sw, ctx(value=None), sig, "bad_signature")
    verify("presented as a config", sw, ctx(kind="config"), sig, "bad_signature")
    verify("moved to another vault", sw, ctx(vid=bytes(16)), sig, "bad_signature")
    verify("moved to another generation", sw, ctx(gen=2), sig, "bad_signature")
    verify("another name ciphertext", sw, ctx(nct=seed("other name ct")), sig, "bad_signature")
    verify("another write time", sw, ctx(at=1), sig, "bad_signature")
