"""The children record (records.md#5): its canonical JSON, the owner's
signature, and opening the sealed record (in the open direction)."""

from .. import proto
from ..prims import b64url, ed_sign, seed, sealed_box, sealed_box_open


def build(f):
    root = bytes(range(32))
    owner = proto.Owner(proto.node_key(root, "acme/prod"))
    other = proto.Owner(proto.node_key(root, "acme/dev"))
    g = proto.Generation("")
    kids = [
        {"seg": "staging", "created_at": 1_757_500_200, "mode": {"kind": "derived"}},
        {"seg": "dev", "created_at": 1_757_500_100, "mode": {"kind": "derived"}},
        {"seg": "eu", "created_at": 1_757_500_300, "mode": {"kind": "sealed", "key_ct": b64url(seed("sealed child"))}},
    ]
    canonical = proto.children_plaintext(kids)
    f.add("encode", "records.md#5.1", "three children, sorted by segment, compact JSON",
          {"children": kids}, outputs={"plaintext": canonical})
    f.add("encode", "records.md#5.1", "no children", {"children": []},
          outputs={"plaintext": proto.children_plaintext([])})
    f.add("parse", "records.md#5.1", "a record in any order parses to the canonical one",
          {"plaintext": '{"v":1,"children":' + str(kids).replace("'", '"') + "}"}, outputs={"plaintext": canonical})
    for desc, text, expect in [
        ("version 0", '{"v":0,"children":[]}', "unknown_version"),
        ("version 2", '{"v":2,"children":[]}', "unknown_version"),
        ("a segment listed twice",
         '{"v":1,"children":[{"seg":"a","created_at":1,"mode":{"kind":"derived"}},'
         '{"seg":"a","created_at":2,"mode":{"kind":"derived"}}]}', "bad_encoding"),
        ("an unknown field", '{"v":1,"children":[],"server":"x"}', "bad_encoding"),
        ("an invalid segment", '{"v":1,"children":[{"seg":"Bad","created_at":1,"mode":{"kind":"derived"}}]}',
         "bad_encoding"),
        ("an unknown entry mode", '{"v":1,"children":[{"seg":"a","created_at":1,"mode":{"kind":"linked"}}]}',
         "bad_encoding"),
        ("not JSON", "children", "bad_encoding"),
    ]:
        f.add("parse", "records.md#5.1", f"refused: {desc}", {"plaintext": text}, expect)

    n = [0]

    def seal(to, text: str) -> bytes:
        n[0] += 1
        ct = sealed_box(to.box_pub, text.encode(), seed(f"children esk {n[0]}"))
        assert sealed_box_open(to.box_secret, ct) == text.encode()
        return ct

    ct = seal(owner, canonical)
    sig = owner.sign(proto.children_input(owner.vault_id, 4, ct))
    f.add("sign", "records.md#5.2", "the owner signs frame(gv/v1/children, vault_id ‖ version ‖ SHA-256(ct))",
          {"owner_node_key": owner.node.hex(), "version": 4, "ct": ct.hex()},
          outputs={"signing_input": proto.children_input(owner.vault_id, 4, ct).hex(), "sig": sig.hex()})

    def open_case(desc, version, ct_, sig_, expect="success", outputs=None):
        f.add("open", "records.md#5.3", desc,
              {"owner_node_key": owner.node.hex(), "version": version, "ct": ct_.hex(), "sig": sig_.hex()},
              expect, outputs)

    open_case("the owner opens its children record", 4, ct, sig, outputs={"plaintext": canonical})
    open_case("signed by the secret writer key (what an append token holds)", 4, ct,
              ed_sign(g.secret_writer, proto.children_input(owner.vault_id, 4, ct)), "bad_signature")
    open_case("served as another version", 5, ct, sig, "bad_signature")
    moved = seal(owner, canonical)
    open_case("signed for another vault", 4, moved,
              other.sign(proto.children_input(owner.vault_id, 4, moved)), "bad_signature")
    theirs = seal(other, canonical)
    open_case("sealed to another owner, signed by this one", 4, theirs,
              owner.sign(proto.children_input(owner.vault_id, 4, theirs)), "decrypt_failed")
    old = seal(owner, '{"v":2,"children":[]}')
    open_case("a version 2 record, correctly sealed and signed", 4, old,
              owner.sign(proto.children_input(owner.vault_id, 4, old)), "unknown_version")
    dup = seal(owner, '{"v":1,"children":[{"seg":"a","created_at":1,"mode":{"kind":"derived"}},'
                      '{"seg":"a","created_at":2,"mode":{"kind":"derived"}}]}')
    open_case("a segment listed twice, correctly sealed and signed", 4, dup,
              owner.sign(proto.children_input(owner.vault_id, 4, dup)), "bad_encoding")
