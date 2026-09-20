"""Bundles (records.md#2), opened from fixed sealed bytes: sealed boxes are
randomised, so bundles are vectored in the open direction. The sealed boxes
are libsodium's construction, built with PyNaCl from given ephemeral keys and
checked with libsodium's own opener."""

from .. import proto
from ..prims import ed_pub, ed_sign, seed, sealed_box, sealed_box_open, sha256, x_pub


def build(f):
    root = bytes(range(32))
    owner = proto.Owner(proto.node_key(root, "acme/prod"))
    other = proto.Owner(proto.node_key(root, "acme/dev"))
    g = proto.Generation("")
    keys = g.keys()
    esk = [0]

    def seal(to_secret: bytes, plaintext: bytes) -> bytes:
        esk[0] += 1
        sealed = sealed_box(x_pub(to_secret), plaintext, seed(f"bundle esk {esk[0]}"))
        assert sealed_box_open(to_secret, sealed) == plaintext  # libsodium agrees
        return sealed

    def held(kind: str) -> dict:
        out = {"kind": kind}
        for name in proto.KINDS[kind][1]:
            out[name] = keys[name].hex()
        return out

    def plain(kind: str, token_id: bytes, gen: int = 1, vault_id: bytes | None = None,
              body: list[bytes] | None = None, version: int = 1, kind_code: int | None = None) -> bytes:
        code, names = proto.KINDS.get(kind, (None, []))
        return proto.bundle_plaintext(
            code if kind_code is None else kind_code, vault_id or owner.vault_id, token_id, gen,
            [keys[n] for n in names] if body is None else body, version)

    descriptor = {"generation": 1, **g.publics()}
    tokens = {}
    for n, scope in enumerate(proto.SCOPE_CODES, 1):
        tokens[scope] = proto.Token(bytes([0x10 + n]) * 16, owner.vault_id, seed(f"bundle token {scope}"))

    def token_case(desc, scope, t, sealed, sig, expect="success", gen=1, sign_pub=None, desc_=None,
                   outputs=None):
        inputs = {"token_id": t.id.hex(), "vault_id": t.vault_id.hex(), "token_secret": t.secret.hex(),
                  "owner_sign_pub": (sign_pub or owner.sign_pub).hex(), "scope": scope,
                  "generation": gen, "sealed": sealed.hex(), "sig": sig.hex()}
        if desc_ is not None:
            inputs["descriptor"] = desc_
        f.add("open_token", "records.md#2.5", desc, inputs, expect, outputs)

    def signed(t, scope, sealed, gen=1, code=None, signer=None):
        s = signer or owner
        return s.sign(proto.bundle_input(t.vault_id, t.id, proto.SCOPE_CODES[scope] if code is None else code,
                                         gen, sealed))

    for scope, t in tokens.items():
        kind = proto.SCOPE_KIND[scope]
        sealed = seal(t.box_secret, plain(kind, t.id))
        token_case(f"a {scope} token opens its {kind} bundle, and every key matches the descriptor",
                   scope, t, sealed, signed(t, scope, sealed), desc_=descriptor, outputs=held(kind))

    t = tokens["read"]
    good = seal(t.box_secret, plain("read", t.id))
    token_case("an owner key that does not hash to the token's vault id", "read", t, good,
               signed(t, "read", good, signer=other), "key_mismatch", sign_pub=other.sign_pub)
    token_case("signed for another scope", "read", t, good, signed(t, "admin", good), "bad_signature")
    sig = signed(t, "read", good)
    token_case("a flipped signature bit", "read", t, good, sig[:9] + bytes([sig[9] ^ 1]) + sig[10:],
               "bad_signature")
    token_case("signed for another generation", "read", t, good, signed(t, "read", good, gen=2),
               "bad_signature", gen=1)
    wrong_box = seal(tokens["meta"].box_secret, plain("read", t.id))
    token_case("sealed to another token's box key", "read", t, wrong_box, signed(t, "read", wrong_box),
               "decrypt_failed")
    tampered = good[:60] + bytes([good[60] ^ 1]) + good[61:]
    token_case("a sealed byte changed, and the change signed", "read", t, tampered,
               signed(t, "read", tampered), "decrypt_failed")
    for desc, pt, expect in [
        ("a bundle version this client does not know", plain("read", t.id, version=2), "unknown_version"),
        ("a bundle kind this client does not know", plain("read", t.id, kind_code=9), "unknown_kind"),
        ("a read bundle one key short", plain("read", t.id, body=[keys["name_key"], keys["vault_sk"]]),
         "bad_length"),
        ("a plaintext shorter than the header", plain("read", t.id)[:20], "truncated"),
        ("a child key where a token bundle is expected",
         proto.bundle_plaintext(proto.KIND_CHILD, owner.vault_id, t.id, 1, [seed("child")]), "kind_mismatch"),
        ("a plaintext naming another vault", plain("read", t.id, vault_id=other.vault_id), "vault_mismatch"),
        ("a plaintext naming another token", plain("read", tokens["meta"].id), "token_mismatch"),
        ("a plaintext naming another generation", plain("read", t.id, gen=2), "generation_mismatch"),
        ("a names bundle signed as a read token's", plain("names", t.id), "kind_mismatch"),
    ]:
        sealed = seal(t.box_secret, pt)
        token_case(desc, "read", t, sealed, signed(t, "read", sealed), expect)
    other_gen = {"generation": 1, **proto.Generation(" generation 2").publics()}
    token_case("the bundle's keys are not the ones the descriptor names", "read", t, good,
               signed(t, "read", good), "descriptor_mismatch", desc_=other_gen)

    def owner_case(desc, sealed, sig, expect="success", gen=1, outputs=None):
        f.add("open_owner", "records.md#2.5", desc,
              {"owner_node_key": owner.node.hex(), "generation": gen, "sealed": sealed.hex(),
               "sig": sig.hex()}, expect, outputs)

    own = seal(owner.box_secret, plain("full", proto.OWNER_TOKEN_ID))
    own_sig = owner.sign(proto.bundle_input(owner.vault_id, proto.OWNER_TOKEN_ID, 0, 1, own))
    owner_case("the owner opens its own bundle: token id zero, scope code 0", own, own_sig,
               outputs=held("full"))
    as_token = owner.sign(proto.bundle_input(owner.vault_id, proto.OWNER_TOKEN_ID, 4, 1, own))
    owner_case("the owner's bundle signed with an admin scope code", own, as_token, "bad_signature")
    names = seal(owner.box_secret, plain("names", proto.OWNER_TOKEN_ID))
    owner_case("a names bundle where the owner expects every key", names,
               owner.sign(proto.bundle_input(owner.vault_id, proto.OWNER_TOKEN_ID, 0, 1, names)),
               "kind_mismatch")

    def child_case(desc, sealed, expect="success", outputs=None):
        f.add("open_child", "records.md#2.6", desc,
              {"owner_node_key": owner.node.hex(), "sealed": sealed.hex()}, expect, outputs)

    child = proto.node_key(seed("re-rooted child"), "x")
    ok = seal(owner.box_secret, proto.bundle_plaintext(proto.KIND_CHILD, owner.vault_id, bytes(16), 0, [child]))
    child_case("a re-rooted child's key, sealed to its parent", ok, outputs={"node_key": child.hex()})
    child_case("a child key bound to another parent vault",
               seal(owner.box_secret, proto.bundle_plaintext(proto.KIND_CHILD, other.vault_id, bytes(16), 0, [child])),
               "vault_mismatch")
    child_case("a token bundle where a child key is expected", own, "kind_mismatch")
    child_case("a child key with 64 bytes of body",
               seal(owner.box_secret, proto.bundle_plaintext(proto.KIND_CHILD, owner.vault_id, bytes(16), 0,
                                                             [child, child])), "bad_length")
    child_case("sealed to another owner", seal(other.box_secret, proto.bundle_plaintext(
        proto.KIND_CHILD, owner.vault_id, bytes(16), 0, [child])), "decrypt_failed")
