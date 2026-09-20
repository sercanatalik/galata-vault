"""The key schedule (keys.md): HKDF with the protocol framing, the key tree, owner
keys and vault ids, token keys, and the name key's two derived keys."""

from .. import proto
from ..prims import checked, derive, frame, seed, sha256


def build(f):
    ikm = seed("hkdf ikm")
    for label, data in [
        ("gv/v1/child", b"prod"), ("gv/v1/owner-sign", b""), ("gv/v1/owner-box", b""),
        ("gv/v1/token-auth", bytes(range(16))), ("gv/v1/token-box", bytes(range(16))),
        ("gv/v1/name-index", b""), ("gv/v1/name-enc", b""),
    ]:
        f.add("hkdf", "keys.md#2", f"HKDF-SHA256, salt galata-vault/v1, info {label} ‖ 0x00 ‖ data",
              {"ikm": ikm.hex(), "label": label, "data": data.hex()},
              outputs={"info": frame(label, data).hex(), "okm": derive(ikm, label, data).hex()})

    roots = [bytes(range(32)), sha256(b"galata-vault test root 2")]
    paths = ["acme", "acme/prod", "acme/prod/eu", "acme/prod/eu/1", "acme/staging-2", "acme/dev"]
    for n, root in enumerate(roots, 1):
        for path in paths:
            node = proto.node_key(root, path)
            o = proto.Owner(node)
            f.add("node", "keys.md#4", f"{path} under test root {n}: node key, owner keys, vault id",
                  {"root_key": root.hex(), "path": path},
                  outputs={
                      "node_key": node.hex(), "gvk1": checked("gvk1_", node),
                      "owner_sign_seed": o.sign_seed.hex(), "owner_sign_pub": o.sign_pub.hex(),
                      "owner_box_secret": o.box_secret.hex(), "owner_box_pub": o.box_pub.hex(),
                      "vault_id": o.vault_id.hex(),
                  })

    for what, pub in [
        ("acme/prod's owner key", proto.Owner(proto.node_key(roots[0], "acme/prod")).sign_pub),
        ("32 zero bytes (hashed, never checked as a point)", bytes(32)),
    ]:
        f.add("vault_id", "keys.md#5", f"the vault id of {what}", {"owner_sign_pub": pub.hex()},
              outputs={"vault_id": proto.vault_id_of(pub).hex()})

    prod = proto.Owner(proto.node_key(roots[0], "acme/prod"))
    for what, t in [
        ("the first test token", proto.Token(bytes(range(16)), prod.vault_id, sha256(b"galata-vault test token secret"))),
        ("all 0xff id, zero vault and secret", proto.Token(b"\xff" * 16, bytes(16), bytes(32))),
        ("the same secret under another id", proto.Token(bytes(range(1, 17)), prod.vault_id, sha256(b"galata-vault test token secret"))),
    ]:
        f.add("token", "keys.md#6", f"{what}: its string and both keys",
              {"token_id": t.id.hex(), "vault_id": t.vault_id.hex(), "secret": t.secret.hex()},
              outputs={
                  "token": t.string, "auth_seed": t.auth_seed.hex(), "auth_pub": t.auth_pub.hex(),
                  "box_secret": t.box_secret.hex(), "box_pub": t.box_pub.hex(),
              })

    name_key = sha256(b"galata-vault test name key")
    f.add("name_keys", "keys.md#8", "the name-index and name-encryption keys of a name key",
          {"name_key": name_key.hex()},
          outputs={"index_key": proto.name_index_key(name_key).hex(),
                   "enc_key": proto.name_enc_key(name_key).hex()})
