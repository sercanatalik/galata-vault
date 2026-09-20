"""Name indexes and name ciphertexts (keys.md#8). Name ciphertexts are
randomised, so they are vectored in the open direction only."""

from .. import proto
from ..prims import seed, sha256, xchacha_seal


def build(f):
    nk = sha256(b"galata-vault test name key")
    for kind in ["secret", "config"]:
        for name in ["DATABASE_URL", "STRIPE_KEY", "gv:children", "a", "ünïcode"]:
            f.add("index", "keys.md#8.1", f"the {kind} index of {name!r}",
                  {"name_key": nk.hex(), "kind": kind, "name": name},
                  outputs={"index": proto.name_index(nk, kind, name).hex()})

    root = bytes(range(32))
    vault = proto.Owner(proto.node_key(root, "acme/prod")).vault_id
    other_vault = proto.Owner(proto.node_key(root, "acme/dev")).vault_id
    for gen, kind in [(1, "secret"), (7, "config")]:
        f.add("aad", "keys.md#8.2", f"the associated data of a generation {gen} {kind} name",
              {"vault_id": vault.hex(), "generation": gen, "kind": kind},
              outputs={"aad": proto.name_aad(vault, gen, kind).hex()})

    enc = proto.name_enc_key(nk)
    counter = [0]

    def seal(name: bytes, vault_id=vault, gen=1, kind="secret", key=enc) -> bytes:
        counter[0] += 1
        nonce = seed(f"name nonce {counter[0]}")[:24]
        return nonce + xchacha_seal(key, nonce, name, proto.name_aad(vault_id, gen, kind))

    def case(desc, ct, name, expect="success", vault_id=vault, gen=1, kind="secret", key=nk):
        inputs = {"name_key": key.hex(), "vault_id": vault_id.hex(), "generation": gen, "kind": kind,
                  "index": proto.name_index(key, kind, name).hex(), "name_ct": ct.hex()}
        f.add("open", "keys.md#8.3", desc, inputs, expect,
              {"name": name} if expect == "success" else None)

    db = seal(b"DATABASE_URL")
    case("a secret's name opens and matches its index", db, "DATABASE_URL")
    case("a config's name opens", seal(b"app", gen=2, kind="config"), "app", gen=2, kind="config")
    case("a UTF-8 name opens", seal("ünïcode".encode()), "ünïcode")
    case("a name from another vault does not open", seal(b"DATABASE_URL", vault_id=other_vault),
         "DATABASE_URL", "decrypt_failed")
    case("a name from another generation does not open", seal(b"DATABASE_URL", gen=2), "DATABASE_URL",
         "decrypt_failed")
    case("a config's name does not open as a secret's", seal(b"DATABASE_URL", kind="config"),
         "DATABASE_URL", "decrypt_failed")
    case("a flipped tag bit", db[:-1] + bytes([db[-1] ^ 1]), "DATABASE_URL", "decrypt_failed")
    case("shorter than a nonce", db[:23], "DATABASE_URL", "decrypt_failed")
    case("the wrong name key", db, "DATABASE_URL", "decrypt_failed", key=sha256(b"another name key"))
    stripe = seal(b"STRIPE_KEY")
    inputs = {"name_key": nk.hex(), "vault_id": vault.hex(), "generation": 1, "kind": "secret",
              "index": proto.name_index(nk, "secret", "DATABASE_URL").hex(), "name_ct": stripe.hex()}
    f.add("open", "keys.md#8.3", "a genuine name listed under another name's index", inputs,
          "name_mismatch")
    case("a plaintext that is not UTF-8", seal(b"\xff\xfe"), "DATABASE_URL", "decrypt_failed")
