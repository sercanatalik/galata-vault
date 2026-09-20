"""Kits (records.md#6): a node key, its path and its pinned server, as TOML."""

from .. import proto
from ..prims import checked, sha256

HEADER = """# galata-vault {kind} kit (v1)
#
# Whoever holds this file owns {what}.
# There is no account and no reset: lose every copy of this key and
# the secrets are gone. Keep it offline or in a password manager,
# and never commit it.
"""


def kit(kind: str, path: str, server: str, key: str, v: int = 1, extra: str = "") -> str:
    what = (f'the project "{path}" and every environment in it' if kind == "recovery"
            else f"{path} and everything beneath it")
    body = f'v = {v}\nkind = "{kind}"\npath = "{path}"\nserver = "{server}"\nkey = "{key}"\n{extra}'
    return HEADER.format(kind=kind, what=what) + body


def build(f):
    root = sha256(b"galata-vault test kit root")
    dev = proto.node_key(root, "acme/dev")
    server = "https://vault.example"

    def parse(desc, text, expect="success", outputs=None):
        f.add("parse", "records.md#6", desc, {"text": text}, expect, outputs)

    rec = checked("gvk1_", root)
    parse("a recovery kit", kit("recovery", "acme", server, rec),
          outputs={"kind": "recovery", "path": "acme", "server": server, "key": root.hex()})
    parse("a delegation kit for an environment", kit("delegation", "acme/dev", "http://127.0.0.1:8750",
                                                     checked("gvk1_", dev)),
          outputs={"kind": "delegation", "path": "acme/dev", "server": "http://127.0.0.1:8750", "key": dev.hex()})
    parse("comments and key order do not matter",
          f'key = "{rec}"\nserver = "{server}"\n# a comment\npath = "acme"\nkind = "recovery"\nv = 1\n',
          outputs={"kind": "recovery", "path": "acme", "server": server, "key": root.hex()})
    parse("kit version 0", kit("recovery", "acme", server, rec, v=0), "unknown_version")
    parse("kit version 2", kit("recovery", "acme", server, rec, v=2), "unknown_version")
    parse("a key with another version digit", kit("recovery", "acme", server, checked("gvk2_", root)),
          "unknown_version")
    typo = rec[:10] + ("1" if rec[10] != "1" else "2") + rec[11:]
    parse("a mistyped key", kit("recovery", "acme", server, typo), "checksum_mismatch")
    parse("a plain http server off loopback", kit("recovery", "acme", "http://vault.example", rec), "bad_server")
    parse("a recovery kit for an environment", kit("recovery", "acme/dev", server, checked("gvk1_", dev)),
          "kind_mismatch")
    parse("an unknown field", kit("recovery", "acme", server, rec, extra='note = "x"\n'), "bad_encoding")
    parse("not TOML", "v = 1\nkind = recovery\n", "bad_encoding")
