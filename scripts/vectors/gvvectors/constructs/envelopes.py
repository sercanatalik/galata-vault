"""Record envelopes v3 (records.md#3): the plaintext encoding both ways, and
age v1 ciphertexts in the open direction (age encryption is randomised)."""

from .. import age, proto
from ..prims import seed, x_pub

VAULT = bytes([0x11] * 16)
VAULT_SK = bytes([0x21] * 32)
CONFIG_SK = bytes([0x22] * 32)
GEN, VERSION, AT = 2, 7, 1_757_500_000


def build(f):
    def encoded(kind, name, body, fmt=None, **kw):
        return proto.envelope(kind, kw.get("vault", VAULT), kw.get("gen", GEN), kw.get("version", VERSION),
                              kw.get("at", AT), name, body, fmt)

    def fields(kind, name, body, fmt=None):
        return {"kind": kind, "format": fmt, "vault_id": VAULT.hex(), "generation": GEN,
                "version": VERSION, "written_at": AT, "name": name.decode(), "body": body.hex()}

    samples = [
        ("secret", b"DATABASE_URL", b"postgres://u:p@h/db", None),
        ("secret", b"EMPTY", b"", None),
        ("secret", b"BINARY", bytes(range(256)), None),
        ("secret", "ünïcode".encode(), b"v", None),
        ("secret", b"n" * 256, b"a 256-byte name", None),
        ("config", b"app", b"[a]\r\nb = 1  \r\n# no final newline", "toml"),
        ("config", b"app.json", b'{"a": 1}', "json"),
        ("config", b"app.yaml", b"a: 1\n", "yaml"),
        ("config", b"notes", b"text", "text"),
    ]
    for kind, name, body, fmt in samples:
        f.add("encode", "records.md#3.1", f"a {kind} envelope for {name[:20].decode()!r}",
              {"kind": kind, "format": fmt, "vault_id": VAULT.hex(), "generation": GEN, "version": VERSION,
               "written_at": AT, "name": name.decode(), "body": body.hex()},
              outputs={"plaintext": encoded(kind, name, body, fmt).hex()})
        f.add("decode", "records.md#3.1", f"a {kind} envelope for {name[:20].decode()!r} decodes",
              {"plaintext": encoded(kind, name, body, fmt).hex()}, outputs=fields(kind, name, body, fmt))

    good = encoded("secret", b"K", b"v")
    for desc, pt, expect in [
        ("empty", b"", "truncated"),
        ("version 4", bytes([4]) + good[1:], "unknown_version"),
        ("version 2", bytes([2, 1]), "unknown_version"),
        ("record kind 9", bytes([proto.ENVELOPE_VERSION, 9]) + good[2:], "unknown_kind"),
        ("config format 9", proto.envelope("config", VAULT, GEN, VERSION, AT, b"a", b"", format_code=9),
         "unknown_format"),
        ("shorter than its fixed fields", good[:20], "truncated"),
        ("a name length of 257", proto.envelope("secret", VAULT, GEN, VERSION, AT, b"n" * 257, b""), "bad_length"),
        ("a name running past the end", good[:-2], "truncated"),
        ("a name that is not UTF-8", proto.envelope("secret", VAULT, GEN, VERSION, AT, b"\xff", b""), "bad_encoding"),
    ]:
        f.add("decode", "records.md#3.1", f"refused: {desc}", {"plaintext": pt.hex()}, expect)

    n = [0]

    def seal(secret_key, plaintext):
        n[0] += 1
        return age.encrypt(x_pub(secret_key), plaintext, file_key=seed(f"age file key {n[0]}")[:16],
                           ephemeral_secret=seed(f"age esk {n[0]}"), nonce=seed(f"age nonce {n[0]}")[:16])

    def open_case(desc, open_as, sk, ct, name, expect="success", outputs=None, **ctx):
        # Every ciphertext here opens with age.py, which CCTV checked, unless
        # it is meant not to.
        if expect not in ("decrypt_failed", "unknown_version"):
            age.decrypt(ct, sk)
        f.add("open", "records.md#3.3", desc,
              {"open_as": open_as, "secret_key": sk.hex(), "value_ct": ct.hex(),
               "vault_id": ctx.get("vault", VAULT).hex(), "generation": ctx.get("gen", GEN),
               "version": ctx.get("version", VERSION), "written_at": ctx.get("at", AT), "name": name},
              expect, outputs)

    db = seal(VAULT_SK, encoded("secret", b"DATABASE_URL", b"postgres://u:p@h/db"))
    open_case("a secret opens and every binding matches", "secret", VAULT_SK, db, "DATABASE_URL",
              outputs={"body": b"postgres://u:p@h/db".hex(), "format": None})
    open_case("an empty secret opens", "secret", VAULT_SK, seal(VAULT_SK, encoded("secret", b"EMPTY", b"")),
              "EMPTY", outputs={"body": "", "format": None})
    big = bytes(range(256)) * 300
    open_case("a secret larger than one 64 KiB STREAM chunk", "secret", VAULT_SK,
              seal(VAULT_SK, encoded("secret", b"BIG", big)), "BIG", outputs={"body": big.hex(), "format": None})
    toml = b"[a]\r\nb = 1  \r\n# no final newline"
    open_case("a config opens byte for byte", "config", CONFIG_SK,
              seal(CONFIG_SK, encoded("config", b"app", toml, "toml")), "app",
              outputs={"body": toml.hex(), "format": "toml"})
    for desc, ct, name, expect, ctx in [
        ("sealed for another vault", seal(VAULT_SK, encoded("secret", b"DATABASE_URL", b"v", vault=bytes([0x99] * 16))),
         "DATABASE_URL", "vault_mismatch", {}),
        ("sealed in another generation", seal(VAULT_SK, encoded("secret", b"DATABASE_URL", b"v", gen=3)),
         "DATABASE_URL", "generation_mismatch", {}),
        ("sealed as another version", seal(VAULT_SK, encoded("secret", b"DATABASE_URL", b"v", version=8)),
         "DATABASE_URL", "version_mismatch", {}),
        ("sealed with another write time", seal(VAULT_SK, encoded("secret", b"DATABASE_URL", b"v", at=AT + 1)),
         "DATABASE_URL", "written_at_mismatch", {}),
        ("sealed under another name", seal(VAULT_SK, encoded("secret", b"DATABASE_URI", b"v")),
         "DATABASE_URL", "name_mismatch", {}),
        ("an envelope of version 4 inside valid age", seal(VAULT_SK, bytes([4]) + encoded("secret", b"K", b"v")[1:]),
         "K", "unknown_version", {}),
    ]:
        open_case(desc, "secret", VAULT_SK, ct, name, expect, **ctx)
    open_case("a secret envelope sealed to the config key", "config", CONFIG_SK,
              seal(CONFIG_SK, encoded("secret", b"app", b"v")), "app", "kind_mismatch")
    open_case("a config envelope with a format this client does not know", "config", CONFIG_SK,
              seal(CONFIG_SK, proto.envelope("config", VAULT, GEN, VERSION, AT, b"app", b"", format_code=9)),
              "app", "unknown_format")
    open_case("opened with the wrong key", "secret", CONFIG_SK, db, "DATABASE_URL", "decrypt_failed")
    open_case("a payload byte changed", "secret", VAULT_SK, db[:-3] + bytes([db[-3] ^ 1]) + db[-2:],
              "DATABASE_URL", "decrypt_failed")
    header_end = db.index(b"\n---")
    mangled = db[:header_end - 4] + bytes([db[header_end - 4] ^ 0x20]) + db[header_end - 3:]
    open_case("a wrapped file key changed", "secret", VAULT_SK, mangled, "DATABASE_URL", "decrypt_failed")
    open_case("a value that is not age v1", "secret", VAULT_SK, b"age-encryption.org/v2\n" + db[22:],
              "DATABASE_URL", "unknown_version")
    open_case("plaintext where age is expected", "secret", VAULT_SK, b"postgres://u:p@h/db", "DATABASE_URL",
              "unknown_version")
