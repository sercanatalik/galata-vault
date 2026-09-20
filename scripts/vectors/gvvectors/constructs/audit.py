"""The audit chain (audit.md): row encodings and hashes, and the
verification algorithm over served pages."""

from .. import proto
from ..prims import sha256

FORMAT = 1


def chain(v: int, specs: list[dict], prev: bytes = bytes(32)) -> list[dict]:
    rows = []
    for s in specs:
        row = proto.audit_row(v, prev=prev, **s)
        rows.append(row)
        prev = bytes.fromhex(row["hash"])
    return rows


def head(row: dict | None):
    return None if row is None else {"seq": row["seq"], "hash": row["hash"]}


def build(f):
    t = bytes([0x42] * 16)
    n = bytes([0x21] * 32)
    specs = [
        dict(seq=1, ts=1_757_500_000, actor=None, action="vault_create", name=None, result="ok",
             ct_hash=sha256(b"descriptor 1")),
        dict(seq=2, ts=1_757_500_001, actor=None, action="token_mint", name=None, result="ok", subject=t),
        dict(seq=3, ts=1_757_500_002, actor=t, action="secret_put", name=n, result="ok", version=1,
             ct_hash=sha256(b"value 1")),
        dict(seq=4, ts=1_757_500_003, actor=t, action="secret_read", name=n, result="refused", version=1),
        dict(seq=5, ts=1_757_500_004, actor=None, action="vault_rotate", name=None, result="ok",
             ct_hash=sha256(b"descriptor 2")),
    ]
    rows = chain(FORMAT, specs)

    for row in rows:
        f.add("row_hash", "audit.md#2", f"{row['action']} by {row['actor']['kind']}", {"row": row},
              outputs={"encoding": proto.audit_encoding(row).hex(), "hash": row["hash"]})

    def verify(desc, known, page_rows, server_head, expect="success", outputs=None, spec="audit.md#5"):
        f.add("verify", spec, desc, {"known": known, "page": {"rows": page_rows, "head": server_head}},
              expect, outputs)

    def ok(h, verified):
        return {"head": h, "verified": verified, "unverifiable_from": None}

    verify("a chain from genesis", None, rows, head(rows[-1]), outputs=ok(head(rows[-1]), 5))
    verify("the continuation of a known head", head(rows[1]), rows[2:], head(rows[-1]),
           outputs=ok(head(rows[-1]), 3))
    verify("nothing new since the known head", head(rows[-1]), [], head(rows[-1]), outputs=ok(head(rows[-1]), 0))
    verify("no head known: from the first row served", None, rows[2:], head(rows[-1]),
           outputs=ok(head(rows[-1]), 3))

    tampered = [dict(r) for r in rows]
    tampered[2]["version"] = 2
    verify("a row's field changed, its hash not", None, tampered, head(rows[-1]), "chain_break")
    rehashed = [dict(r) for r in rows]
    rehashed[2] = proto.audit_row(FORMAT, prev=bytes(32), **{**specs[2]})
    verify("a row rehashed over another predecessor", None, rehashed, head(rows[-1]), "chain_break")
    verify("a row missing", None, rows[:2] + rows[3:], head(rows[-1]), "chain_break")
    verify("a server head the rows do not reach", None, rows[:4], head(rows[-1]), "chain_break")
    verify("the server ends before the known head", head(rows[3]), [], head(rows[2]), "rollback")
    verify("the server shows no rows at all after a known head", head(rows[3]), [], None, "rollback")
    forked = chain(FORMAT, specs[:3] + [dict(specs[3], result="ok")])
    verify("another row at the known head's position", head(rows[3]), [], head(forked[3]), "fork")

    newer = [dict(r) for r in rows]
    newer[3] = {**newer[3], "v": 2, "witness": "a field format 2 adds"}
    verify("a row in format 2: the rows before it verify, the rest are unverifiable", None, newer,
           head(rows[-1]), "unverifiable_newer_format",
           {"head": head(rows[2]), "verified": 3, "unverifiable_from": 4}, spec="audit.md#4")
    unmarked = [dict(r) for r in rows]
    del unmarked[2]["v"]
    verify("a row without a format marker", None, unmarked, head(rows[-1]), "bad_encoding", spec="audit.md#4")
    odd = [dict(r) for r in rows]
    odd[2] = {**odd[2], "action": "vault_teleport"}
    verify("a row naming an action this client does not know", None, odd, head(rows[-1]),
           "unknown_value", spec="audit.md#4")
    stranger = [dict(r) for r in rows]
    stranger[2] = {**stranger[2], "actor": {"kind": "service", "id": "x"}}
    verify("a row naming an actor kind this client does not know", None, stranger, head(rows[-1]),
           "unknown_value", spec="audit.md#4")
    extra = [dict(r) for r in rows]
    extra[1] = {**extra[1], "note": "not hashed"}
    verify("a row with a field format 1 does not have", None, extra, head(rows[-1]), "bad_encoding",
           spec="audit.md#4")
    broken = [dict(r) for r in rows]
    broken[0] = {**broken[0], "seq": "one"}
    verify("a row whose seq is not a number", None, broken, head(rows[-1]), "bad_encoding", spec="audit.md#4")
