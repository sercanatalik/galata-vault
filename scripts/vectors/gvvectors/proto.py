"""The protocol constructions, written from `docs/spec/`: every derivation,
encoding and signing input the vectors need."""

from __future__ import annotations

import hashlib

from . import blake3
from .prims import (
    b64url, derive, ed_pub, ed_sign, frame, hmac_sha256, i64, sha256, u8, u16, u32, u64,
    x_pub, checked,
)

SCOPE_CODES = {"meta": 1, "append": 2, "read": 3, "admin": 4, "config": 5, "config-write": 6}
OWNER_SCOPE_CODE = 0
OWNER_TOKEN_ID = bytes(16)

# Bundle kinds (records.md#2.2) and what each holds, in order.
KINDS = {
    "names": (1, ["name_key"]),
    "append": (2, ["name_key", "secret_writer", "config_writer"]),
    "config": (3, ["name_key", "config_sk"]),
    "config-write": (4, ["name_key", "config_sk", "config_writer"]),
    "read": (5, ["name_key", "vault_sk", "config_sk"]),
    "full": (6, ["name_key", "vault_sk", "config_sk", "secret_writer", "config_writer"]),
}
KIND_CHILD = 7
SCOPE_KIND = {"meta": "names", "append": "append", "config": "config",
              "config-write": "config-write", "read": "read", "admin": "full"}
BUNDLE_VERSION = 1

RECORD_KIND = {"secret": 1, "config": 2}
CONFIG_FORMATS = {"toml": 1, "json": 2, "yaml": 3, "text": 4}
ENVELOPE_VERSION = 1
DESCRIPTOR_VERSION = 1

AUDIT_CONTEXT = "galata-vault v1 audit row"
AUDIT_ACTIONS = {
    "vault_create": 1, "vault_rotate": 2, "vault_delete": 4, "vault_expire": 5,
    "children_write": 6, "token_mint": 10, "token_revoke": 11, "token_report": 12, "token_list": 13,
    "secret_put": 20, "secret_delete": 21, "secret_read": 22,
    "config_write": 30, "config_delete": 31, "config_read": 32,
}
AUDIT_RESULTS = {"ok": 0, "refused": 1}
POW_CONTEXT = "galata-vault v1 proof-of-work"


# ------------------------------------------------------------------ keys (keys.md)


def node_key(root: bytes, path: str) -> bytes:
    key = root
    for segment in path.split("/")[1:]:
        key = derive(key, "gv/v1/child", segment.encode())
    return key


def vault_id_of(sign_pub: bytes) -> bytes:
    return sha256(frame("gv/v1/vault-id", sign_pub))[:16]


class Owner:
    def __init__(self, node: bytes):
        self.node = node
        self.sign_seed = derive(node, "gv/v1/owner-sign")
        self.box_secret = derive(node, "gv/v1/owner-box")
        self.sign_pub = ed_pub(self.sign_seed)
        self.box_pub = x_pub(self.box_secret)
        self.vault_id = vault_id_of(self.sign_pub)

    def sign(self, message: bytes) -> bytes:
        return ed_sign(self.sign_seed, message)


class Token:
    def __init__(self, token_id: bytes, vault_id: bytes, secret: bytes):
        self.id, self.vault_id, self.secret = token_id, vault_id, secret
        self.auth_seed = derive(secret, "gv/v1/token-auth", token_id)
        self.box_secret = derive(secret, "gv/v1/token-box", token_id)
        self.auth_pub = ed_pub(self.auth_seed)
        self.box_pub = x_pub(self.box_secret)
        self.string = checked("gvt1_", token_id + vault_id + secret)

    def sign(self, message: bytes) -> bytes:
        return ed_sign(self.auth_seed, message)


def name_index_key(name_key: bytes) -> bytes:
    return derive(name_key, "gv/v1/name-index")


def name_enc_key(name_key: bytes) -> bytes:
    return derive(name_key, "gv/v1/name-enc")


def name_index(name_key: bytes, kind: str, name: str) -> bytes:
    return hmac_sha256(name_index_key(name_key), bytes([RECORD_KIND[kind]]) + name.encode())


def name_aad(vault_id: bytes, generation: int, kind: str) -> bytes:
    return frame("gv/v1/name", vault_id, u32(generation), bytes([RECORD_KIND[kind]]))


class Generation:
    """A generation's five keys, from fixed seeds."""

    def __init__(self, tag: str):
        self.name_key = sha256(("galata-vault test name key" + tag).encode())
        self.vault_sk = sha256(("galata-vault test vault sk" + tag).encode())
        self.config_sk = sha256(("galata-vault test config sk" + tag).encode())
        self.secret_writer = sha256(("galata-vault test secret writer" + tag).encode())
        self.config_writer = sha256(("galata-vault test config writer" + tag).encode())

    def keys(self) -> dict[str, bytes]:
        return {
            "name_key": self.name_key, "vault_sk": self.vault_sk, "config_sk": self.config_sk,
            "secret_writer": self.secret_writer, "config_writer": self.config_writer,
        }

    def publics(self) -> dict[str, str]:
        return {
            "vault_pub": x_pub(self.vault_sk).hex(),
            "config_pub": x_pub(self.config_sk).hex(),
            "secret_writer_pub": ed_pub(self.secret_writer).hex(),
            "config_writer_pub": ed_pub(self.config_writer).hex(),
        }


# ------------------------------------------------------------------ records.md


def descriptor(vault_id: bytes, generation: int, vault_pub: bytes, config_pub: bytes,
               secret_writer_pub: bytes, config_writer_pub: bytes, prev_hash: bytes,
               created_at: int, version: int = DESCRIPTOR_VERSION) -> bytes:
    return (bytes([version]) + vault_id + u32(generation) + vault_pub + config_pub
            + secret_writer_pub + config_writer_pub + prev_hash + i64(created_at))


def descriptor_input(encoded: bytes) -> bytes:
    return frame("gv/v1/descriptor", encoded)


def bundle_plaintext(kind: int, vault_id: bytes, token_id: bytes, generation: int,
                     keys: list[bytes], version: int = BUNDLE_VERSION) -> bytes:
    return bytes([version, kind]) + vault_id + token_id + u32(generation) + b"".join(keys)


def bundle_input(vault_id: bytes, token_id: bytes, scope_code: int, generation: int,
                 sealed: bytes) -> bytes:
    return frame("gv/v1/bundle", vault_id, token_id, bytes([scope_code]), u32(generation), sha256(sealed))


def envelope(kind: str, vault_id: bytes, generation: int, version: int, written_at: int,
             name: bytes, body: bytes, fmt: str | None = None, env_version: int = ENVELOPE_VERSION,
             kind_code: int | None = None, format_code: int | None = None) -> bytes:
    out = bytes([env_version, RECORD_KIND[kind] if kind_code is None else kind_code])
    if fmt is not None or format_code is not None:
        out += bytes([CONFIG_FORMATS[fmt] if format_code is None else format_code])
    out += vault_id + u32(generation) + u64(version) + i64(written_at)
    out += u16(len(name)) + name + body
    return out


def record_input(vault_id: bytes, generation: int, kind: str, index: bytes, version: int,
                 written_at: int, name_ct: bytes, value_ct: bytes | None) -> bytes:
    return frame(
        "gv/v1/record", vault_id, u32(generation), bytes([RECORD_KIND[kind]]), index,
        u64(version), i64(written_at), bytes([1 if value_ct is None else 0]),
        sha256(value_ct or b""), sha256(name_ct),
    )


def children_input(vault_id: bytes, version: int, ct: bytes) -> bytes:
    return frame("gv/v1/children", vault_id, u64(version), sha256(ct))


def children_plaintext(children: list[dict], v: int = 1) -> str:
    """The canonical JSON: compact, children sorted by segment, fields in
    the order `seg`, `created_at`, `mode`."""
    import json

    ordered = sorted(children, key=lambda c: c["seg"])
    return json.dumps({"v": v, "children": ordered}, separators=(",", ":"))


def report_input(token_id: bytes, ts: int) -> bytes:
    return frame("gv/v1/report", token_id, i64(ts))


# ------------------------------------------------------------------ signatures.md


def request_text(actor: str, method: str, path: str, body: bytes, vault_id: bytes, ts: int,
                 nonce: bytes, if_match: str | None, if_none_match: str | None) -> str:
    return "\n".join([
        "gv/v1/sig", actor, method.upper(), path, hashlib.sha256(body).hexdigest(),
        vault_id.hex(), str(ts), b64url(nonce), if_match or "", if_none_match or "",
    ])


def request_header(actor: str, token_id: bytes | None, vault_id: bytes, ts: int, nonce: bytes,
                   sig: bytes) -> str:
    who = "actor=owner" if token_id is None else f"actor=token,token={token_id.hex()}"
    return f"GV-Sig v=1,{who},vault={vault_id.hex()},ts={ts},nonce={b64url(nonce)},sig={b64url(sig)}"


# ------------------------------------------------------------------ audit.md


def _opt(value: bytes | None) -> bytes:
    return b"\x00" if value is None else b"\x01" + value


def audit_encoding(row: dict) -> bytes:
    out = u8(row["v"])
    actor = row["actor"]
    out += u64(row["seq"]) + i64(row["ts"])
    out += _opt(None if actor["kind"] == "owner" else bytes.fromhex(actor["id"]))
    out += u16(AUDIT_ACTIONS[row["action"]])
    out += _opt(bytes.fromhex(row["name_hmac"]) if row["name_hmac"] else None)
    out += u8(AUDIT_RESULTS[row["result"]])
    out += _opt(bytes.fromhex(row["subject"]) if row.get("subject") else None)
    out += u64(row.get("version", 0))
    out += _opt(bytes.fromhex(row["ct_hash"]) if row.get("ct_hash") else None)
    out += bytes.fromhex(row["prev"])
    return out


def audit_hash(row: dict) -> bytes:
    return blake3.derive_key(AUDIT_CONTEXT, audit_encoding(row))


def audit_row(v: int, seq: int, ts: int, actor: bytes | None, action: str, name: bytes | None,
              result: str, prev: bytes, subject: bytes | None = None, version: int = 0,
              ct_hash: bytes | None = None) -> dict:
    """A row as a server serves it, hash included."""
    row: dict = {}
    row["v"] = v
    row["seq"] = seq
    row["ts"] = ts
    row["actor"] = {"kind": "owner"} if actor is None else {"kind": "token", "id": actor.hex()}
    row["action"] = action
    row["name_hmac"] = name.hex() if name else None
    if subject is not None:
        row["subject"] = subject.hex()
    row["result"] = result
    row["version"] = version
    if ct_hash is not None:
        row["ct_hash"] = ct_hash.hex()
    row["prev"] = prev.hex()
    row["hash"] = audit_hash(row).hex()
    return row


# ------------------------------------------------------------------ hosted.md


def pow_hash(challenge: str, nonce: int) -> bytes:
    return blake3.derive_key(POW_CONTEXT, challenge.encode() + nonce.to_bytes(8, "little"))


def zero_bits(h: bytes) -> int:
    bits = 0
    for b in h:
        if b == 0:
            bits += 8
            continue
        return bits + (8 - b.bit_length())
    return bits


def pow_challenge(server_key: bytes, cid: bytes, expires_at: int, difficulty: int) -> str:
    payload = cid + i64(expires_at) + bytes([difficulty])
    return b64url(payload + blake3.keyed_hash(server_key, payload)[:16])
