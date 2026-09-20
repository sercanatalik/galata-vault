"""Every signature (signatures.md): the request signature and its header,
and each signing input with its deterministic Ed25519 signature (RFC 8032),
plus the verification rules every verifier applies."""

import hashlib

from .. import proto
from ..prims import b64url, ed_pub, ed_sign, frame, seed, sha256

L = 2**252 + 27742317777372353535851937790883648493


def build(f):
    root = bytes(range(32))
    owner = proto.Owner(proto.node_key(root, "acme/prod"))
    token = proto.Token(bytes(range(16)), owner.vault_id, sha256(b"galata-vault test token secret"))
    nonce = bytes(range(16))
    ts = 1_757_500_000

    def request(desc, who, method, path, body, if_match=None, if_none_match=None):
        actor = "owner" if who == "owner" else f"token:{token.id.hex()}"
        text = proto.request_text(actor, method, path, body, owner.vault_id, ts, nonce, if_match, if_none_match)
        signer = owner if who == "owner" else token
        sig = signer.sign(text.encode())
        header = proto.request_header(actor, None if who == "owner" else token.id, owner.vault_id, ts, nonce, sig)
        inputs = {"signer": who, "method": method, "path": path, "body": body.hex(), "vault_id": owner.vault_id.hex(),
                  "ts": ts, "nonce": nonce.hex(), "if_match": if_match, "if_none_match": if_none_match}
        if who == "owner":
            inputs["node_key"] = owner.node.hex()
        else:
            inputs.update({"token_id": token.id.hex(), "token_secret": token.secret.hex()})
        f.add("request", "signatures.md#2.1", desc, inputs,
              outputs={"signing_input": text, "sig": sig.hex(), "header": header})

    secret = "/v1/secrets/" + "ab" * 32
    request("an owner's PUT under If-Match", "owner", "PUT", secret, b'{"x":1}', if_match="2")
    request("a token's PUT under If-Match", "token", "PUT", secret, b'{"x":1}', if_match="2")
    request("a creation under If-None-Match: *", "owner", "PUT", secret, b'{"x":1}', if_none_match="*")
    request("a GET: no body, and no precondition lines filled", "token", "GET", "/v1/vault", b"")
    request("a query string is signed as sent", "owner", "GET", "/v1/audit?after=5&limit=1000", b"")
    request("the method is upper-cased before signing", "owner", "delete", "/v1/vault", b"")

    def header(desc, text, expect="success", outputs=None):
        f.add("header", "signatures.md#2.2", desc, {"header": text}, expect, outputs)

    sig = owner.sign(b"x")
    oh = proto.request_header("owner", None, owner.vault_id, ts, nonce, sig)
    th = proto.request_header("token", token.id, owner.vault_id, ts, nonce, sig)
    header("an owner's header", oh, outputs={"actor": "owner", "token": None, "vault_id": owner.vault_id.hex(),
                                           "ts": ts, "nonce": nonce.hex(), "sig": sig.hex()})
    header("a token's header", th, outputs={"actor": "token", "token": token.id.hex(),
                                          "vault_id": owner.vault_id.hex(), "ts": ts, "nonce": nonce.hex(),
                                          "sig": sig.hex()})
    header("GV-Sig v=2", oh.replace("v=1", "v=2"), "unknown_version")
    header("a bearer credential", "Bearer gvt1_abc", "bad_encoding")
    header("a parameter twice", oh + f",ts={ts}", "bad_encoding")
    header("an unknown parameter", oh + ",extra=1", "bad_encoding")
    header("no signature", oh.split(",sig=")[0], "bad_encoding")
    header("a token actor without its id", th.replace(f",token={token.id.hex()}", ""), "bad_encoding")
    header("a 15-byte nonce", oh.replace(b64url(nonce), b64url(nonce[:15])), "bad_encoding")

    def sign(op, spec, desc, inputs, message, signer):
        f.add(op, spec, desc, inputs, outputs={"signing_input": message.hex(), "sig": signer.sign(message).hex()})

    g = proto.Generation("")
    from ..prims import ed_pub as _p, x_pub
    d1 = proto.descriptor(owner.vault_id, 1, x_pub(g.vault_sk), x_pub(g.config_sk), _p(g.secret_writer),
                          _p(g.config_writer), bytes(32), 1_757_500_000)
    sign("descriptor", "signatures.md#3", "the owner signs frame(gv/v1/descriptor, descriptor)",
         {"owner_node_key": owner.node.hex(), "descriptor": d1.hex()}, proto.descriptor_input(d1), owner)
    sealed = seed("sealed bundle") * 5
    sign("bundle", "signatures.md#4", "the owner signs a read token's sealed bundle",
         {"owner_node_key": owner.node.hex(), "token_id": (b"\xab" * 16).hex(), "scope_code": 3, "generation": 1,
          "sealed": sealed.hex()},
         proto.bundle_input(owner.vault_id, b"\xab" * 16, 3, 1, sealed), owner)
    sign("bundle", "signatures.md#4", "the owner signs its own bundle: token id zero, scope code 0",
         {"owner_node_key": owner.node.hex(), "token_id": bytes(16).hex(), "scope_code": 0, "generation": 1,
          "sealed": sealed.hex()},
         proto.bundle_input(owner.vault_id, bytes(16), 0, 1, sealed), owner)
    ct = seed("children ct") * 3
    sign("children", "signatures.md#6", "the owner signs the children record at version 2",
         {"owner_node_key": owner.node.hex(), "version": 2, "ct": ct.hex()},
         proto.children_input(owner.vault_id, 2, ct), owner)
    for t in [token, proto.Token(b"\xff" * 16, bytes(16), bytes(32))]:
        f.add("report", "signatures.md#7", "a token-auth key signs frame(gv/v1/report, token_id ‖ ts)",
              {"token_id": t.id.hex(), "vault_id": t.vault_id.hex(), "token_secret": t.secret.hex(), "ts": ts},
              outputs={"signing_input": proto.report_input(t.id, ts).hex(),
                       "sig": t.sign(proto.report_input(t.id, ts)).hex()})

    def verify(desc, pub, msg, sig, expect="success"):
        f.add("verify", "signatures.md#1", desc, {"public_key": pub.hex(), "message": msg.hex(), "sig": sig.hex()},
              expect, {} if expect == "success" else None)

    msg = frame("gv/v1/report", token.id, ts.to_bytes(8, "big"))
    good = token.sign(msg)
    verify("a signature verifies under its key", token.auth_pub, msg, good)
    verify("a flipped signature bit", token.auth_pub, msg, good[:40] + bytes([good[40] ^ 1]) + good[41:],
           "bad_signature")
    verify("another message", token.auth_pub, msg + b"\0", good, "bad_signature")
    verify("another key", owner.sign_pub, msg, good, "bad_signature")
    s = int.from_bytes(good[32:], "little")
    verify("s + L: the same scalar, not reduced (RFC 8032 requires s < L)", token.auth_pub, msg,
           good[:32] + (s + L).to_bytes(32, "little"), "bad_signature")
    # A key of small order (the identity point) makes the cofactorless check
    # [s]B = R + [k]A pass for R = [s]B and any message. Strict verification
    # refuses such a key.
    a = bytearray(hashlib.sha512(seed("small order")).digest()[:32])
    a[0] &= 248
    a[31] &= 127
    a[31] |= 64
    r = ed_pub(seed("small order"))
    forged = r + (int.from_bytes(a, "little") % L).to_bytes(32, "little")
    identity = bytes([1]) + bytes(31)
    verify("a small-order public key (the identity point) accepting anything", identity, msg, forged,
           "bad_signature")
    verify("a public key that is not a curve point", bytes([2]) + bytes(31), msg, good, "bad_signature")
