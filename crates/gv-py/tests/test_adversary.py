"""The galata_vault package against a malicious server: a real server behind
`gv-adversary`, a proxy that
logs, replays, rewrites and serves stale answers. Setup goes through `gv`;
every attack must end in an exception with a specific integrity code, or
the server's own 401."""

from __future__ import annotations

import json

import pytest

import galata_vault as gvl

SELF = "/v1/tokens/self"


def refused(code: str, fn, *args) -> gvl.GalataVaultError:
    with pytest.raises(gvl.IntegrityError) as caught:
        fn(*args)
    assert caught.value.code == code, caught.value
    return caught.value


def test_an_honest_proxy_changes_nothing(adversary, adv_gv):
    adv_gv.set("DATABASE_URL", "postgres://db")
    token, _ = adv_gv.mint("read")
    v = gvl.Vault(token, adversary.url)
    assert v.get("DATABASE_URL") == "postgres://db"
    assert "DATABASE_URL" in [s.name for s in v.list()]


def test_a_record_with_a_forged_signature_is_refused(adversary, adv_gv):
    adv_gv.set("S", "genuine")
    token, _ = adv_gv.mint("read")
    v = gvl.Vault(token, adversary.url)
    adversary.rewrite(adversary.match("GET", "/v1/secrets/", prefix=True), flip=[("/sig", 0)])
    error = refused("bad_signature", v.get, "S")
    assert "genuine" not in str(error)
    adversary.clear()
    assert v.get("S") == "genuine", "a refused record leaves the handle usable"


def test_a_listing_with_a_forged_signature_is_refused(adversary, adv_gv):
    adv_gv.set("S", "genuine")
    token, _ = adv_gv.mint("meta")
    v = gvl.Vault(token, adversary.url)
    adversary.rewrite(adversary.match("GET", "/v1/secrets"), flip=[("/items/0/sig", 0)])
    refused("bad_signature", v.list)


def test_a_substituted_vault_or_config_key_is_refused(adversary, adv_gv):
    token, _ = adv_gv.mint("read")
    for at in (21, 53):  # the descriptor's vault key, then its config key
        adversary.rewrite(adversary.match("GET", SELF), flip=[("/descriptor/descriptor", at)])
        refused("bad_signature", gvl.Vault, token, adversary.url)
        adversary.clear()
    gvl.Vault(token, adversary.url)


def test_another_vaults_genuine_view_is_refused(adversary, adv_gv, tmp_path):
    from conftest import project

    (tmp_path / "other").mkdir()
    other = project(tmp_path / "other", adversary.url)
    theirs, _ = other.mint("read")
    mine, _ = adv_gv.mint("read")
    me = adversary.match("GET", SELF)
    adversary.record(me)
    gvl.Vault(theirs, adversary.url)
    genuine = adversary.recorded(me)
    adversary.rewrite(me, set=[("/owner_sign_pub", genuine["owner_sign_pub"]),
                               ("/descriptor", genuine["descriptor"])])
    refused("key_mismatch", gvl.Vault, mine, adversary.url)


def test_a_bundle_moved_between_tokens_is_refused(adversary, adv_gv):
    admin, _ = adv_gv.mint("admin")
    read, _ = adv_gv.mint("read")
    me = adversary.match("GET", SELF)
    adversary.record(me)
    gvl.Vault(admin, adversary.url)
    bundle = adversary.recorded(me)["bundle"]
    adversary.rewrite(me, set=[("/bundle", bundle)])
    refused("bad_signature", gvl.Vault, read, adversary.url)


def test_a_rolled_back_version_is_refused(adversary, adv_gv):
    adv_gv.set("S", "v1")
    token, _ = adv_gv.mint("read")
    v = gvl.Vault(token, adversary.url)
    latest = adversary.match("GET", "/v1/secrets/", prefix=True)
    adversary.record(latest)
    assert v.get("S") == "v1"
    adv_gv.set("S", "v2")
    assert v.get("S") == "v2"
    adversary.serve_recorded(latest)
    refused("version_rollback", v.get, "S")


def test_a_replayed_request_is_refused_and_no_request_carries_the_token(adversary, adv_gv):
    token, _ = adv_gv.mint("append")
    adversary.clear_log()
    v = gvl.Vault(token, adversary.url)
    assert v.set("FROM_PY", b"v1") == 1
    log = adversary.log()
    assert len(log) >= 2
    for entry in log:
        seen = json.dumps(entry)
        assert token not in seen and token[5:] not in seen, entry["path"]
        assert "FROM_PY" not in seen, entry["path"]
    put = next(e for e in log if e["method"] == "PUT" and e["path"].startswith("/v1/secrets/"))
    status, body = adversary.replay(put)
    assert (status, body["error"]) == (401, "unauthorized")


def test_a_token_of_another_version_is_refused_before_any_request(adversary):
    before = len(adversary.log())
    with pytest.raises(gvl.GalataVaultError) as caught:
        gvl.Vault("gvt2_" + "a" * 92, adversary.url)
    assert caught.value.code == "invalid_token", caught.value
    assert len(adversary.log()) == before, "no request was made"
