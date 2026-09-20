"""The galata_vault token client and the bundled gv command, against a real
local server. Setup goes through `gv`; everything asserted goes through the
library."""

from __future__ import annotations

import os
import resource
import subprocess
import threading
import time
import warnings

import pytest

import galata_vault as gvl


def vault(gv, token: str) -> gvl.Vault:
    return gvl.Vault(token, gv.server)


def test_the_package_provides_the_library_and_the_command():
    out = subprocess.run(["gv", "--version"], capture_output=True)
    assert out.returncode == 0
    assert gvl.__version__ in out.stdout.decode()


def test_from_env_reads_lists_and_hides_system_records(gv, monkeypatch):
    gv.set("DATABASE_URL", "postgres://db")
    gv.set("PLAIN", "p")
    token, _ = gv.mint("read")
    monkeypatch.setenv("GV_TOKEN", token)
    monkeypatch.setenv("GV_SERVER", gv.server)

    v = gvl.Vault.from_env()
    assert v.scope == "read"
    assert v.get("DATABASE_URL") == "postgres://db"
    assert v.get_bytes("PLAIN") == b"p"
    listed = v.list()
    assert [s.name for s in listed] == ["DATABASE_URL", "PLAIN"], "gv:children is hidden"
    assert listed[0].version == 1 and listed[0].size > 0
    assert listed[0].updated_at.tzinfo is not None
    with pytest.raises(gvl.NotFoundError) as e:
        v.get("NOPE")
    assert e.value.code == "not_found"


def test_versions_and_values_that_are_not_text(gv):
    gv.set("ROTATED", "one")
    gv.set("ROTATED", "two")
    gv.set("BINARY", b"\xff\xfe\x00raw")
    v = vault(gv, gv.mint("read")[0])
    assert v.get("ROTATED") == "two"
    assert v.get("ROTATED", version=1) == "one"
    with pytest.raises(gvl.NotFoundError):
        v.get("ROTATED", version=9)
    assert v.get_bytes("BINARY") == b"\xff\xfe\x00raw"
    with pytest.raises(gvl.GalataVaultError) as e:
        v.get("BINARY")
    assert e.value.code == "not_text" and "get_bytes" in str(e.value)
    assert "raw" not in str(e.value)


def test_load_env_keeps_existing_variables(gv, monkeypatch):
    gv.set("GVTEST_A", "a")
    gv.set("GVTEST_B", "b")
    gv.set("not-an-env-name", "x")
    v = vault(gv, gv.mint("read")[0])
    monkeypatch.setenv("GVTEST_B", "kept")
    monkeypatch.delenv("GVTEST_A", raising=False)
    try:
        with pytest.warns(RuntimeWarning, match="not-an-env-name"):
            loaded = v.load_env()
        assert loaded == ["GVTEST_A"]
        assert os.environ["GVTEST_A"] == "a" and os.environ["GVTEST_B"] == "kept"
        assert v.load_env(only=["GVTEST_B"], override=True) == ["GVTEST_B"]
        assert os.environ["GVTEST_B"] == "b"
        with pytest.raises(gvl.NotFoundError):
            v.load_env(only=["GVTEST_MISSING"])
    finally:
        os.environ.pop("GVTEST_A", None)


def test_meta_tokens_list_but_cannot_read(gv):
    gv.set("SECRET", "s")
    v = vault(gv, gv.mint("meta")[0])
    assert v.scope == "meta"
    assert [s.name for s in v.list()] == ["SECRET"]
    with pytest.raises(gvl.ForbiddenError) as e:
        v.get("SECRET")
    assert e.value.code == "forbidden"
    with pytest.raises(gvl.ForbiddenError):
        v.load_env()


def test_an_allow_listed_read_token_reads_only_its_names(gv):
    gv.set("ALLOWED", "yes")
    gv.set("DENIED", "no")
    v = vault(gv, gv.mint("read", "--only", "ALLOWED")[0])
    assert v.get("ALLOWED") == "yes"
    with pytest.raises(gvl.ForbiddenError):
        v.get("DENIED")
    assert [name for name, _ in v._inner.load_items(None)] == ["ALLOWED"]


def test_writes_follow_the_scope(gv):
    appender = vault(gv, gv.mint("append")[0])
    assert appender.set("FROM_APP", "v1") == 1
    assert appender.set("FROM_APP", b"v2") == 2
    assert gv.get("FROM_APP") == "v2"
    with pytest.raises(gvl.ForbiddenError):
        appender.get("FROM_APP")
    reader = vault(gv, gv.mint("read")[0])
    with pytest.raises(gvl.ForbiddenError):
        reader.set("NOPE", "x")
    with pytest.raises(gvl.GalataVaultError) as e:
        appender.set("gv:children", "x")
    assert e.value.code == "invalid_name"


def test_bad_revoked_and_unreachable_tokens(gv, monkeypatch):
    token, token_id = gv.mint("read")
    swap = "y" if token.endswith("x") else "x"
    mistyped = token[:-1] + swap
    with pytest.raises(gvl.AuthenticationError) as e:
        gvl.Vault(mistyped, gv.server)
    assert e.value.code == "invalid_token"
    assert mistyped[5:30] not in str(e.value)

    monkeypatch.setenv("GV_TOKEN", token)
    monkeypatch.delenv("GV_SERVER", raising=False)
    with pytest.raises(gvl.AuthenticationError) as e:
        gvl.Vault.from_env()
    assert e.value.code == "missing_server" and "GV_SERVER" in str(e.value)

    with pytest.raises(gvl.GalataVaultError) as e:
        gvl.Vault(token, "http://vault.example")
    assert e.value.code == "invalid_server"

    from conftest import free_port

    with pytest.raises(gvl.TransportError) as e:
        gvl.Vault(token, f"http://127.0.0.1:{free_port()}")
    assert e.value.code == "unreachable"

    opened = gvl.Vault(token, gv.server)
    gv.run("token", "revoke", token_id, "--env", gv.env)
    with pytest.raises(gvl.AuthenticationError) as e:
        gvl.Vault(token, gv.server)
    assert e.value.code == "unauthorized"
    with pytest.raises(gvl.AuthenticationError) as e:
        opened.list()
    assert e.value.code == "unauthorized"


def test_no_error_or_repr_carries_a_token_or_a_value(gv):
    gv.set("CANARY", "value-canary-4c1d")
    token, _ = gv.mint("read")
    meta, _ = gv.mint("meta")
    texts = [repr(vault(gv, token)), str(vault(gv, meta))]
    for attempt in (
        lambda: vault(gv, meta).get("CANARY"),
        lambda: vault(gv, token).get("MISSING"),
        lambda: vault(gv, token).set("CANARY", "x"),
        lambda: gvl.Vault(token[:-1] + ("y" if token.endswith("x") else "x"), gv.server),
    ):
        with pytest.raises(gvl.GalataVaultError) as e:
            attempt()
        texts += [str(e.value), repr(e.value)]
    secrets = [token[5:], meta[5:], "value-canary"]  # a message may name the gvt1_ format
    for text in texts:
        for secret in secrets:
            assert secret[:20] not in text, text
    assert "scope=read" in texts[0]


def test_expiry_is_a_warning_issued_once_per_vault(gv):
    gv.set("A", "a")
    v = vault(gv, gv.mint("read")[0])
    with warnings.catch_warnings():
        warnings.simplefilter("error", gvl.ExpiryWarning)
        v.get("A")  # 90 days away: no warning

    class SoonExpiring:
        scope, vault_id = "read", "00"
        last_expires_at = int(time.time()) + 10 * 86_400

        def get_bytes(self, name, version):
            return b"a"

    v._inner, v._warned = SoonExpiring(), False
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        v.get("A")
        v.get("A")
    assert [w.category for w in caught] == [gvl.ExpiryWarning]


def test_a_vault_can_be_shared_between_threads(gv):
    gv.set("SHARED", "s")
    v = vault(gv, gv.mint("read")[0])
    results, errors = [], []

    def read():
        try:
            for _ in range(5):
                results.append(v.get("SHARED"))
        except Exception as e:  # pragma: no cover - reported below
            errors.append(e)

    threads = [threading.Thread(target=read) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors and results == ["s"] * 20


def test_the_library_leaves_the_core_dump_limit_alone(gv):
    gv.set("A", "a")
    before = resource.getrlimit(resource.RLIMIT_CORE)
    vault(gv, gv.mint("read")[0]).get("A")
    assert resource.getrlimit(resource.RLIMIT_CORE) == before


def test_the_bundled_gv_preserves_exit_status_and_injects_secrets(gv):
    gv.set("INJECTED", "yes")
    p = gv.run("run", "--env", gv.env, "--", "sh", "-c", 'test "$INJECTED" = yes && exit 3', check=False)
    assert p.returncode == 3, p.stderr.decode()


def test_the_bundled_gv_has_the_local_ui():
    out = subprocess.run(["gv", "ui", "--help"], capture_output=True)
    assert out.returncode == 0, out.stderr
    assert b"--no-open" in out.stdout


def test_gv_ui_refuses_to_start_without_a_terminal(gv):
    p = gv.run("ui", "--no-open", check=False)
    assert p.returncode != 0
    assert b"needs a terminal" in p.stderr


# ---------------------------------------------------------------- configs


def set_config(gv, name: str, body: str, fmt: str = "toml") -> None:
    gv.run("config", "set", name, "--format", fmt, "--env", gv.env, input=body.encode())


def test_a_config_token_reads_configs_and_nothing_else(gv, monkeypatch):
    gv.set("GVTEST_SECRET", "s")
    set_config(gv, "app", '[app]\nname = "acme"\nworkers = 4\n')
    v = vault(gv, gv.mint("config")[0])
    assert v.scope == "config"
    doc = v.get_config("app")
    assert (doc.name, doc.format, doc.version) == ("app", "toml", 1)
    assert doc.parse() == {"app": {"name": "acme", "workers": 4}}
    assert doc.data == doc.text.encode() and doc.text.startswith("[app]")
    assert [(c.name, c.version) for c in v.list_configs()] == [("app", 1)]
    for attempt in (
        lambda: v.get("GVTEST_SECRET"),
        lambda: v.get_bytes("GVTEST_SECRET"),
        lambda: v.set("OTHER", "x"),
        lambda: v.set_config("app", "a = 1\n", "toml"),
    ):
        with pytest.raises(gvl.ForbiddenError):
            attempt()
    monkeypatch.delenv("GVTEST_SECRET", raising=False)
    with pytest.raises(gvl.ForbiddenError):
        v.load_env()
    assert "GVTEST_SECRET" not in os.environ


def test_configs_round_trip_exactly_and_bad_bodies_are_refused(gv):
    writer = vault(gv, gv.mint("config-write")[0])
    body = b'[app]\r\nname = "acme"  \r\n\n# no final newline'
    assert writer.set_config("app", body, "toml") == 1
    doc = writer.get_config("app")
    assert doc.data == body
    shown = repr(doc) + str(doc)
    assert "app" in shown and f"size={len(body)}" in shown and "acme" not in shown

    assert writer.set_config("app", "v = 2\n", "toml") == 2
    with pytest.raises(gvl.ConflictError) as e:
        writer.set_config("app", "v = 3\n", "toml", expect_version=1)
    assert e.value.code == "conflict"
    with pytest.raises(gvl.ConflictError):
        writer.set_config("app", "v = 3\n", "toml", expect_absent=True)
    assert writer.get_config("app").text == "v = 2\n"
    assert writer.get_config("app", version=1).data == body

    with pytest.raises(gvl.GalataVaultError) as e:
        writer.set_config("app", "{not json", "json")
    assert e.value.code == "invalid_config" and "not json" not in str(e.value)
    key = 'agent_key = "0x' + "ab" * 32 + '"\n'
    with pytest.raises(gvl.GalataVaultError) as e:
        writer.set_config("signer", key, "toml")
    assert e.value.code == "credential_literal" and "abab" not in str(e.value)
    assert writer.set_config("signer", key, "toml", allow_literals=True) == 1
    with pytest.raises(gvl.GalataVaultError) as e:
        writer.set_config("other", "a", "ini")
    assert e.value.code == "unsupported_format"
    with pytest.raises(gvl.GalataVaultError) as e:
        writer.set_config("gv:children", "a", "text")
    assert e.value.code == "invalid_name"

    writer.set_config("k8s", "a: 1\n", "yaml")
    with pytest.raises(gvl.GalataVaultError) as e:
        writer.get_config("k8s").parse()
    assert e.value.code == "unsupported_format"
    assert [c.name for c in writer.list_configs()] == ["app", "k8s", "signer"]


def test_token_files_and_the_environment(gv, tmp_path, monkeypatch):
    gv.set("A", "a")
    token, _ = gv.mint("read")
    path = tmp_path / "token"
    path.write_text(token + "\n")
    path.chmod(0o644)
    with pytest.raises(gvl.GalataVaultError) as e:
        gvl.Vault.from_token_file(path, gv.server)
    assert e.value.code == "invalid_token_file"
    assert "0644" in str(e.value) and str(path) in str(e.value)
    path.chmod(0o600)
    assert gvl.Vault.from_token_file(path, gv.server).get("A") == "a"

    monkeypatch.setenv("GV_SERVER", gv.server)
    monkeypatch.setenv("GV_TOKEN_FILE", str(path))
    monkeypatch.delenv("GV_TOKEN", raising=False)
    assert gvl.Vault.from_env().get("A") == "a"

    monkeypatch.setenv("GV_TOKEN", token)
    with pytest.raises(gvl.GalataVaultError) as e:
        gvl.Vault.from_env()
    assert e.value.code == "invalid_environment"
    assert "GV_TOKEN " in str(e.value) and "GV_TOKEN_FILE" in str(e.value)
    assert token[5:25] not in str(e.value)


def test_a_token_of_another_version_is_refused(gv):
    with pytest.raises(gvl.GalataVaultError) as e:
        gvl.Vault("gvt2_" + "0" * 92, gv.server)
    assert e.value.code == "invalid_token"
    assert "version 2" in str(e.value)


def test_a_value_forged_by_the_server_is_an_integrity_error(private_gv):
    import sqlite3

    private_gv.set("FORGED", "value-canary-f0r9")
    v = vault(private_gv, private_gv.mint("read")[0])
    assert v.get("FORGED") == "value-canary-f0r9"

    # A malicious operator edits the stored ciphertext; the server serves it.
    db = sqlite3.connect(private_gv.data / "vault.db", timeout=10)
    with db:
        for table in ("secrets", "configs"):
            for rowid, ct in db.execute(f"SELECT rowid, value_ct FROM {table} WHERE value_ct IS NOT NULL").fetchall():
                forged = bytes(ct[:-1]) + bytes([ct[-1] ^ 1])
                db.execute(f"UPDATE {table} SET value_ct = ? WHERE rowid = ?", (forged, rowid))
    db.close()

    with pytest.raises(gvl.IntegrityError) as e:
        v.get("FORGED")
    assert e.value.code == "bad_signature"
    assert "canary" not in str(e.value)


def test_audit_heads_carry_across_handles(gv):
    gv.set("AUDITED", "a")
    first = vault(gv, gv.mint("meta")[0])
    head = first.verify_audit()
    assert head is not None and ":" in head
    assert first.verify_audit(head) is not None

    gv.set("AUDITED", "b")
    later = vault(gv, gv.mint("read")[0])
    grown = later.verify_audit(head)
    assert int(grown.split(":")[0]) > int(head.split(":")[0])

    seq = head.split(":")[0]
    with pytest.raises(gvl.IntegrityError) as e:
        later.verify_audit(f"{seq}:{'0' * 64}")
    assert e.value.code == "audit_mismatch"
    with pytest.raises(gvl.GalataVaultError) as e:
        later.verify_audit("not-a-head")
    assert e.value.code == "invalid_audit_head"
