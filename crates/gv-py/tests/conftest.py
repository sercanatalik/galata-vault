"""A real `gv-server local` for the session, and the wheel's own `gv`
command (with its own home and a file credential store, never the
keychain) to set up projects, secrets and tokens."""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

SERVER_BIN = os.environ.get("GV_SERVER_BIN") or shutil.which("gv-server")
ADVERSARY_BIN = os.environ.get("GV_ADVERSARY_BIN") or shutil.which("gv-adversary")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_server(base: Path):
    """A `gv-server local` in `base`: (url, data directory, process, log)."""
    if not SERVER_BIN:
        pytest.skip("no gv-server binary (set GV_SERVER_BIN)")
    port = free_port()
    data = base / "data"
    log = open(base / "server.log", "w")
    proc = subprocess.Popen(
        [SERVER_BIN, "local", "--data-dir", str(data), "--port", str(port)],
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 30
    while True:
        try:
            urllib.request.urlopen(url + "/healthz", timeout=1)
            break
        except OSError:
            if proc.poll() is not None:
                raise RuntimeError((base / "server.log").read_text())
            if time.time() > deadline:
                raise
            time.sleep(0.05)
    return url, data, proc, log


def stop_server(proc, log) -> None:
    proc.terminate()
    proc.wait(10)
    log.close()


@pytest.fixture(scope="session")
def server(tmp_path_factory) -> str:
    url, _, proc, log = start_server(tmp_path_factory.mktemp("server"))
    yield url
    stop_server(proc, log)


class Gv:
    """The installed `gv` console script, on one simulated machine."""

    def __init__(self, root: Path, server: str) -> None:
        self.home = root / "home"
        self.work = root / "work"
        self.home.mkdir()
        self.work.mkdir()
        self.server = server
        self.project = "p" + uuid.uuid4().hex[:10]
        self.env = f"{self.project}/prod"
        self.data: Path | None = None

    def run(self, *args: str, input: bytes = b"", check: bool = True) -> subprocess.CompletedProcess:
        env = {
            "PATH": os.environ["PATH"],
            "GV_HOME": str(self.home),
            "GV_CREDENTIAL_STORE": "file",
        }
        p = subprocess.run(["gv", *args], input=input, capture_output=True, cwd=self.work, env=env)
        if check and p.returncode != 0:
            raise AssertionError(f"gv {args} failed ({p.returncode}): {p.stderr.decode()}")
        return p

    def set(self, name: str, value: str | bytes, env: str | None = None) -> None:
        data = value.encode() if isinstance(value, str) else value
        self.run("set", name, "--env", env or self.env, input=data)

    def get(self, name: str) -> str:
        return self.run("get", name, "--env", self.env).stdout.decode()

    def token_ids(self) -> set[str]:
        out = self.run("token", "ls", "--env", self.env).stdout.decode()
        return {line.split()[0] for line in out.splitlines() if line.strip()}

    def mint(self, scope: str, *extra: str) -> tuple[str, str]:
        """A new token for the environment: (token, token id)."""
        before = self.token_ids()
        token = self.run("token", "mint", "--scope", scope, "--env", self.env, *extra).stdout.decode().strip()
        (token_id,) = self.token_ids() - before
        return token, token_id


def project(root: Path, server: str) -> Gv:
    g = Gv(root, server)
    g.run("init", g.project, "--server", server, input=b"saved\n")
    g.run("env", "add", g.env)
    return g


@pytest.fixture
def gv(server, tmp_path) -> Gv:
    """A fresh project with one environment, `<project>/prod`."""
    return project(tmp_path, server)


class Adversary:
    """`gv-adversary`: a real server behind a malicious proxy, scripted
    through its control API. A match is
    ``{"method", "path", "prefix", "token"}``; see crates/gv-adversary."""

    # Headers urllib sets itself when a logged request is sent again.
    _TRANSPORT = {"host", "content-length", "connection", "user-agent",
                  "accept", "accept-encoding", "transfer-encoding"}

    def __init__(self, url: str) -> None:
        self.url = url

    @staticmethod
    def match(method: str, path: str, prefix: bool = False) -> dict:
        return {"method": method, "path": path, "prefix": prefix}

    def send(self, method: str, path: str, headers: dict, body: bytes | None):
        """One raw request through the proxy: (status, parsed JSON or None)."""
        request = urllib.request.Request(
            self.url + path, data=body, method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(request, timeout=10) as r:
                status, raw = r.status, r.read()
        except urllib.error.HTTPError as error:
            status, raw = error.code, error.read()
        try:
            return status, json.loads(raw)
        except ValueError:
            return status, None

    def _control(self, what: str, body: dict | None = None):
        status, reply = self.send(
            "POST", f"/__adversary/{what}",
            {"content-type": "application/json"}, json.dumps(body or {}).encode(),
        )
        assert status == 200, reply
        return reply

    def rewrite(self, match: dict, set=(), flip=()) -> None:
        """From now on, set JSON pointers in (or flip a byte of a base64
        value in) every response to ``match``."""
        self._control("rewrite", {"match": match, "set": [list(s) for s in set],
                                  "flip": [list(f) for f in flip]})

    def record(self, match: dict) -> None:
        self._control("record", {"match": match})

    def recorded(self, match: dict):
        return self._control("recorded", {"match": match})["body"]

    def serve_recorded(self, match: dict) -> None:
        self._control("serve_recorded", {"match": match})

    def clear(self) -> None:
        self._control("clear")

    def clear_log(self) -> None:
        self._control("clear_log")

    def log(self) -> list[dict]:
        status, log = self.send("GET", "/__adversary/log", {}, None)
        assert status == 200
        return log

    def replay(self, entry: dict):
        headers = {k: v for k, v in entry["headers"] if k not in self._TRANSPORT}
        body = entry["body"].encode() if entry["body"] else None
        return self.send(entry["method"], entry["path"], headers, body)


@pytest.fixture
def adversary():
    """A fresh malicious server for one test."""
    if not ADVERSARY_BIN:
        if os.environ.get("GV_REQUIRE_PYTHON") == "1":
            pytest.fail("no gv-adversary binary (set GV_ADVERSARY_BIN)")
        pytest.skip("no gv-adversary binary (set GV_ADVERSARY_BIN)")
    proc = subprocess.Popen(
        [ADVERSARY_BIN], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
    )
    url = proc.stdout.readline().decode().strip()
    if not url.startswith("http://"):
        proc.kill()
        raise RuntimeError("gv-adversary did not start")
    yield Adversary(url)
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def adv_gv(adversary, tmp_path) -> Gv:
    """A fresh project with one environment, on the malicious server."""
    return project(tmp_path, adversary.url)


@pytest.fixture
def private_gv(tmp_path) -> Gv:
    """A fresh project on a server of its own, whose database a test may
    tamper with as a malicious operator would (`data / vault.db`)."""
    base = tmp_path / "server"
    base.mkdir()
    url, data, proc, log = start_server(base)
    g = project(tmp_path, url)
    g.data = data
    yield g
    stop_server(proc, log)
