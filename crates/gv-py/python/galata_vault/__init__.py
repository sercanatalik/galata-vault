"""galata-vault from Python: end-to-end encrypted secrets and config
documents, no account.

A token client for applications::

    import galata_vault

    vault = galata_vault.Vault.from_env()      # GV_SERVER, and GV_TOKEN or GV_TOKEN_FILE
    url = vault.get("DATABASE_URL")
    vault.load_env()                           # every readable secret into os.environ
    app = vault.get_config("app").parse()      # a dict; a `config` token is enough

Verification and decryption happen here, in the same Rust client the ``gv``
command and the Rust SDK use; the server only ever sees ciphertext and
signatures. Opening a vault verifies it from the vault id inside the token,
and every value read must carry a valid writer signature. Installing the
package also installs the ``gv`` command.

Errors derive from :class:`GalataVaultError` and carry a stable ``code``, the
same string the Rust SDK reports. No error message or ``repr`` contains a
token, a key, a secret value or a config body.
"""

from __future__ import annotations

import json
import os
import re
import time
import tomllib
import warnings
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, NoReturn

from . import _native

__version__: str = _native.__version__

__all__ = [
    "AuthenticationError",
    "ConfigDocument",
    "ConfigInfo",
    "ConflictError",
    "ExpiryWarning",
    "ForbiddenError",
    "GalataVaultError",
    "IntegrityError",
    "NotFoundError",
    "SecretInfo",
    "TransportError",
    "Vault",
    "__version__",
]

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class GalataVaultError(Exception):
    """Base class for every galata-vault error.

    ``code`` is stable, and the same string the Rust SDK reports: the
    server's error code (``token_expired``, ``precondition_failed``, ...) or
    one of ``not_found``, ``forbidden``, ``conflict``, ``invalid_token``,
    ``invalid_token_file``, ``invalid_server``, ``missing_server``,
    ``invalid_environment``, ``invalid_name``, ``invalid_config``,
    ``invalid_audit_head``, ``credential_literal``, ``unsupported_format``,
    ``not_text``, ``unreachable``, ``error``, and the integrity codes
    ``bad_signature``, ``key_mismatch``, ``binding_mismatch``,
    ``version_rollback``, ``generation_rollback`` and ``audit_mismatch``.
    """

    def __init__(self, message: str, code: str = "error") -> None:
        super().__init__(message)
        self.code = code


class AuthenticationError(GalataVaultError):
    """The token is malformed, unknown, revoked or expired, or its vault expired."""


class NotFoundError(GalataVaultError):
    """No such secret or config, no such version, or it was deleted."""


class ForbiddenError(GalataVaultError):
    """This token's scope (or allow-list) does not permit the operation."""


class ConflictError(GalataVaultError):
    """Another writer changed the record first; nothing was overwritten."""


class TransportError(GalataVaultError):
    """The server could not be reached."""


class IntegrityError(GalataVaultError):
    """Something the server served does not verify: a forged or moved value,
    a substituted key, a rolled-back version or audit history. Do not trust
    the server's answer."""


class ExpiryWarning(UserWarning):
    """The vault expires soon unless it is used."""


_KINDS: dict[str, type[GalataVaultError]] = {
    "auth": AuthenticationError,
    "not_found": NotFoundError,
    "forbidden": ForbiddenError,
    "conflict": ConflictError,
    "transport": TransportError,
    "integrity": IntegrityError,
}


def _raise(error: _native.NativeError) -> NoReturn:
    kind, code, message = error.args
    raise _KINDS.get(kind, GalataVaultError)(message, code) from None


@dataclass(frozen=True)
class SecretInfo:
    """A live secret's latest version. Never its value."""

    name: str
    version: int
    updated_at: datetime
    size: int


@dataclass(frozen=True)
class ConfigInfo:
    """A live config's latest version. Never its body."""

    name: str
    version: int
    updated_at: datetime
    size: int


class ConfigDocument:
    """A decrypted config document: ``name``, ``format`` (``toml``,
    ``json``, ``yaml`` or ``text``), ``version``, and its body as ``data``
    (bytes, exactly as written) or ``text``. Its ``repr`` never shows the
    body."""

    __slots__ = ("_data", "format", "name", "version")

    def __init__(self, name: str, format: str, version: int, data: bytes) -> None:
        self.name = name
        self.format = format
        self.version = version
        self._data = data

    @property
    def data(self) -> bytes:
        """The body, exactly as written: no newline or encoding normalisation."""
        return self._data

    @property
    def text(self) -> str:
        """The body as text."""
        try:
            return self._data.decode("utf-8")
        except UnicodeDecodeError:
            raise GalataVaultError(
                f"config {self.name} is not UTF-8 text; use .data", "not_text"
            ) from None

    def parse(self) -> Any:
        """The body as Python data: a ``dict`` for ``toml`` (via
        :mod:`tomllib`) and for a ``json`` object. ``yaml`` and ``text``
        raise :class:`GalataVaultError` with code ``unsupported_format``."""
        if self.format == "toml":
            try:
                return tomllib.loads(self.text)
            except tomllib.TOMLDecodeError as error:
                raise self._unparsable(error) from None
        if self.format == "json":
            try:
                return json.loads(self.text)
            except json.JSONDecodeError as error:
                raise self._unparsable(error) from None
        raise GalataVaultError(
            f"config {self.name} is {self.format}; only toml and json parse, "
            "so parse .text yourself",
            "unsupported_format",
        )

    def _unparsable(self, error: ValueError) -> GalataVaultError:
        # Only the line number is kept from the parser, never its excerpt.
        line = getattr(error, "lineno", None)
        if line is None:
            found = re.search(r"line (\d+)", str(error))
            line = found.group(1) if found else "?"
        return GalataVaultError(
            f"config {self.name}, line {line}: the body does not parse as {self.format}",
            "invalid_config",
        )

    def __repr__(self) -> str:
        return (
            f"<galata_vault.ConfigDocument name={self.name!r} format={self.format} "
            f"version={self.version} size={len(self._data)}>"
        )

    __str__ = __repr__


class Vault:
    """One environment's vault, opened with an access token.

    What a token can do depends on its scope: ``meta`` lists names,
    ``append`` also writes, ``read`` lists and reads, ``admin`` does both.
    ``config`` reads config documents and never a secret; ``config-write``
    also writes configs, and holds no key that writes a secret.
    """

    __slots__ = ("_inner", "_warned")

    def __init__(self, token: str, server: str) -> None:
        try:
            inner = _native.Vault(token, server)
        except _native.NativeError as error:
            _raise(error)
        self._adopt(inner)

    def _adopt(self, inner: _native.Vault) -> None:
        self._inner = inner
        self._warned = False
        self._check_expiry()

    @classmethod
    def from_token_file(cls, path: str | os.PathLike[str], server: str) -> Vault:
        """Open the vault of the token in ``path``. The file must be mode
        0600 or 0400 (checked before it is read) and hold one token."""
        try:
            inner = _native.Vault.from_token_file(os.fspath(path), server)
        except _native.NativeError as error:
            _raise(error)
        vault = cls.__new__(cls)
        vault._adopt(inner)
        return vault

    @classmethod
    def from_env(cls) -> Vault:
        """Open the vault named by ``GV_SERVER`` and exactly one of
        ``GV_TOKEN`` or ``GV_TOKEN_FILE``. Both set is refused, not ranked."""
        token = os.environ.get("GV_TOKEN")
        token_file = os.environ.get("GV_TOKEN_FILE")
        server = os.environ.get("GV_SERVER")
        if token and token_file:
            raise GalataVaultError(
                "GV_TOKEN and GV_TOKEN_FILE are both set; set exactly one",
                "invalid_environment",
            )
        if not token and not token_file:
            raise AuthenticationError(
                "neither GV_TOKEN nor GV_TOKEN_FILE is set", "invalid_token"
            )
        if not server:
            raise AuthenticationError(
                "GV_SERVER is not set; a token needs the server it belongs to",
                "missing_server",
            )
        if token_file:
            return cls.from_token_file(token_file, server)
        return cls(token, server)

    # ------------------------------------------------------------------

    def _call(self, method, *args):
        try:
            result = method(*args)
        except _native.NativeError as error:
            _raise(error)
        self._check_expiry()
        return result

    def _check_expiry(self) -> None:
        at = self._inner.last_expires_at
        if self._warned or at is None or at - time.time() >= _native.EXPIRY_WARNING_SECS:
            return
        self._warned = True
        when = datetime.fromtimestamp(at, UTC).strftime("%Y-%m-%d %H:%MZ")
        warnings.warn(
            f"this vault expires at {when} unless it is used before then",
            ExpiryWarning,
            stacklevel=4,
        )

    # ------------------------------------------------------------------

    @property
    def scope(self) -> str:
        """``meta``, ``append``, ``read``, ``admin``, ``config`` or ``config-write``."""
        return self._inner.scope

    @property
    def vault_id(self) -> str:
        return self._inner.vault_id

    def get(self, name: str, version: int | None = None) -> str:
        """The value of ``name`` (its latest version, or ``version``) as text."""
        data = self.get_bytes(name, version)
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError:
            raise GalataVaultError(
                f"{name} is not UTF-8 text; use get_bytes()", "not_text"
            ) from None

    def get_bytes(self, name: str, version: int | None = None) -> bytes:
        """The value of ``name`` as bytes."""
        return self._call(self._inner.get_bytes, name, version)

    def list(self) -> list[SecretInfo]:
        """Every live secret, sorted by name. System records are omitted."""
        return [
            SecretInfo(name, version, datetime.fromtimestamp(updated_at, UTC), size)
            for name, version, updated_at, size in self._call(self._inner.list)
        ]

    def set(self, name: str, value: str | bytes) -> int:
        """Create or update ``name``; returns the new version.

        Raises :class:`ConflictError` if another writer changed it meanwhile.
        """
        data = value.encode("utf-8") if isinstance(value, str) else bytes(value)
        return self._call(self._inner.set, name, data)

    def load_env(self, only: Iterable[str] | None = None, override: bool = False) -> list[str]:
        """Copy readable secrets into ``os.environ``; returns the names set.

        Existing variables are kept unless ``override`` is true. With
        ``only``, just those names (each must exist). Names that cannot be
        environment variables are skipped with a warning.
        """
        wanted = None if only is None else list(only)
        loaded: list[str] = []
        for name, value in self._call(self._inner.load_items, wanted):
            if not _ENV_NAME.match(name) or b"\0" in value:
                warnings.warn(
                    f"{name} cannot be an environment variable; skipped",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            if not override and name in os.environ:
                continue
            os.environ[name] = value.decode("utf-8", "surrogateescape")
            loaded.append(name)
        return loaded

    def verify_audit(self, known: str | None = None) -> str | None:
        """Verify this vault's audit chain and return its head, an opaque
        string to keep. Pass a head an earlier call returned (from this or
        any other handle, in this or a later process) to check that the
        server's history only grew since; a history that does not continue
        from it raises :class:`IntegrityError` with code ``audit_mismatch``.
        Every scope may verify.

        Rows in an audit row format newer than this package reads are
        neither verified nor tampered: a :class:`RuntimeWarning` names where
        they start, and the returned head stops before them."""
        head, unverifiable = self._call(self._inner.verify_audit, known)
        if unverifiable is not None:
            from_seq, row_format = unverifiable
            warnings.warn(
                f"audit rows from seq {'?' if from_seq is None else from_seq} on are in row "
                f"format {row_format}, newer than this galata-vault reads: they are unverified, "
                "not tampered, and the returned head stops before them. Upgrade to verify them.",
                RuntimeWarning,
                stacklevel=2,
            )
        return head

    # ------------------------------------------------------------------ configs

    def get_config(self, name: str, version: int | None = None) -> ConfigDocument:
        """Config ``name`` (its latest version, or ``version``)."""
        name, version, format, data = self._call(self._inner.get_config, name, version)
        return ConfigDocument(name, format, version, data)

    def list_configs(self) -> list[ConfigInfo]:
        """Every live config, sorted by name."""
        return [
            ConfigInfo(name, version, datetime.fromtimestamp(updated_at, UTC), size)
            for name, version, updated_at, size in self._call(self._inner.list_configs)
        ]

    def set_config(
        self,
        name: str,
        body: str | bytes,
        format: str,
        allow_literals: bool = False,
        *,
        expect_version: int | None = None,
        expect_absent: bool = False,
    ) -> int:
        """Create or update config ``name`` as ``format`` (``toml``,
        ``json``, ``yaml`` or ``text``); returns the new version.

        The body is checked before any request: it must parse in its
        format, and a credential literal (a key, a token, a PEM block) is
        refused unless ``allow_literals``. With ``expect_version`` the write
        succeeds only if the config is still at that version; with
        ``expect_absent``, only if it does not exist. A lost race raises
        :class:`ConflictError` and is never retried.
        """
        if expect_version is not None and expect_absent:
            raise ValueError("give expect_version or expect_absent, not both")
        data = body.encode("utf-8") if isinstance(body, str) else bytes(body)
        return self._call(
            self._inner.set_config,
            name,
            data,
            format,
            allow_literals,
            expect_version,
            expect_absent,
        )

    def __repr__(self) -> str:
        return f"<galata_vault.Vault scope={self.scope} vault_id={self.vault_id}>"

    __str__ = __repr__
