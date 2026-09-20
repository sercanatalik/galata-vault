"""Private and unsupported: run one galata-vault protocol test-vector case
with this wheel's compiled Rust code (``docs/spec/README.md#5``).

The test suite walks every file under ``testdata/vectors/v1/`` through it, so
the wheel that ships is the build that is tested. It is pure: no key is held
between calls, and nothing is read or written. Do not build on it.
"""

from __future__ import annotations

import json

from . import _native


def run(construct: str, case: dict) -> dict:
    """``{"result": "success" | <failure name>, "outputs": ...}`` for ``case``."""
    return json.loads(_native._vectors_run(construct, json.dumps(case)))
