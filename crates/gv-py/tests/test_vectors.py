"""Every protocol test vector (``testdata/vectors/v1/``), run against the
installed wheel through its private ``_vectors`` runner: the same outcomes
the Rust crates' vector tests require (``docs/spec/README.md#5``)."""

from __future__ import annotations

import json
import pathlib

import pytest

from galata_vault import _vectors

VECTORS = pathlib.Path(__file__).resolve().parents[3] / "testdata" / "vectors" / "v1"
FILES = sorted(VECTORS.glob("*.json"))


def _cases():
    for path in FILES:
        doc = json.loads(path.read_text())
        for case in doc["cases"]:
            yield pytest.param(doc["construct"], case, id=case["id"])


def test_the_vector_files_are_there():
    assert len(FILES) == 13, f"expected 13 vector files in {VECTORS}"


@pytest.mark.parametrize("construct, case", list(_cases()))
def test_vector(construct, case):
    got = _vectors.run(construct, case)
    assert got["result"] == case["expect"], f"{case['id']} ({case['description']}): {got}"
    if "outputs" in case:
        assert got["outputs"] == case["outputs"], case["id"]
