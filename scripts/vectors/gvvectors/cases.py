"""The vector file format (`docs/spec/README.md#5`, `testdata/vectors/schema.json`)."""

from __future__ import annotations

import json

SUITE = "galata-vault test vectors"
PROTOCOL = 2
GENERATOR = "scripts/vectors (independent Python: stdlib, cryptography, PyNaCl; age and BLAKE3 written out)"

# The failure registry (`docs/spec/README.md#4`). An `expect` is "success" or
# one of these.
FAILURES = {
    "checksum_mismatch",
    "bad_encoding",
    "bad_length",
    "truncated",
    "unknown_version",
    "unknown_kind",
    "unknown_format",
    "kind_mismatch",
    "bad_signature",
    "key_mismatch",
    "vault_mismatch",
    "token_mismatch",
    "generation_mismatch",
    "version_mismatch",
    "written_at_mismatch",
    "name_mismatch",
    "descriptor_mismatch",
    "decrypt_failed",
    "chain_break",
    "rollback",
    "fork",
    "unverifiable_newer_format",
    "unknown_value",
    "bad_path",
    "bad_server",
    "bad_proof",
    "expired",
}


class VectorFile:
    def __init__(self, construct: str, spec: str):
        self.construct = construct
        self.spec = spec
        self.cases: list[dict] = []

    def add(self, op: str, spec: str, description: str, inputs: dict,
            expect: str = "success", outputs: dict | None = None) -> None:
        assert expect == "success" or expect in FAILURES, expect
        assert expect != "success" or outputs is not None, description
        assert "#" in spec, spec
        case = {
            "id": f"{self.construct}-{len(self.cases) + 1:03d}",
            "description": description,
            "spec": spec,
            "op": op,
            "inputs": inputs,
            "expect": expect,
        }
        if outputs is not None:
            case["outputs"] = outputs
        self.cases.append(case)

    def render(self) -> str:
        doc = {
            "suite": SUITE,
            "protocol": PROTOCOL,
            "construct": self.construct,
            "spec": self.spec,
            "generator": GENERATOR,
            "cases": self.cases,
        }
        return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
