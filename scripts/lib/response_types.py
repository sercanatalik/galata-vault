"""List the `proto` module's types declared `deny_unknown_fields`, and fail on any that
the allow-list does not name (scripts/check-response-types.sh).

Usage: response_types.py <root>. Prints a summary and exits 0, or prints one
line per violation and exits 1.
"""

import pathlib
import re
import sys

# Every type that may refuse unknown fields, and why.
ALLOWED = {
    # Request bodies: requests are strict (docs/spec/http-api.md#7.1).
    "ChallengeRequest": "request",
    "CreateVaultRequest": "request",
    "RotationRequest": "request",
    "RotatedVersion": "request (inside a rotation)",
    "ResealedBundle": "request (inside a rotation)",
    "RegisterTokenRequest": "request",
    "ReportTokenRequest": "request",
    "PutSecretRequest": "request",
    "DeleteRecordRequest": "request",
    # Every field is hashed (docs/spec/audit.md#2).
    "AuditRow": "hashed",
    # The children record's plaintext, inside the owner's ciphertext.
    "ChildMode": "encrypted plaintext",
    "ChildEntry": "encrypted plaintext",
    "ChildrenRecord": "encrypted plaintext",
    # The MCP's local configuration file.
    "McpConfig": "local file",
    "McpEntry": "local file",
}

ATTR = re.compile(r"#\[serde\([^\]]*\bdeny_unknown_fields\b[^\]]*\)\]")
ITEM = re.compile(r"pub(?:\([a-z]+\))?\s+(?:struct|enum)\s+(\w+)")


def main() -> int:
    root = pathlib.Path(sys.argv[1])
    src = root / "crates" / "galata-vault" / "src" / "proto"
    files = sorted(src.rglob("*.rs"))
    if not files:
        print(f"no Rust source under {src}")
        return 1
    strict, problems = [], []
    for path in files:
        text = path.read_text()
        cut = text.find("#[cfg(test)]")
        if cut >= 0:
            text = text[:cut]
        for m in ATTR.finditer(text):
            item = ITEM.search(text, m.end())
            name = item.group(1) if item else "?"
            line = text.count("\n", 0, m.start()) + 1
            rel = path.relative_to(root)
            if name in ALLOWED:
                strict.append(name)
            else:
                problems.append(
                    f"{rel}:{line}: {name} refuses unknown fields, and it is not a request body, "
                    "the audit row or a type that never crosses the wire as a response "
                    "(docs/spec/http-api.md#7.2)"
                )
    if problems:
        print("\n".join(problems))
        return 1
    print(f"{len(strict)} strict types in the `proto` module, every one a request body, the audit row or never a response")
    return 0


if __name__ == "__main__":
    sys.exit(main())
