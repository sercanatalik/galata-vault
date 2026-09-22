"""Compare the label registry in docs/spec/keys.md#3 with the labels the
protocol, key and seal crates use (scripts/check-spec-labels.sh).

Usage: spec_labels.py <root>. Prints a summary and exits 0, or prints one
line per difference and exits 1.
"""

import pathlib
import re
import sys

MODULES = ("proto", "keys", "seal")
# A string or byte-string literal holding a label or a context. Byte strings
# may carry the framing's 0x00 after the label (`b"gv/v1/vault-id\0"`).
LITERAL = re.compile(
    r'b?"(gv/v1/[A-Za-z0-9._-]+|galata-vault/v[0-9]+|galata-vault v[0-9]+ [A-Za-z0-9 -]+)(?:\\0)?"'
)


def code_labels(root: pathlib.Path) -> dict[str, str]:
    found: dict[str, str] = {}
    for module in MODULES:
        for path in sorted((root / "crates" / "galata-vault" / "src" / module).rglob("*.rs")):
            text = path.read_text()
            cut = text.find("#[cfg(test)]")
            if cut >= 0:
                text = text[:cut]
            for m in LITERAL.finditer(text):
                line = text.count("\n", 0, m.start()) + 1
                found.setdefault(m.group(1), f"{path.relative_to(root)}:{line}")
    return found


def registry(root: pathlib.Path) -> set[str]:
    doc = (root / "docs" / "spec" / "keys.md").read_text()
    start = doc.find('<a id="3"></a>')
    if start < 0:
        raise SystemExit("docs/spec/keys.md has no section 3 (the label registry)")
    rest = doc[start + len('<a id="3"></a>'):]
    end = rest.find("<a id=")
    section = rest[: end if end >= 0 else len(rest)]
    labels = set()
    for line in section.splitlines():
        m = re.match(r"\|\s*`([^`]+)`\s*\|", line.strip())
        if m:
            labels.add(m.group(1))
    return labels


def main() -> int:
    root = pathlib.Path(sys.argv[1])
    code = code_labels(root)
    spec = registry(root)
    if not code or not spec:
        print(f"found {len(code)} labels in the code and {len(spec)} in the registry; refusing to compare nothing")
        return 1
    problems = [
        f"{label} is used at {where} but docs/spec/keys.md#3 does not register it"
        for label, where in sorted(code.items())
        if label not in spec
    ]
    problems += [
        f"{label} is registered in docs/spec/keys.md#3 but no longer used by {', '.join(f'the `{m}` module' for m in MODULES)}"
        for label in sorted(spec - code.keys())
    ]
    if problems:
        print("\n".join(problems))
        return 1
    print(f"{len(spec)} labels, the same in docs/spec/keys.md#3 and in {', '.join(f'the `{m}` module' for m in MODULES)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
