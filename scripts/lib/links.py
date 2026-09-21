"""Every relative link in the project's Markdown, and every path its
packaging metadata names, resolved against the tree.

A published link to a document that is not here is a promise the repository
does not keep, and the README is where a reader meets it first.

Two sources are checked:

- **Markdown**, every `.md` outside the excluded directories: inline links
  and images, `](target)` and `](target "title")`, reference definitions,
  `[name]: target`, and the `src`, `srcset` and `href` of any HTML it
  carries. A `#fragment` is dropped before the file is
  resolved: this checks that the document exists, not that a heading inside
  it does.
- **Cargo manifests**, the `readme` and `license-file` paths, which are what
  `cargo publish` packages and crates.io renders.

Skipped: absolute URLs and `mailto:`, bare fragments, and anything under
`testdata/cctv`, which is vendored upstream and not ours to police.
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

# Inline links and images: `](target)`, `](target "title")`.
LINK_RE = re.compile(r"\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
# Reference definitions: `[name]: target`.
REF_RE = re.compile(r"^\[[^\]]+\]:\s+(\S+)", re.MULTILINE)
# `readme = "…"` / `license-file = "…"` in a manifest.
MANIFEST_RE = re.compile(r'^\s*(?:readme|license-file)\s*=\s*"([^"]+)"', re.MULTILINE)
# Markdown carries HTML, and a `<img src>` or `<source srcset>` is as much a
# published reference as a `](…)` link is. README.md uses one for the logo.
HTML_RE = re.compile(r'<[^>]*?\b(?:src|srcset|href)\s*=\s*"([^"]+)"', re.IGNORECASE)

# Generated, vendored, or not source.
SKIP_DIRS = {
    ".git",
    ".venv",
    "__pycache__",
    "node_modules",
    "target",
    "_src",
    "_build",
}
SKIP_PREFIXES = ("testdata/cctv",)


def markdown_files(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if not name.endswith(".md"):
                continue
            rel = Path(dirpath, name).relative_to(root).as_posix()
            if rel.startswith(SKIP_PREFIXES):
                continue
            out.append(rel)
    return out


def manifests(root: Path) -> list[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        if "Cargo.toml" in filenames:
            out.append(Path(dirpath, "Cargo.toml").relative_to(root).as_posix())
    return sorted(out)


def external(target: str) -> bool:
    return (
        bool(re.match(r"^[a-z][a-z0-9+.-]*:", target))
        or target.startswith("#")
        or target.startswith("<")
    )


def dead(root: Path) -> list[tuple[str, str]]:
    """(source, target) for every link whose target is not in the tree."""
    out = []
    for rel in markdown_files(root):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        base = Path(rel).parent
        targets = LINK_RE.findall(text) + REF_RE.findall(text)
        # A srcset may list several candidates, each with a descriptor.
        for attr in HTML_RE.findall(text):
            targets += [c.strip().split()[0] for c in attr.split(",") if c.strip()]
        for target in targets:
            if external(target):
                continue
            path = target.split("#", 1)[0]
            if not path:
                continue
            joined = os.path.normpath((base / path).as_posix())
            if joined.startswith(".."):
                out.append((rel, target))
            elif not (root / joined).exists():
                out.append((rel, target))
    for rel in manifests(root):
        text = (root / rel).read_text(encoding="utf-8", errors="replace")
        base = Path(rel).parent
        for target in MANIFEST_RE.findall(text):
            joined = os.path.normpath((base / target).as_posix())
            if not (root / joined).exists():
                out.append((rel, target))
    return out


def main(argv: list[str]) -> int:
    verb = argv[1] if len(argv) > 1 else "check"
    root = Path(argv[2] if len(argv) > 2 else ".").resolve()

    if verb == "targets":
        for rel in markdown_files(root) + manifests(root):
            print(rel)
        return 0

    found = dead(root)
    if found:
        for source, target in found:
            print(f"{source}: links to {target}, which is not in the tree", file=sys.stderr)
        print(
            f"links: FAILED, {len(found)} dead link(s). Write the target, or remove the link.",
            file=sys.stderr,
        )
        return 1
    scanned = len(markdown_files(root))
    print(
        f"links: ok. every relative link in {scanned} Markdown files, and every "
        f"readme and licence path in {len(manifests(root))} manifests, resolves"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
