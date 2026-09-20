#!/usr/bin/env python3
"""Stage the docs book's sources under site/_src (site/README.md).

The book mirrors the repository's layout, so the Markdown is copied
unchanged to the same relative paths: README.md stays README.md,
docs/spec/keys.md stays docs/spec/keys.md, and every relative link between
them keeps resolving. Two things are added on top:

- SUMMARY.md, generated from the curated table below. Entries whose file is
  missing are skipped, so a document can be removed from the tree without
  touching this script; Markdown under docs/ that the table does not name is
  appended at the end under "More".
- Links to files that are not in the book (source, licences, scripts, test
  data) are rewritten to the GitHub tree, so nothing on the site is a dead
  link.

Run from any directory: paths are resolved from this file's location.
"""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
SRC = HERE / "_src"
GITHUB = "https://github.com/sercanatalik/galata-vault"
BRANCH = "main"

# (part title or None, [(title, repo-relative path)]). Missing files are
# skipped; a part with no surviving entries is skipped too.
TABLE: list[tuple[str | None, list[tuple[str, str]]]] = [
    (None, [("Overview", "README.md")]),
    ("Guide", [
        ("Using galata-vault", "docs/guide.md"),
        ("Threat model", "docs/threat-model.md"),
        ("Architecture", "ARCHITECTURE.md"),
        ("The local UI", "docs/local-ui.md"),
        ("Running a server", "deploy/README.md"),
    ]),
    ("Specification", [
        ("Status and conventions", "docs/spec/README.md"),
        ("Formats", "docs/spec/formats.md"),
        ("Keys", "docs/spec/keys.md"),
        ("Records", "docs/spec/records.md"),
        ("Signatures", "docs/spec/signatures.md"),
        ("Protocol flows", "docs/spec/protocol.md"),
        ("HTTP API", "docs/spec/http-api.md"),
        ("Audit chain", "docs/spec/audit.md"),
        ("Hosted appendix", "docs/spec/hosted.md"),
        ("Stability", "docs/spec/stability.md"),
    ]),
    ("Crates", [
        ("galata-vault, the SDK", "crates/galata-vault/README.md"),
        ("galata-vault-cli", "crates/galata-vault-cli/README.md"),
        ("galata-vault-server", "crates/galata-vault-server/README.md"),
        ("galata-vault-mcp", "crates/galata-vault-mcp/README.md"),
        ("galata-vault on PyPI", "crates/gv-py/README.md"),
        ("galata-vault-proto", "crates/galata-vault-proto/README.md"),
        ("galata-vault-keys", "crates/galata-vault-keys/README.md"),
        ("galata-vault-seal", "crates/galata-vault-seal/README.md"),
        ("galata-vault-client", "crates/galata-vault-client/README.md"),
        ("galata-vault-store", "crates/galata-vault-store/README.md"),
        ("galata-vault-server-core", "crates/galata-vault-server-core/README.md"),
    ]),
    ("Project", [
        ("Security policy", "SECURITY.md"),
        ("Changelog", "CHANGELOG.md"),
        ("Releasing", "RELEASING.md"),
        ("Contributing", "CONTRIBUTING.md"),
        ("Code of conduct", "CODE_OF_CONDUCT.md"),
    ]),
]

# Markdown link targets: `](target)` and `](target "title")`, not images.
LINK_RE = re.compile(r"(?<!!)\]\(([^)\s]+)(\s+\"[^\"]*\")?\)")
# Reference-style definitions: `[name]: target`.
REF_RE = re.compile(r"^(\[[^\]]+\]:\s+)(\S+)", re.MULTILINE)


def first_heading(path: Path) -> str:
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("# "):
            return line[2:].strip().replace("[", "").replace("]", "")
    return path.stem


def chapters() -> list[tuple[str | None, list[tuple[str, str]]]]:
    parts: list[tuple[str | None, list[tuple[str, str]]]] = []
    seen: set[str] = set()
    for title, entries in TABLE:
        kept = []
        for name, rel in entries:
            if rel in seen or not (REPO / rel).is_file():
                continue
            seen.add(rel)
            kept.append((name, rel))
        if kept:
            parts.append((title, kept))
    extra = []
    for path in sorted((REPO / "docs").rglob("*.md")):
        rel = path.relative_to(REPO).as_posix()
        if rel not in seen and path.name != "SUMMARY.md":
            seen.add(rel)
            extra.append((first_heading(path), rel))
    if extra:
        parts.append(("More", extra))
    return parts


def summary(parts) -> str:
    out = ["# Summary", ""]
    for title, entries in parts:
        if title:
            out += ["", f"# {title}", ""]
        for name, rel in entries:
            out.append(f"- [{name}]({rel})")
    return "\n".join(out) + "\n"


def rewrite_links(text: str, rel: str, book: set[str], dangling: list) -> str:
    base = Path(rel).parent

    def resolve(target: str) -> str | None:
        """A repo-relative path for a relative target, or None to leave it."""
        if re.match(r"^[a-z][a-z0-9+.-]*:", target) or target.startswith("#"):
            return None
        path, _, frag = target.partition("#")
        if not path:
            return None
        joined = os.path.normpath((base / path).as_posix())
        if joined.startswith(".."):
            return None
        if joined in book:
            # mdBook renders a chapter named README.md as its directory's
            # index.html but does not rewrite links to it; point them at
            # index.md, which it does rewrite.
            if Path(joined).name == "README.md":
                target = path[: -len("README.md")] + "index.md"
                return target + (f"#{frag}" if frag else "")
            return None
        node = REPO / joined
        if node.is_dir():
            kind = "tree"
        elif node.is_file():
            kind = "blob"
        else:
            # Neither a chapter nor a file: rewriting it to the GitHub tree
            # would only move the 404. Collect it and fail the build, so the
            # promise above ("nothing on the site is a dead link") holds.
            dangling.append((rel, target))
            return None
        url = f"{GITHUB}/{kind}/{BRANCH}/{joined}"
        return url + (f"#{frag}" if frag else "")

    def link(m: re.Match) -> str:
        new = resolve(m.group(1))
        if new is None:
            return m.group(0)
        return f"]({new}{m.group(2) or ''})"

    def ref(m: re.Match) -> str:
        new = resolve(m.group(2))
        if new is None:
            return m.group(0)
        return m.group(1) + new

    return REF_RE.sub(ref, LINK_RE.sub(link, text))


def main() -> int:
    parts = chapters()
    book = {rel for _, entries in parts for _, rel in entries}
    if SRC.exists():
        shutil.rmtree(SRC)
    SRC.mkdir(parents=True)
    dangling: list[tuple[str, str]] = []
    for rel in sorted(book):
        text = (REPO / rel).read_text(encoding="utf-8")
        dest = SRC / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(rewrite_links(text, rel, book, dangling), encoding="utf-8")
    (SRC / "SUMMARY.md").write_text(summary(parts), encoding="utf-8")
    if dangling:
        for source, target in dangling:
            print(f"{source}: links to {target}, which is not in the tree", file=sys.stderr)
        print(
            f"{len(dangling)} dead link(s): write the target, or remove the link.",
            file=sys.stderr,
        )
        return 1
    print(f"staged {len(book)} chapters under {SRC.relative_to(REPO)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
