"""What the documents say about a release, against what the tree records.

Two rules, both answered from files this repository already maintains, so
neither needs a network:

  1. `CHANGELOG.md` dates a version  ->  no document may call it unpublished.
     `scripts/release.sh` writes and dates that heading as part of cutting a
     release, so a dated section is the release process's own record.

  2. `dist-workspace.toml` lists the installers  ->  no document may offer an
     installation command for one that is not in the list.

An OFFER is a command inside a fenced code block or a <pre>. Prose is free,
deliberately: RELEASING.md says "the tap does not exist and no README offers
`brew install`", and dist-workspace.toml holds the three lines that would
restore Homebrew. Both must stay legal. A rule keyed on the words alone would
forbid the sentence explaining the absence along with the absence itself, and
the explanation is the more valuable of the two -- it is what stops somebody
adding it back without noticing why it went.
"""

import os
import pathlib
import re
import sys
import tomllib

# The installers this tree knows how to advertise, and the command that
# advertises each. A name dist does not configure, appearing as one of these
# commands inside a code block, is the defect.
INSTALLER_COMMANDS = {
    "homebrew": "brew install",
}

# The phrasings this tree has ACTUALLY used to call a shipped version
# forthcoming -- every one of them from the 2026-09-21 defect, where six
# places said 0.1.0 was unpublished while it was on crates.io.
#
# Not a claim to completeness: English is not enumerable, and a guard that
# catches the mistake that happened is worth more than one that aspires to
# catch every mistake and is therefore never written.
UNPUBLISHED_PHRASES = [
    re.compile(r"not yet published", re.I),
    re.compile(r"\bafter\s+\d+\.\d+\.\d+\s+is\s+published", re.I),
    re.compile(r"\bonce\s+\d+\.\d+\.\d+\s+is\s+published", re.I),
    re.compile(r"these lines work (?:after|once)", re.I),
]

SKIP_DIRS = {"target", "openspec", ".git", "_build", "_src", "node_modules"}


def documents(root: pathlib.Path):
    """Every document in the repository's own voice.

    The walk is PRUNED rather than filtered. `rglob("*")` descends into
    `target/` and discards it afterwards, which took 23 seconds on this
    workspace -- a guard slow enough that somebody eventually runs the gate
    without it. Pruning the directory list before descending takes the same
    scan to a few milliseconds.
    """
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            if name.endswith((".md", ".html")):
                yield pathlib.Path(dirpath, name)


def code_block_lines(text: str, is_html: bool):
    """(line number, line) for lines a reader would copy.

    Markdown: inside ``` fences. HTML: inside <pre>. Everything else is prose,
    and prose may say anything.
    """
    if is_html:
        inside = False
        for n, line in enumerate(text.splitlines(), 1):
            if "<pre" in line:
                inside = True
            if inside:
                yield n, line
            if "</pre>" in line:
                inside = False
        return
    fenced = False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            yield n, line


def dated_versions(changelog: pathlib.Path) -> set[str]:
    """Versions the changelog records as shipped, by their dated headings."""
    if not changelog.is_file():
        return set()
    return set(
        re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}", changelog.read_text(), re.M)
    )


def configured_installers(dist: pathlib.Path) -> set[str]:
    """Parsed as TOML, so a comment or a reordering cannot change the answer."""
    if not dist.is_file():
        return set()
    return set(tomllib.loads(dist.read_text()).get("dist", {}).get("installers", []))


def workspace_version(cargo: pathlib.Path) -> str | None:
    return tomllib.loads(cargo.read_text()).get("workspace", {}).get("package", {}).get("version")


def check(root: pathlib.Path, docs: list[pathlib.Path] | None = None) -> list[str]:
    problems: list[str] = []
    version = workspace_version(root / "Cargo.toml")
    shipped = dated_versions(root / "CHANGELOG.md")
    installers = configured_installers(root / "dist-workspace.toml")
    unbuilt = {name: cmd for name, cmd in INSTALLER_COMMANDS.items() if name not in installers}

    for path in docs if docs is not None else documents(root):
        rel = path.relative_to(root)
        text = path.read_text(errors="replace")

        # Rule one: prose included. A claim that a shipped version is coming is
        # wrong wherever it is written.
        for n, line in enumerate(text.splitlines(), 1):
            for phrase in UNPUBLISHED_PHRASES:
                if not phrase.search(line):
                    continue
                # A phrase that names a version is judged against THAT version;
                # one that does not is judged against the version the tree is
                # at. "after 0.1.0 is published" is stale the moment 0.1.0 is
                # dated, whatever the workspace has moved on to since.
                named = re.search(r"\d+\.\d+\.\d+", line)
                subject = named.group(0) if named else version
                if subject and subject in shipped:
                    problems.append(
                        f"{rel}:{n}: calls {subject} unpublished, and CHANGELOG.md dates it. "
                        f"The changelog is what the release process writes; this is the copy "
                        f"that is wrong.\n      {line.strip()}"
                    )
                break

        # Rule two: code blocks only.
        for n, line in code_block_lines(text, path.suffix == ".html"):
            for name, command in unbuilt.items():
                if command in line:
                    problems.append(
                        f"{rel}:{n}: offers `{command}`, and dist-workspace.toml does not build "
                        f"`{name}`. A release that advertises an installer and then fails to "
                        f"produce it is worse than one that does not offer it.\n      {line.strip()}"
                    )
    return problems


def main() -> int:
    verb = sys.argv[1] if len(sys.argv) > 1 else "check"
    root = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else ".").resolve()
    if verb == "targets":
        for name in ("Cargo.toml", "CHANGELOG.md", "dist-workspace.toml", "README.md"):
            print(name)
        return 0
    docs = list(documents(root))
    problems = check(root, docs)
    if problems:
        print("check-release-claims: a document says something the tree contradicts:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        return 1
    version = workspace_version(root / "Cargo.toml")
    print(
        f"release claims: ok. {len(docs)} documents; none calls {version} unpublished, "
        f"and none offers an installer dist does not build"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
