#!/usr/bin/env bash
#
# Cut a release: set the version, date the changelog entry, commit, tag.
# Pushing the tag is what publishes, and pushing is yours to do.
#
#   scripts/release.sh 0.2.0
#   git push origin main && git push origin v0.2.0
#
# The tag starts three workflows, from the one push: crates.yml publishes
# every crate to crates.io, wheels.yml uploads the wheels and the sdist to
# PyPI, and release.yml (dist) builds the binaries and installers and makes
# the GitHub release. Nothing else is approved or clicked (RELEASING.md).
#
# What it changes: `[workspace.package] version` and the workspace path
# dependencies in Cargo.toml, the `## [Unreleased]` heading in CHANGELOG.md
# (which becomes the new entry, dated today) and its link definitions, and
# Cargo.lock. Then scripts/check-all.sh, which is the same gate CI runs.
#
# Usage: release.sh <version> [--no-verify] [--no-commit]

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

VERSION="${1:-}"
shift || true
VERIFY=1
COMMIT=1
for arg in "$@"; do
    case "$arg" in
        --no-verify) VERIFY=0 ;;
        --no-commit) COMMIT=0 ;;
        *) echo "release: unknown option $arg" >&2; exit 2 ;;
    esac
done

die() { echo "release: $*" >&2; exit 1; }

[[ -n "$VERSION" ]] || die "usage: release.sh <version> [--no-verify] [--no-commit]"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] \
    || die "\"$VERSION\" is not a version. Write it without the leading v"
TAG="v$VERSION"

# A release is built from what is committed, or it is not reproducible from
# the tag it claims to be.
[[ -z "$(git status --porcelain)" ]] \
    || die "the working tree has uncommitted changes. Commit them first; this makes only the release commit"
git rev-parse -q --verify "refs/tags/$TAG" >/dev/null \
    && die "$TAG already exists here. A published version stays published: release the next one instead"
if git ls-remote --exit-code --tags origin "$TAG" >/dev/null 2>&1; then
    die "$TAG is already on the remote. Release the next version instead"
fi

CURRENT="$(awk '
    /^\[workspace\.package\]/ { in_section = 1; next }
    /^\[/ { in_section = 0 }
    in_section && /^version *= *"/ { match($0, /"[^"]+"/); print substr($0, RSTART + 1, RLENGTH - 2); exit }
' Cargo.toml)"
echo "release: $CURRENT -> $VERSION"

# The workspace version, and every path dependency that carries it.
perl -0pi -e 's/(\[workspace\.package\]\nversion = ")[^"]+/${1}'"$VERSION"'/' Cargo.toml
perl -0pi -e 's/^([a-z0-9-]+ = \{ version = ")[^"]+(", path = "crates\/)/${1}'"$VERSION"'${2}/mg' Cargo.toml

# The changelog: `## [Unreleased]` keeps its place, and today's entry takes
# what was under it. An entry already written by hand for this version is
# left alone but dated.
python3 - "$VERSION" <<'PY'
import datetime, re, sys, pathlib

version = sys.argv[1]
today = datetime.date.today().isoformat()
repo = "https://github.com/sercanatalik/galata-vault"
p = pathlib.Path("CHANGELOG.md")
text = p.read_text()

heading = f"## [{version}] - {today}"
existing = re.search(rf"^## \[{re.escape(version)}\][^\n]*$", text, re.M)
if existing:
    text = text[: existing.start()] + heading + text[existing.end() :]
else:
    text = re.sub(r"^## \[Unreleased\]\n", f"## [Unreleased]\n\n{heading}\n", text, count=1, flags=re.M)

text = re.sub(
    r"^\[Unreleased\]: .*$",
    f"[Unreleased]: {repo}/compare/v{version}...HEAD",
    text,
    count=1,
    flags=re.M,
)
link = f"[{version}]: {repo}/releases/tag/v{version}"
if link not in text:
    text = re.sub(r"^\[Unreleased\]: .*$", lambda m: m.group(0) + "\n" + link, text, count=1, flags=re.M)
p.write_text(text)
print(f"changelog: {heading}")
PY

# Cargo.lock names the workspace members by version too.
cargo update --workspace --offline >/dev/null 2>&1 || cargo update --workspace >/dev/null

scripts/check-version.sh
if (( VERIFY )); then
    echo "release: running scripts/check-all.sh (--no-verify skips it)"
    scripts/check-all.sh
fi

if (( ! COMMIT )); then
    echo "release: the tree is at $VERSION, uncommitted (--no-commit)"
    exit 0
fi

git commit -s -q -a -m "Set the workspace to $VERSION and date its changelog entry"
git tag -a "$TAG" -m "$TAG"

cat <<DONE

release: committed and tagged $TAG. Nothing has been pushed.

  git push origin HEAD && git push origin $TAG

The tag starts crates.yml (crates.io), wheels.yml (PyPI) and release.yml
(binaries and the GitHub release).
DONE
