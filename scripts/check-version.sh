#!/usr/bin/env bash
#
# One version, everywhere it is written down.
#
# The workspace version (`[workspace.package] version`) is what every
# published crate carries, what the `v<version>` tag names, and what the
# newest CHANGELOG.md entry heads. A release is nothing but that tag being
# pushed (RELEASING.md), so a tree where those disagree would publish
# something nobody described.
#
# Checked:
#   - every path dependency in `[workspace.dependencies]` names the workspace
#     version, so a packaged manifest points at a registry version that exists;
#   - the newest CHANGELOG.md release heading is the workspace version, and
#     has its link definition at the foot of the file;
#   - with GV_EXPECT_VERSION set -- the release workflows set it from the tag
#     they were started by -- the workspace version is that version.
#
# Between releases the tree carries the version that was last released, and
# pending notes live under `## [Unreleased]`. scripts/release.sh moves the
# version and the changelog together, which is what keeps this guard quiet.
#
# Usage: check-version.sh [check|plant|plants|targets|expect] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|plants|targets|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PLANTED="9.9.9"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

# The version under [workspace.package], and nothing else's.
workspace_version() {
    awk '
        /^\[workspace\.package\]/ { in_section = 1; next }
        /^\[/ { in_section = 0 }
        in_section && /^version *= *"/ {
            match($0, /"[^"]+"/)
            print substr($0, RSTART + 1, RLENGTH - 2)
            exit
        }
    ' "$ROOT/Cargo.toml"
}

case "$VERB" in
    targets)
        echo "Cargo.toml"
        echo "CHANGELOG.md"
        exit 0
        ;;
    plants)
        echo "changelog"
        echo "dependency"
        exit 0
        ;;
    expect)
        echo "$PLANTED"
        [[ "${GV_GUARD_PLANT:-changelog}" == dependency ]] && echo "galata-vault"
        exit 0
        ;;
    plant)
        case "${GV_GUARD_PLANT:-changelog}" in
            dependency)
                # A path dependency left behind at a version of its own.
                perl -0pi -e 's/^(galata-vault = \{ version = ")[^"]+/${1}'"$PLANTED"'/m' \
                    "$ROOT/Cargo.toml"
                ;;
            *)
                # A changelog whose newest entry is not what the tree is.
                perl -0pi -e 's/^## \[[0-9][^\]]*\]/## ['"$PLANTED"']/m' "$ROOT/CHANGELOG.md"
                ;;
        esac
        exit 0
        ;;
esac

version="$(workspace_version)"
failed=0
note() { echo "version: $*" >&2; failed=1; }

if [[ -z "$version" ]]; then
    note "Cargo.toml has no [workspace.package] version"
    exit 1
fi

# Every workspace path dependency moves with it.
while IFS= read -r line; do
    name="${line%% *}"
    declared="$(sed -n 's/.*version = "\([^"]*\)".*/\1/p' <<<"$line")"
    [[ -z "$declared" ]] && continue
    [[ "$declared" == "$version" ]] \
        || note "$name is declared at $declared but the workspace is $version (Cargo.toml)"
done < <(grep -E '^[a-z0-9-]+ = \{ version = "[^"]+", path = "crates/' "$ROOT/Cargo.toml")

# The newest release heading is this version, and it is linkable.
newest="$(sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' "$ROOT/CHANGELOG.md" | head -1)"
if [[ -z "$newest" ]]; then
    note "CHANGELOG.md has no release heading"
elif [[ "$newest" != "$version" ]]; then
    note "CHANGELOG.md's newest entry is $newest but the workspace is $version"
elif ! grep -qE "^\[$version\]: " "$ROOT/CHANGELOG.md"; then
    note "CHANGELOG.md's $version entry has no link definition at the foot of the file"
fi

# What the tag says, when a release workflow is asking.
if [[ -n "${GV_EXPECT_VERSION:-}" && "${GV_EXPECT_VERSION}" != "$version" ]]; then
    note "the tag names ${GV_EXPECT_VERSION} but the workspace is $version"
fi

if (( failed )); then
    exit 1
fi
echo "version: ok ($version, in Cargo.toml, its path dependencies and CHANGELOG.md)"
