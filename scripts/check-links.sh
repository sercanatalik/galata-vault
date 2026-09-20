#!/usr/bin/env bash
#
# No published link points at something that is not here.
#
# The README is where a reader meets this project, and a link there to a
# document the repository does not contain is a promise it does not keep.
# The same goes for the `readme` a crate names, which crates.io renders.
#
# What is scanned, and what is skipped, is in scripts/lib/links.py. Fragments
# are dropped before resolving: this checks that a document exists, not that
# a heading inside it does.
#
# Usage: check-links.sh [check|plant|targets|expect] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|targets|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

# The document a planted link points at, which must not exist.
PLANTED="docs/a-document-that-is-not-here.md"

case "$VERB" in
    targets)
        python3 "$HERE/lib/links.py" targets "$ROOT"
        ;;
    plant)
        printf '\n[a planted dead link](%s)\n' "$PLANTED" >>"$ROOT/README.md"
        ;;
    expect)
        echo "$PLANTED"
        ;;
    check)
        python3 "$HERE/lib/links.py" check "$ROOT"
        ;;
esac
