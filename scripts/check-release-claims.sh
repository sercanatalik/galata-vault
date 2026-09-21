#!/usr/bin/env bash
#
# A document says only what the tree can back.
#
# On 2026-09-21 the landing page offered `brew install sercanatalik/tap/...`
# for a tap that does not exist, and six places said 0.1.0 was not yet
# published while it was on crates.io -- four of them crate READMEs being
# rendered beside the version they denied. check-all.sh was green through all
# of it, the release verified and the attestations checked.
#
# `scripts/release.sh` sets the version in Cargo.toml, CHANGELOG.md and
# Cargo.lock. It touches no prose, and until this guard nothing else did: the
# release process updated the version where it is written as data and left
# what the documents SAY about it unchecked.
#
# Two rules, both read from files this repository already maintains, so
# neither asks the network. The reasoning, and why prose stays free while code
# blocks do not, is in scripts/lib/release_claims.py.
#
# Usage: check-release-claims.sh [check|plant|targets|plants|expect] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|targets|plants|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

# Two, because the rules fail for different reasons: one is a sentence that has
# gone stale, the other an instruction that never worked.
PLANT="${GV_GUARD_PLANT:-unpublished-claim}"

case "$VERB" in
    plants)
        echo unpublished-claim
        echo unbuilt-installer
        ;;
    targets)
        python3 "$HERE/lib/release_claims.py" targets "$ROOT"
        ;;
    plant)
        case "$PLANT" in
            # The shape that shipped: a banner telling readers to build from a
            # checkout until a version that had already been published.
            unpublished-claim)
                printf '\n**Not yet published: these lines work after 0.1.0 is published.**\n' \
                    >>"$ROOT/README.md"
                ;;
            # The shape that was live on the landing page, in a fenced block,
            # because a fenced block is what a reader copies.
            unbuilt-installer)
                printf '\n```sh\nbrew install sercanatalik/tap/galata-vault-cli\n```\n' \
                    >>"$ROOT/README.md"
                ;;
            *)
                echo "check-release-claims: unknown plant $PLANT" >&2
                exit 2
                ;;
        esac
        ;;
    expect)
        case "$PLANT" in
            unpublished-claim) echo "README.md"; echo "unpublished" ;;
            unbuilt-installer) echo "README.md"; echo "brew install" ;;
        esac
        ;;
    check)
        python3 "$HERE/lib/release_claims.py" check "$ROOT"
        ;;
esac
