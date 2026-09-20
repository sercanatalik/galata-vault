#!/usr/bin/env bash
#
# The vector regenerate-and-diff (docs/spec/README.md#5.3). The independent
# Python generator (scripts/vectors/) checks its age implementation against
# the vendored C2SP CCTV vectors, regenerates every file in
# testdata/vectors/v1/, and fails if a committed file differs from what it
# generates, or if a file there is one it no longer generates. It writes
# nothing.
#
# It needs uv, which fetches cryptography and PyNaCl from PyPI into its own
# cache (nothing is installed globally). Without uv it prints SKIPPED and
# exits 0, and a skip is never reported as a pass; with GV_REQUIRE_VECTORS=1
# (CI) a skip is a failure.
#
# Usage: vectors.sh [root]

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
LABEL="vector regenerate-and-diff"

if ! command -v uv >/dev/null 2>&1; then
    if [[ "${GV_REQUIRE_VECTORS:-0}" == 1 ]]; then
        echo "$LABEL: FAILED, uv is required (GV_REQUIRE_VECTORS=1)" >&2
        exit 1
    fi
    echo "$LABEL: SKIPPED, uv not installed; the vectors were not regenerated"
    exit 0
fi

cd "$ROOT"
if out=$(uv run -q --no-project --with cryptography --with pynacl \
    python3 scripts/vectors/generate.py --check 2>&1); then
    echo "$LABEL: ok ($(tr '\n' ' ' <<<"$out" | sed 's/  */ /g; s/ $//'))"
else
    echo "$LABEL: FAILED" >&2
    echo "$out" | tail -40 >&2
    exit 1
fi
