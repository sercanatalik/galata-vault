#!/usr/bin/env bash
#
# The label registry (docs/spec/keys.md#3) is exactly the set of derivation
# labels and context strings the protocol, key and seal crates use, in both
# directions (docs/spec/README.md#7). A
# label in the code that the registry does not list is an unspecified
# derivation; a registry row the code no longer uses is a stale spec.
#
# Extracted from the non-test source of crates/galata-vault-proto, crates/galata-vault-keys and
# crates/galata-vault-seal (each file up to its first #[cfg(test)]):
#   - "gv/v1/<purpose>" string and byte-string literals;
#   - the HKDF salt "galata-vault/v<N>";
#   - "galata-vault v<N> <purpose>" context strings.
# Compared with the backticked first column of the registry table.
#
# Usage: check-spec-labels.sh [check|plant|targets|expect] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|targets|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLANTED="gv/v1/planted-by-test-guards"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

case "$VERB" in
    targets)
        echo "docs/spec/keys.md"
        echo "crates/galata-vault/src/proto"
        echo "crates/galata-vault/src/proto/frame.rs"
        echo "crates/galata-vault/src/keys"
        echo "crates/galata-vault/src/seal"
        echo "scripts/lib/spec_labels.py"
        exit 0
        ;;
    expect)
        echo "$PLANTED"
        exit 0
        ;;
    plant)
        # A new derivation label added to the code without a registry row.
        perl -0pi -e 's/(\n\s*pub const SIG: &str = "gv\/v1\/sig";)/$1\n    pub const PLANTED: &str = "gv\/v1\/planted-by-test-guards";/' \
            "$ROOT/crates/galata-vault/src/proto/frame.rs"
        exit 0
        ;;
esac

if ! out=$(python3 "$HERE/lib/spec_labels.py" "$ROOT"); then
    echo "spec labels: the label registry (docs/spec/keys.md#3) and the code disagree" >&2
    sed 's/^/  /' <<<"$out" >&2
    exit 1
fi
echo "spec labels: ok. $out"
