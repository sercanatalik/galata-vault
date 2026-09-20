#!/usr/bin/env bash
#
# galata-vault-mcp hands vault metadata to a language model. Its whole claim to being
# safe is what it cannot do: it holds only meta tokens (name key, never the
# vault private key), and it links no code that could decrypt a value even if
# it were handed one. Its requests go through galata-vault-client, the one client
# implementation the SDK also uses; galata-vault-client links no value crypto either
# (scripts/check-client-linkage.sh), so sharing it costs this guard nothing.
#
#   1. DIRECT workspace dependencies are exactly galata-vault-proto, galata-vault-keys and
#      galata-vault-client.
#   2. At ANY depth, none of: galata-vault-seal, age.
#
# Usage: check-mcp-linkage.sh [check|plant|targets|expect] [root]

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

case "$VERB" in
    targets)
        echo "crates/galata-vault-mcp/Cargo.toml"
        echo "Cargo.lock"
        exit 0
        ;;
    plant)
        # An agent-facing binary reaching for the value crate: the first step
        # towards a tool that could return a secret.
        perl -0pi -e 's/\[dependencies\]/[dependencies]\ngalata-vault-seal.workspace = true/' \
            "$ROOT/crates/galata-vault-mcp/Cargo.toml"
        exit 0
        ;;
    expect)
        # What a planted run must name.
        echo "galata-vault-mcp reaches galata-vault-seal"
        exit 0
        ;;
esac

TABLE='{
  "galata-vault-mcp": {"direct_ok": ["galata-vault-proto", "galata-vault-keys", "galata-vault-client"], "forbidden": ["galata-vault-seal", "age"]}
}'

if ! failures=$(python3 "$HERE/lib/linkage.py" "$ROOT" "$TABLE"); then
    echo "mcp linkage: galata-vault-mcp links code that could read a secret value" >&2
    sed 's/^/  /' <<<"$failures" >&2
    exit 1
fi

echo "mcp linkage: ok. galata-vault-mcp links galata-vault-proto, galata-vault-keys and galata-vault-client only, and no value decryption at any depth"
