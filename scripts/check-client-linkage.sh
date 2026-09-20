#!/usr/bin/env bash
#
# galata-vault-client is the one client transport: request building, signing and
# response mapping, shared by the SDK and by galata-vault-mcp. galata-vault-mcp's promise that it
# cannot read a secret value rests on this crate linking no value decryption,
# and the SDK's promise that it leaves its host alone rests on this crate
# linking no host-process code either.
#
#   1. DIRECT workspace dependencies are exactly galata-vault-proto and galata-vault-keys.
#   2. At ANY depth, none of: galata-vault-seal, age (value decryption), keyring,
#      rlimit, rpassword, clap, pyo3 (host-process code).
#
# Usage: check-client-linkage.sh [check|plant|targets|expect] [root]

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
        echo "crates/galata-vault-client/Cargo.toml"
        echo "Cargo.lock"
        exit 0
        ;;
    plant)
        # The shared transport reaching for the value crate "for a helper":
        # the first step towards an MCP server that could return a secret.
        perl -0pi -e 's/\n\[dependencies\]\n/\n[dependencies]\ngalata-vault-seal.workspace = true\n/' \
            "$ROOT/crates/galata-vault-client/Cargo.toml"
        exit 0
        ;;
    expect)
        # What a planted run must name.
        echo "galata-vault-client reaches galata-vault-seal"
        exit 0
        ;;
esac

TABLE='{
  "galata-vault-client": {
    "direct_ok": ["galata-vault-proto", "galata-vault-keys"],
    "forbidden": ["galata-vault-seal", "age", "keyring", "rlimit", "rpassword", "clap", "pyo3"]
  }
}'

if ! failures=$(python3 "$HERE/lib/linkage.py" "$ROOT" "$TABLE"); then
    echo "client linkage: galata-vault-client links value decryption or host-process code" >&2
    sed 's/^/  /' <<<"$failures" >&2
    exit 1
fi

echo "client linkage: ok. galata-vault-client links galata-vault-proto and galata-vault-keys only, and no value decryption, keychain, process-limit, prompt, CLI or Python code at any depth"
