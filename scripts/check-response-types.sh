#!/usr/bin/env bash
#
# Responses are tolerant (docs/spec/http-api.md#7.2): a newer server may add a
# field to any response, and an older client must read the rest. So in the
# protocol crate, galata-vault-proto, `deny_unknown_fields` may appear only on the types
# allowed below, and on no response type:
#
#   - request bodies, which are strict (http-api.md#7.1);
#   - the audit row, every field of which is hashed (audit.md#2);
#   - the children record's plaintext, which travels inside the owner's
#     ciphertext and is owner-signed, never a response body (records.md#5);
#   - the MCP's configuration file, which is local and never on the wire.
#
# The unit test `every_response_tolerates_an_unknown_field` checks each
# response type by parsing; this checks the declarations, so a new response
# type cannot be declared strict before anyone writes its test.
#
# Usage: check-response-types.sh [check|plant|targets|expect] [root]

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
        echo "crates/galata-vault-proto/src"
        echo "crates/galata-vault-proto/src/api.rs"
        echo "scripts/lib/response_types.py"
        exit 0
        ;;
    expect)
        echo "VaultStatus"
        exit 0
        ;;
    plant)
        # A response type made strict: an older client would refuse a newer
        # server's vault status outright.
        perl -0pi -e 's/\npub struct VaultStatus \{/\n#[serde(deny_unknown_fields)]\npub struct VaultStatus {/' \
            "$ROOT/crates/galata-vault-proto/src/api.rs"
        exit 0
        ;;
esac

if ! out=$(python3 "$HERE/lib/response_types.py" "$ROOT"); then
    echo "response types: a galata-vault-proto type outside the allow-list refuses unknown fields" >&2
    sed 's/^/  /' <<<"$out" >&2
    exit 1
fi
echo "response types: ok. $out"
