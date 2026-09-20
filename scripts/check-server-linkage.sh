#!/usr/bin/env bash
#
# The server cannot read what it stores, and this makes that a fact about the
# build rather than about anyone's care.
#
# galata-vault-server-core and galata-vault-server handle every byte the service
# holds: ciphertext, sealed bundles, hashes. Their claim to safety is that no
# code which could open any of it is in the binary:
#
#   1. DIRECT workspace dependencies: galata-vault-server-core exactly
#      galata-vault-proto and galata-vault-store; galata-vault-server those two
#      and galata-vault-server-core.
#   2. At ANY depth, none of: galata-vault-keys (bundles, name key), galata-vault-seal (values),
#      age, crypto_box, x25519-dalek.
#   3. galata-vault-server-core, which the SDK's embedded backend links too, holds no
#      HTTP stack, async runtime or S3 client: no axum, hyper, tokio or
#      aws-sdk-s3 at any depth.
#   4. galata-vault-server links no aws-sdk-s3: it journals to a directory
#      beside the database, and speaks to no bucket.
#
# There is one server build, so each crate is checked once.
#
# Dev-dependencies are exempt: an integration test may link the client crates
# to produce real ciphertext, because a test is not the shipped binary.
#
# Usage: check-server-linkage.sh [check|plant|targets|expect] [root]

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
        echo "crates/galata-vault-server-core/Cargo.toml"
        echo "crates/galata-vault-server/Cargo.toml"
        echo "Cargo.lock"
        exit 0
        ;;
    plant)
        # The first step towards a server that can decrypt: linking the value
        # crate into the core "just for a helper". Every server build, and the
        # SDK's embedded backend, would inherit it.
        perl -0pi -e 's/\[dependencies\]/[dependencies]\ngalata-vault-seal.workspace = true/' \
            "$ROOT/crates/galata-vault-server-core/Cargo.toml"
        exit 0
        ;;
    expect)
        # What a planted run must name.
        echo "galata-vault-server-core reaches galata-vault-seal"
        echo "galata-vault-server reaches galata-vault-seal"
        exit 0
        ;;
esac

DECRYPT='"galata-vault-keys", "galata-vault-seal", "age", "crypto_box", "x25519-dalek"'
CORE="\"galata-vault-server-core\": {\"direct_ok\": [\"galata-vault-proto\", \"galata-vault-store\"], \"forbidden\": [$DECRYPT, \"axum\", \"hyper\", \"tokio\", \"aws-sdk-s3\"]}"
SERVER_DIRECT='["galata-vault-proto", "galata-vault-store", "galata-vault-server-core"]'
TABLE="{
  $CORE,
  \"galata-vault-server\":  {\"direct_ok\": $SERVER_DIRECT, \"forbidden\": [$DECRYPT, \"aws-sdk-s3\"]}
}"

failed=0
# One feature set: a label, the table, and the arguments cargo metadata
# resolves it with.
check_set() {
    local label="$1" table="$2"
    shift 2
    local failures
    if ! failures=$(python3 "$HERE/lib/linkage.py" "$ROOT" "$table" "$@" 2>&1); then
        echo "server linkage ($label): FAILED, a server-side crate links what it must not" >&2
        sed 's/^/  /' <<<"$failures" >&2
        failed=1
    else
        echo "server linkage ($label): ok"
    fi
}

check_set "galata-vault-server-core and galata-vault-server" "$TABLE"

if (( failed )); then
    exit 1
fi
echo "server linkage: ok. galata-vault-server-core and galata-vault-server link no bundle, name-key or value crypto at any depth; the core links no HTTP, async or S3 crate, and the server no S3 client"
