#!/usr/bin/env bash
#
# What the one crate links, and what its modules may name.
#
# galata-vault used to be ten crates, and cargo enforced the separation: the
# server could not name the value crypto because it did not depend on it.
# One crate has to earn that twice over.
#
#   1. The dependency graph, per feature set. `--features server` must not
#      pull in a value- or name-crypto crate, an HTTP client, a keychain or a
#      prompt; the SDK's default build must not pull in a database, an HTTP
#      server or an async runtime. This is still cargo's answer, read out of
#      `cargo tree`, and it is the half that cannot be argued with.
#   2. The module graph, by source. `server`, `server_core` and `backend` may
#      not name `crate::keys`, `crate::seal`, `crate::client` or the SDK
#      root; `client` may not name `crate::seal`. Inside one crate the
#      compiler will not say this for us, so a violation is a `#[cfg]` away
#      and this is the guard that catches it.
#
# Usage: check-linkage.sh [check|plant|plants|targets|expect] [root]

set -uo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|plants|targets|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"

if [[ ! -d "$ROOT/crates/galata-vault/src" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

# Value and name crypto: what a server must never link. Signature and hash
# crates are not here -- the server verifies request signatures.
VALUE_CRYPTO="chacha20poly1305 crypto_box age bech32 hkdf hmac"
HOST="keyring rlimit rpassword clap pyo3"
SERVING="rusqlite axum tokio tracing"

case "$VERB" in
    targets)
        echo "crates/galata-vault/Cargo.toml"
        echo "crates/galata-vault/src"
        echo "crates/gv-server/Cargo.toml"
        exit 0
        ;;
    plants)
        echo "dependency"
        echo "module"
        exit 0
        ;;
    expect)
        if [[ "${GV_GUARD_PLANT:-dependency}" == module ]]; then
            echo "server_core"
            echo "crate::seal"
        else
            echo "chacha20poly1305"
        fi
        exit 0
        ;;
    plant)
        case "${GV_GUARD_PLANT:-dependency}" in
            module)
                # The serving side reaching for value crypto.
                printf '\n#[allow(unused_imports)]\nuse crate::seal::ConfigFormat;\n' \
                    >>"$ROOT/crates/galata-vault/src/server_core/auth.rs"
                ;;
            *)
                # Value crypto pulled into the server feature set.
                perl -0pi -e 's/^(server = \["server-core", )/${1}"dep:chacha20poly1305", /m' \
                    "$ROOT/crates/galata-vault/Cargo.toml"
                ;;
        esac
        exit 0
        ;;
esac

failed=0
note() { echo "linkage: $*" >&2; failed=1; }

# 1. The dependency graph, per feature set.
tree() {
    (cd "$ROOT" && cargo tree -p galata-vault -e normal --prefix none "$@" 2>/dev/null | awk '{print $1}' | sort -u)
}
check_set() {
    local label="$1"; shift
    local forbidden="$1"; shift
    local crates
    crates=$(tree "$@")
    # A guard that reads an empty graph would pass every check it makes.
    if (( $(wc -l <<<"$crates") < 20 )); then
        note "$label: cargo tree returned $(wc -l <<<"$crates") crates; refusing to call that a dependency graph"
        return
    fi
    local hit=0
    for c in $forbidden; do
        if grep -qx "$c" <<<"$crates"; then
            note "$label links $c"
            hit=1
        fi
    done
    (( hit )) || echo "  $label: ok ($(wc -l <<<"$crates" | tr -d ' ') crates, none forbidden)"
}

check_set "sdk (default)"        "$SERVING $HOST aws-sdk-s3"                 
check_set "sdk --features embedded" "axum tracing $HOST aws-sdk-s3"          --features embedded
check_set "server only"          "$VALUE_CRYPTO $HOST ureq aws-sdk-s3"       --no-default-features --features server
# gv-mcp is a host process: an async runtime and a process limit are its
# own, and expected. A database, an HTTP server, a keychain or a prompt are
# not.
check_set "mcp only"             "rusqlite axum keyring rpassword clap pyo3 aws-sdk-s3" --no-default-features --features mcp

# 2. The module graph, by source.
module_rule() {
    local module="$1"; shift
    local dir="$ROOT/crates/galata-vault/src/$module"
    [[ -d "$dir" ]] || { note "module $module is missing"; return; }
    for forbidden in "$@"; do
        local hits
        hits=$(grep -rn "crate::${forbidden}\b" "$dir" --include='*.rs' | grep -v '^\s*//' | head -3)
        if [[ -n "$hits" ]]; then
            note "$module names crate::$forbidden, which it must not reach:"
            sed 's/^/    /' <<<"$hits" >&2
        fi
    done
}
module_rule server      keys seal client cli mcp
module_rule server_core keys seal client cli mcp
module_rule backend     keys seal client cli mcp
module_rule client      seal

if (( failed )); then
    exit 1
fi
echo "linkage: ok. the server feature set links no value or name crypto, the SDK links no database, HTTP server or runtime, and the serving modules name no client-side crypto"
