#!/usr/bin/env bash
#
# galata-vault, the Rust SDK, is linked into other people's processes. It must
# leave its host alone: no keychain, no process limits, no terminal prompts, no
# argument parser, no Python runtime. Those belong to gv and gv-py, which are
# built on the SDK, never the other way round. And applications depend on it
# from crates.io, so it must stay publishable.
#
# Two builds are checked:
#
#   default features
#     DIRECT workspace dependencies: galata-vault-client, galata-vault-proto,
#     galata-vault-keys, galata-vault-seal.
#     At ANY depth, none of: keyring, rlimit, rpassword, clap, pyo3,
#     galata-vault-cli, gv-py, galata-vault-mcp, galata-vault-server,
#     galata-vault-server-core, galata-vault-store, rusqlite, axum, tokio.
#
#   --features embedded (the in-process backend)
#     DIRECT workspace dependencies: the four above, galata-vault-server-core,
#     galata-vault-store. rusqlite comes with galata-vault-store; still none
#     of: keyring, rlimit, rpassword, clap, pyo3, galata-vault-cli, gv-py,
#     galata-vault-mcp, galata-vault-server, axum, tokio, aws-sdk-s3.
#
# Then publishability,
# offline:
#   - galata-vault is not `publish = false`;
#   - every workspace crate it reaches through normal, build or optional
#     edges is published, and named with a version (scripts/lib/packaging.py);
#   - `cargo package --no-verify` of the SDK and those crates succeeds, the
#     unpublished ones resolving from cargo's local overlay, and the packaged
#     manifest's dependency tables hold no `path`.
#
# Three plants, each on its own copy (scripts/test-guards.sh sets
# GV_GUARD_PLANT):
#   keyring        the SDK reaches for the keychain;
#   publish-false  the SDK is marked `publish = false`;
#   versionless    the SDK names a workspace crate by path, with no version.
#
# Usage: check-sdk-linkage.sh [check|plant|plants|targets|expect] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|plants|targets|expect) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK="$ROOT/crates/galata-vault/Cargo.toml"
PLANT="${GV_GUARD_PLANT:-keyring}"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

case "$VERB" in
    targets)
        echo "crates/galata-vault/Cargo.toml"
        echo "Cargo.lock"
        echo "scripts/lib/linkage.py"
        echo "scripts/lib/packaging.py"
        exit 0
        ;;
    plants)
        printf '%s\n' keyring publish-false versionless
        exit 0
        ;;
    plant)
        case "$PLANT" in
            keyring)
                # The library reaching for the keychain: the first step towards
                # an SDK that pops a system prompt inside someone else's service.
                perl -0pi -e 's/\n\[dependencies\]\n/\n[dependencies]\nkeyring.workspace = true\n/' "$SDK"
                ;;
            publish-false)
                # The SDK taken off the registry: every application that
                # depends on `galata-vault = "0.1"` stops getting fixes.
                perl -0pi -e 's/\nversion\.workspace = true\n/\nversion.workspace = true\npublish = false\n/' "$SDK"
                ;;
            versionless)
                # A workspace crate named by path alone: cargo cannot package it.
                perl -0pi -e 's/\ngalata-vault-proto\.workspace = true\n/\ngalata-vault-proto = { path = "..\/galata-vault-proto" }\n/' "$SDK"
                ;;
            *) echo "unknown plant $PLANT" >&2; exit 2 ;;
        esac
        exit 0
        ;;
    expect)
        # What a planted run must name.
        case "$PLANT" in
            keyring) echo "galata-vault reaches keyring" ;;
            publish-false) echo "galata-vault is publish = false" ;;
            versionless) echo "galata-vault depends on galata-vault-proto by path with no version" ;;
        esac
        exit 0
        ;;
esac

HOST='"keyring", "rlimit", "rpassword", "clap", "pyo3", "galata-vault-cli", "gv-py", "galata-vault-mcp", "galata-vault-server", "axum", "tokio"'
DEFAULT="{
  \"galata-vault\": {
    \"direct_ok\": [\"galata-vault-client\", \"galata-vault-proto\", \"galata-vault-keys\", \"galata-vault-seal\"],
    \"forbidden\": [$HOST, \"galata-vault-server-core\", \"galata-vault-store\", \"rusqlite\"]
  }
}"
EMBEDDED="{
  \"galata-vault\": {
    \"direct_ok\": [\"galata-vault-client\", \"galata-vault-proto\", \"galata-vault-keys\", \"galata-vault-seal\", \"galata-vault-server-core\", \"galata-vault-store\"],
    \"forbidden\": [$HOST, \"aws-sdk-s3\"]
  }
}"

failed=0
check_set() {
    local label="$1" table="$2"
    shift 2
    local failures
    if ! failures=$(python3 "$HERE/lib/linkage.py" "$ROOT" "$table" "$@" 2>&1); then
        echo "sdk linkage ($label): FAILED, galata-vault links code that would reach into its host process" >&2
        sed 's/^/  /' <<<"$failures" >&2
        failed=1
    else
        echo "sdk linkage ($label): ok"
    fi
}

check_set "default features" "$DEFAULT"
check_set "--features embedded" "$EMBEDDED" --features galata-vault/embedded

# Publishable, offline. The manifest rules first, so a failure names its
# reason rather than cargo's first complaint.
if ! closure=$(python3 "$HERE/lib/packaging.py" "$ROOT" closure galata-vault); then
    echo "sdk publish: FAILED, galata-vault must stay publishable" >&2
    sed 's/^/  /' <<<"$closure" >&2
    exit 1
fi
if (( failed )); then
    exit 1
fi
args=()
while IFS= read -r crate; do args+=(-p "$crate"); done <<<"$closure"
if ! out=$(cd "$ROOT" && cargo package --no-verify --offline --allow-dirty "${args[@]}" 2>&1); then
    echo "sdk publish: FAILED, cargo refuses to package galata-vault" >&2
    grep -v '^warning: ignoring' <<<"$out" | tail -20 | sed 's/^/  /' >&2
    exit 1
fi
# The packaged manifest: every dependency table by version, none by path.
if ! paths=$(cd "$ROOT" && cargo metadata --no-deps --format-version 1 --offline | python3 -c '
import io, json, sys, tarfile, tomllib
m = json.load(sys.stdin)
v = next(p["version"] for p in m["packages"] if p["name"] == "galata-vault")
target = m["target_directory"]
crate = f"{target}/package/galata-vault-{v}.crate"
with tarfile.open(crate) as t:
    doc = tomllib.load(t.extractfile(f"galata-vault-{v}/Cargo.toml"))
tables = [(k, doc.get(k, {})) for k in ("dependencies", "build-dependencies", "dev-dependencies")]
for target, spec in doc.get("target", {}).items():
    tables += [(f"target.{target}.{k}", spec.get(k, {})) for k in ("dependencies", "build-dependencies", "dev-dependencies")]
bad = [f"{kind}.{name}" for kind, deps in tables for name, d in deps.items() if isinstance(d, dict) and "path" in d]
bad += [f"{kind}.{name}" for kind, deps in tables for name, d in deps.items() if isinstance(d, dict) and "version" not in d and "git" not in d]
print("\n".join(bad))
sys.exit(1 if bad else 0)
'); then
    echo "sdk publish: FAILED, the packaged galata-vault manifest names a dependency without a registry version:" >&2
    sed 's/^/  /' <<<"$paths" >&2
    exit 1
fi

echo "sdk linkage: ok. galata-vault links no keychain, process-limit, prompt, CLI or Python code at any depth; by default no store or server core either, and with embedded no HTTP server, runtime or S3 client; it packages offline with $(wc -l <<<"$closure" | tr -d ' ') published crates and a manifest free of path dependencies"
