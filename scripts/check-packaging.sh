#!/usr/bin/env bash
#
# Every published crate packages, offline, as it would go to crates.io
# (the publishable set).
#
# The published set is read from cargo: every workspace member without
# `publish = false`. `cargo package --workspace` would also try the
# unpublished members, so the set is named with -p; unpublished workspace
# crates in the set resolve from cargo's local overlay, not crates.io.
#
#   1. The licence text in every published package, identical to the root
#      (scripts/sync-licenses.sh --check).
#   2. Metadata: description, the workspace licence, repository, README,
#      keywords, categories and docs.rs metadata.
#   3. Dependencies: a published crate depends on workspace crates by version
#      and only on published ones; an unpublished dev-dependency is path-only.
#      A failure names both crates.
#   4. `cargo package --no-verify --offline` for the set, then each .crate
#      holds LICENSE-MIT and README.md and no tests/.
#
# `verify` (not a guard verb; check-all and CI run it) also builds every
# package from its .crate, as `cargo publish` would.
#
# Usage: check-packaging.sh [check|plant|targets|expect|verify] [root]

set -euo pipefail

VERB=check
if [[ $# -gt 0 ]]; then
    case "$1" in check|plant|targets|expect|verify) VERB="$1"; shift ;; esac
fi
ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -d "$ROOT/crates" ]]; then
    echo "$(basename "$0"): $ROOT is not a galata-vault workspace; refusing to scan nothing and call it ok" >&2
    exit 2
fi

case "$VERB" in
    targets)
        echo "Cargo.toml"
        echo "LICENSE-MIT"
        echo "crates/galata-vault-seal/LICENSE-MIT"
        echo "scripts/sync-licenses.sh"
        echo "scripts/lib/packaging.py"
        exit 0
        ;;
    plant)
        # A published crate that lost its licence text: its package would ship
        # without the licence it claims.
        rm -f "$ROOT/crates/galata-vault-seal/LICENSE-MIT"
        exit 0
        ;;
    expect)
        echo "crates/galata-vault-seal/LICENSE-MIT"
        echo "galata-vault-seal-0.1.0.crate lacks LICENSE-MIT"
        exit 0
        ;;
esac

cd "$ROOT"
fail() {
    echo "packaging: FAILED, $1" >&2
    [[ -n "${2:-}" ]] && sed 's/^/  /' <<<"$2" >&2
    exit 1
}

out=$("$HERE/sync-licenses.sh" --check "$ROOT" 2>&1) || licence_failure="$out"
if ! meta=$(python3 "$HERE/lib/packaging.py" "$ROOT" metadata); then
    fail "published crates are missing metadata" "$meta"
fi
if ! set=$(python3 "$HERE/lib/packaging.py" "$ROOT" set); then
    fail "a published crate depends on what cannot be published" "$set"
fi
args=()
while IFS= read -r crate; do args+=(-p "$crate"); done <<<"$set"

if [[ "$VERB" == "verify" ]]; then
    if ! out=$(cargo package --offline --allow-dirty "${args[@]}" 2>&1); then
        fail "a published crate does not build from its package" "$(tail -40 <<<"$out")"
    fi
    echo "packaging (verified): ok. every published crate builds from its .crate, offline"
    exit 0
fi

if ! out=$(cargo package --no-verify --offline --allow-dirty "${args[@]}" 2>&1); then
    fail "cargo package refuses the published set" "$(grep -v '^warning: ignoring test' <<<"$out" | tail -30)"
fi

info=$(cargo metadata --no-deps --format-version 1 --offline | python3 -c '
import json, sys
m = json.load(sys.stdin)
print(m["target_directory"])
for p in m["packages"]:
    print(p["name"], p["version"], p.get("repository") or "")
')
target=$(head -1 <<<"$info")
problems=()
sizes=()
placeholder=0
while IFS= read -r crate; do
    read -r _ version repo < <(grep "^$crate " <<<"$info")
    [[ "$repo" == "TBD" ]] && placeholder=1
    archive="$target/package/$crate-$version.crate"
    [[ -f "$archive" ]] || { problems+=("$crate-$version.crate was not written"); continue; }
    files=$(tar -tzf "$archive")
    for need in LICENSE-MIT README.md Cargo.toml; do
        grep -qx "$crate-$version/$need" <<<"$files" || problems+=("$crate-$version.crate lacks $need")
    done
    if grep -q "^$crate-$version/tests/" <<<"$files"; then
        problems+=("$crate-$version.crate packages tests/, which read the repository")
    fi
    sizes+=("$crate ($(wc -l <<<"$files" | tr -d ' ') files)")
done <<<"$set"

if [[ -n "${licence_failure:-}" ]]; then
    problems=("licence copies: $licence_failure" "${problems[@]+"${problems[@]}"}")
fi
if (( ${#problems[@]} > 0 )); then
    fail "a package is incomplete" "$(printf '%s\n' "${problems[@]}")"
fi

note=""
(( placeholder )) && note="; repository is still the TBD placeholder, so crates.io would refuse a publish"
echo "packaging: ok. ${#sizes[@]} published crates package offline with the licence and a README, no tests: $(IFS=,; echo "${sizes[*]}" | sed 's/,/, /g')$note"
