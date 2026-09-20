#!/usr/bin/env bash
#
# Every guard, proved able to fail.
#
# A guard that has only ever passed is evidence of nothing. So every guard
# answers three verbs, and this runs all of them:
#
#   check   <root>    exit 0 clean, exit 1 on a violation
#   plant   <root>    create exactly one violation of THIS guard
#   targets <root>    print every path the guard depends on
#
# and a guard may answer two more:
#
#   expect  <root>    print what its planted failure must name, one per line
#   plants  <root>    print the names of several plants, one per line; then
#                     `plant` and `expect` read the one to use from
#                     GV_GUARD_PLANT. A guard that does not answer (any
#                     failure or empty output) has one plant.
#
# Each guard is checked on its own fresh copies of the tree: clean (must
# pass), then once per plant (each must fail). Plants only ever touch a copy
# under this harness's scratch root, never the real tree.
#
# The guard set is discovered, never listed: a `scripts/check-*.sh` that exists
# is a guard that runs.
#
# Usage: test-guards.sh [root]

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
SCRATCH="$(mktemp -d "${TMPDIR:-/tmp}/gv-guards-XXXXXX")"
trap 'rm -rf "$SCRATCH"' EXIT

failures=()

copy_tree() {
    local dest="$1"
    mkdir -p "$dest"
    tar -cf - -C "$ROOT" --exclude=./target --exclude=./.git . | tar -xf - -C "$dest"
}

# A plant mutates a tree by definition, so it runs only on a directory that
# is under SCRATCH, is not a symlink, and actually holds a workspace.
safe_to_plant() {
    local tree="$1"
    [[ -L "$tree" ]] && return 1
    case "$tree" in "$SCRATCH"/*) ;; *) return 1 ;; esac
    [[ -f "$tree/Cargo.toml" && -d "$tree/crates" ]]
}

guards=0
planted_count=0
for guard in "$ROOT"/scripts/check-*.sh; do
    [[ -e "$guard" ]] || continue
    name="$(basename "$guard" .sh)"
    [[ "$name" == "check-all" ]] && continue
    guards=$((guards + 1))

    # Every path the guard names must exist, or it is guarding a ghost.
    while IFS= read -r target; do
        [[ -e "$ROOT/$target" ]] || failures+=("$name: target $target does not exist")
    done < <("$guard" targets "$ROOT")

    clean="$SCRATCH/$name-clean"
    copy_tree "$clean"
    if ! "$guard" check "$clean" >/dev/null 2>&1; then
        failures+=("$name: fails on a clean copy of the tree")
    fi

    plants=$("$guard" plants "$ROOT" 2>/dev/null) || plants=""
    [[ -n "$plants" ]] || plants="default"
    for plant in $plants; do
        label="$name"
        [[ "$plant" == default ]] || label="$name ($plant)"
        planted="$SCRATCH/$name-planted-$plant"
        copy_tree "$planted"
        if ! safe_to_plant "$planted"; then
            failures+=("$label: refused to plant into $planted")
            continue
        fi
        planted_count=$((planted_count + 1))
        GV_GUARD_PLANT="$plant" "$guard" plant "$planted" >/dev/null 2>&1
        if out=$("$guard" check "$planted" 2>&1); then
            failures+=("$label: PASSES with its own violation planted; it cannot fail")
        elif expected=$(GV_GUARD_PLANT="$plant" "$guard" expect "$ROOT" 2>/dev/null); then
            # Failing is not enough: it must fail for the planted reason.
            while IFS= read -r needle; do
                [[ -n "$needle" ]] || continue
                grep -qF -- "$needle" <<<"$out" \
                    || failures+=("$label: its planted failure does not name \"$needle\"")
            done <<<"$expected"
        fi
    done
done

if (( guards == 0 )); then
    echo "guards: no scripts/check-*.sh found; refusing to report an empty suite as ok" >&2
    exit 1
fi

if (( ${#failures[@]} > 0 )); then
    echo "guards: FAILED" >&2
    printf '  %s\n' "${failures[@]}" >&2
    exit 1
fi

echo "guards: ok. $guards guard(s) and $planted_count plant(s): each guard passes clean and fails with each of its violations planted"
