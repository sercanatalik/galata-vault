#!/usr/bin/env bash
#
# The licence text in every published package.
#
# A package carries only what its `include` list names, and nothing above
# its own directory, so each published crate keeps a copy of the root
# LICENSE-MIT beside its Cargo.toml. This copies it;
# with --check it changes nothing and fails if a copy is missing or differs
# from the root (scripts/check-packaging.sh runs the check, and also reads
# `cargo package --list` to see the text in every package).
#
# The published set is read from cargo, never listed: every workspace member
# without `publish = false`.
#
# Usage: sync-licenses.sh [--check] [root]

set -euo pipefail

CHECK=0
if [[ "${1:-}" == "--check" ]]; then
    CHECK=1
    shift
fi
ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
cd "$ROOT"

published=$(cargo metadata --no-deps --format-version 1 --offline 2>/dev/null | python3 -c '
import json, os, sys
meta = json.load(sys.stdin)
for p in meta["packages"]:
    if p["publish"] is None or p["publish"]:
        print(os.path.relpath(os.path.dirname(p["manifest_path"])))
')
[[ -n "$published" ]] || { echo "licences: no published package found; refusing to call that ok" >&2; exit 1; }

stale=()
while IFS= read -r dir; do
    for f in LICENSE-MIT; do
        if (( CHECK )); then
            cmp -s "$f" "$dir/$f" || stale+=("$dir/$f")
        else
            cp "$f" "$dir/$f"
        fi
    done
done <<<"$published"

if (( ${#stale[@]} > 0 )); then
    echo "licences: FAILED, missing or different from the root copy (run scripts/sync-licenses.sh):" >&2
    printf '  %s\n' "${stale[@]}" >&2
    exit 1
fi
count=$(wc -l <<<"$published" | tr -d ' ')
if (( CHECK )); then
    echo "licences: ok. $count published packages carry LICENSE-MIT identical to the root"
else
    echo "licences: copied into $count published packages"
fi
