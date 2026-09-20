#!/usr/bin/env bash
#
# The galata-vault Python package, end to end: build the wheel with maturin,
# install it into fresh virtual environments (the oldest and newest
# supported CPython), start `gv-server local`, and run the pytest suite
# against it, using the wheel's own `gv` command for setup.
#
#   scripts/python-suite.sh [root]
#
# Skips (exit 0) when maturin or uv is missing, unless GV_REQUIRE_PYTHON=1
# (CI sets it). GV_PYTHONS overrides the interpreters (default "3.11 3.14").

set -euo pipefail

ROOT="${1:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)}"
PYTHONS="${GV_PYTHONS:-3.11 3.14}"

for tool in maturin uv; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        if [[ "${GV_REQUIRE_PYTHON:-}" == 1 ]]; then
            echo "python: $tool is required (GV_REQUIRE_PYTHON=1)" >&2
            exit 1
        fi
        echo "python: skipped ($tool not installed)"
        exit 0
    fi
done

cd "$ROOT"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/gv-python.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT

if ! out="$(cargo build -q -p galata-vault-server 2>&1)"; then
    echo "python: FAILED building gv-server" >&2
    echo "$out" | tail -20 >&2
    exit 1
fi
if ! out="$(maturin build --release -m crates/gv-py/Cargo.toml -o "$WORK/wheels" 2>&1)"; then
    echo "python: FAILED building the wheel" >&2
    echo "$out" | tail -30 >&2
    exit 1
fi
WHEEL="$(ls "$WORK"/wheels/*.whl)"

for py in $PYTHONS; do
    venv="$WORK/venv-$py"
    uv venv -q --python "$py" "$venv"
    uv pip install -q --python "$venv/bin/python" "$WHEEL" pytest
    if out="$(GV_SERVER_BIN="$ROOT/target/debug/gv-server" PATH="$venv/bin:$PATH" \
        "$venv/bin/python" -m pytest -q -p no:cacheprovider crates/gv-py/tests 2>&1)"; then
        echo "python $py: ok ($(echo "$out" | tail -1))"
    else
        echo "python $py: FAILED" >&2
        echo "$out" | tail -40 >&2
        exit 1
    fi
done
