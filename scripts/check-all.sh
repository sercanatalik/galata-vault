#!/usr/bin/env bash
#
# Everything, in one command. What CI runs.
#
# Structural guards first (they answer before a compile starts), then format,
# lints and tests, then the guard self-test. `cargo deny` is deliberately not
# here: it needs a network for the advisory database, so it runs as its own
# CI job (see deny.toml).

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
failed=0

# Discovered, never listed: a guard file that exists runs.
for check in "$ROOT"/scripts/check-*.sh; do
    [[ -e "$check" ]] || continue
    case "$check" in */check-all.sh) continue ;; esac
    if ! "$check" "$ROOT"; then
        failed=$((failed + 1))
    fi
done

run() {
    local label="$1"; shift
    local out
    if out=$("$@" 2>&1); then
        echo "$label: ok"
    else
        echo "$label: FAILED" >&2
        echo "$out" | tail -40 >&2
        failed=$((failed + 1))
    fi
}

run "format" cargo fmt --all --check
# Default features (galata-vault-cli without `ui`, as an embedding binary builds it),
# then everything on (`ui`, `test-util`, `platform-verifier`).
run "lints" cargo clippy --workspace --all-targets -- -D warnings
run "lints (all features)" cargo clippy --workspace --all-targets --all-features -- -D warnings
# One server build, and the SDK with its in-process backend, which must also
# build without HTTP. The linkage guards above check each graph.
run "lints (galata-vault, embedded)" \
    cargo clippy -p galata-vault --all-targets --features embedded -- -D warnings
run "build (galata-vault, embedded without http)" \
    cargo build -p galata-vault --no-default-features --features embedded
# gv-py is a Python extension: it links against Python only when maturin
# builds the wheel, so its tests are the pytest suite (scripts/python-suite.sh).
# `ui` is off by default in galata-vault-cli; every
# gv we release enables it, so the suite does too. Its lib tests also run
# without it, where `gv ui` must refuse by naming the feature.
run "tests" cargo test --workspace --exclude gv-py --features galata-vault-cli/ui
run "tests (galata-vault-cli without ui)" cargo test -p galata-vault-cli --lib
# The embedded backend (the conformance list over both transports) runs only
# with its feature.
run "tests (galata-vault, embedded)" cargo test -p galata-vault --features embedded
run "tests (gv-conformance, embedded target)" cargo test -p gv-conformance --features embedded
# The adversarial harness: a real server behind a proxy that
# forges, replays and rolls back. Also part of "tests"; named here so a
# regression shows up as what it is. The Python half runs in the suite below.
run "adversarial harness (malicious server vs the SDK, gv and gv-mcp)" \
    cargo test -p galata-vault -p galata-vault-cli -p galata-vault-mcp --test adversary
# The harness proved able to fail, as the guards are below: with the SDK's
# descriptor-signature check planted away (debug builds only), the
# key-substitution tests must fail, and a release build must refuse the plant.
run "adversarial plant (the suite fails with descriptor signatures unchecked)" \
    "$ROOT/scripts/adversary-plant.sh" "$ROOT"
run "guards" "$ROOT/scripts/test-guards.sh" "$ROOT"
# Every published crate built from its own .crate, offline, as `cargo
# publish` would (the packaging guard above checks the lists and licences
# without building). Then the documentation with rustdoc warnings denied:
# broken intra-doc links, and missing docs where a crate warns on them.
run "packaging (every published crate builds from its package, offline)" \
    "$ROOT/scripts/check-packaging.sh" verify "$ROOT"
run "docs (rustdoc warnings denied, every feature)" \
    env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features

# The specification against the code (docs/spec/README.md#7). The label and
# response-type guards ran first with the other check-*.sh; these are also
# part of "tests", named here so a drift shows up as what it is.
run "spec: error table (http-api.md#5.2) is ErrorCode; every vector anchor exists" \
    cargo test -p galata-vault-proto --test spec_tables
run "spec: endpoint table (http-api.md#2) is the route table" \
    cargo test -p galata-vault-server-core --test route_table
run "vectors: every construct in the Rust crates" \
    cargo test -p galata-vault-proto -p galata-vault-keys -p galata-vault-seal -p galata-vault --test vectors
# The committed vectors against the independent generator (and its age
# against C2SP CCTV). Without uv it prints SKIPPED; CI requires it.
if ! "$ROOT/scripts/vectors.sh" "$ROOT"; then
    failed=$((failed + 1))
fi
# The conformance suite against a real `gv-server local` on an ephemeral
# loopback port, and against the embedded backend.
run "conformance (gv-server local over HTTP, then embedded)" "$ROOT/scripts/conformance.sh" "$ROOT"
# galata-vault-proto's public API against semver. Advisory until the first release gives
# it a baseline; CI installs and runs it. Not installed globally here.
if command -v cargo-semver-checks >/dev/null 2>&1; then
    if cargo semver-checks -p galata-vault-proto --baseline-rev HEAD >/dev/null 2>&1; then
        echo "semver (galata-vault-proto, advisory): ok"
    else
        echo "semver (galata-vault-proto, advisory): breaking changes against HEAD; see cargo semver-checks -p galata-vault-proto"
    fi
else
    echo "semver (galata-vault-proto, advisory): SKIPPED, cargo-semver-checks not installed; CI runs it"
fi

# The Python package end to end; it skips itself without maturin and uv. Its
# adversarial tests drive the gv-adversary binary.
run "adversary binary" cargo build -q -p gv-adversary
export GV_ADVERSARY_BIN="$ROOT/target/debug/gv-adversary"
if ! "$ROOT/scripts/python-suite.sh" "$ROOT"; then
    failed=$((failed + 1))
fi

if (( failed > 0 )); then
    echo "$failed check(s) failed" >&2
    exit 1
fi
echo "all checks passed"
