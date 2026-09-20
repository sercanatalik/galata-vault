#!/usr/bin/env bash
#
# The adversarial suite, proved able to fail.
#
# A suite that has only ever passed is evidence of nothing, so this removes
# one key-substitution check from the SDK and requires the suite to catch it.
# The plant: galata-vault's `adversary-plant` feature, run with
# GV_ADVERSARY_PLANT=skip-descriptor-signature, accepts a generation
# descriptor without verifying the owner's signature over it (`plant` in
# crates/galata-vault/src/vault.rs). A public key the server substitutes in
# the descriptor is then no longer refused.
#
# In order:
#   1. nothing in the workspace enables the feature; only galata-vault
#      defines it;
#   2. a release build (no debug assertions) with the feature does not
#      compile, and says why;
#   3. with the feature but without the variable, the key-substitution tests
#      pass: the feature alone changes nothing;
#   4. with the variable, the SDK's adversarial tests FAIL, and the failures
#      include every key-substitution test named below.
#
# Usage: adversary-plant.sh [root]

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
cd "$ROOT"

FEATURE="adversary-plant"
VAR="GV_ADVERSARY_PLANT"
PLANT="skip-descriptor-signature"
# The tests that exist to catch a substituted key. Each must fail planted.
MUST_FAIL=(
    a_substituted_vault_or_config_key_is_refused
    an_append_token_never_encrypts_to_a_substituted_key
)
TEST=(cargo test -q -p galata-vault --features "$FEATURE" --test adversary)

fail() {
    echo "adversary plant: FAILED, $*" >&2
    exit 1
}

# 1. Only galata-vault's own [features] table may name it.
while IFS= read -r manifest; do
    [[ "$manifest" == "./crates/galata-vault/Cargo.toml" ]] && continue
    fail "$manifest names the \`$FEATURE\` feature; nothing may enable it"
# Manifests in the tree only: not target/ (cargo package unpacks published
# crates, the SDK's own manifest among them, under target/package/) and not
# .git/.
done < <(find . \( -path ./target -o -path ./.git \) -prune -o -name Cargo.toml -print 2>/dev/null \
    | xargs grep -l -- "$FEATURE" 2>/dev/null)
defined=$(grep -c -- "^$FEATURE = \[\]" crates/galata-vault/Cargo.toml || true)
[[ "$defined" == "1" ]] || fail "crates/galata-vault/Cargo.toml must define \`$FEATURE = []\` exactly once"
if grep -q -- "default = \[.*$FEATURE" crates/galata-vault/Cargo.toml; then
    fail "\`$FEATURE\` is a default feature"
fi

# 2. A release build refuses it.
if out=$(cargo check -q --release -p galata-vault --features "$FEATURE" 2>&1); then
    fail "a release build with \`$FEATURE\` compiles; it must not"
fi
grep -q "cannot be built without debug assertions" <<<"$out" \
    || fail "the release build failed, but not with the plant's compile_error: $(tail -5 <<<"$out")"

# 3. The feature alone changes nothing.
for t in "${MUST_FAIL[@]}"; do
    if ! out=$(env -u "$VAR" "${TEST[@]}" -- --exact "$t" 2>&1); then
        fail "$t fails with the feature built in but not planted: $(tail -20 <<<"$out")"
    fi
    grep -q "1 passed" <<<"$out" || fail "$t did not run (renamed?); update MUST_FAIL"
done

# 4. Planted, the suite fails, and for the planted reason.
if out=$(env "$VAR=$PLANT" "${TEST[@]}" 2>&1); then
    fail "the adversarial suite PASSES with descriptor signatures unchecked; it cannot catch a substituted key"
fi
failed_tests=$(sed -n '/^failures:$/,/^test result/p' <<<"$out" | grep -E '^    [a-z_0-9]+$' | sed 's/^ *//' | sort -u)
[[ -n "$failed_tests" ]] || fail "the planted run failed without a test failing: $(tail -20 <<<"$out")"
for t in "${MUST_FAIL[@]}"; do
    grep -qx -- "$t" <<<"$failed_tests" || fail "planted, $t still passes"
done

echo "adversary plant: ok. descriptor signatures unchecked, the suite fails ($(wc -l <<<"$failed_tests" | tr -d ' ') test(s): $(tr '\n' ' ' <<<"$failed_tests"| sed 's/ $//')); a release build refuses the feature"
