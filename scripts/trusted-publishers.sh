#!/usr/bin/env bash
#
# Register this repository as the trusted publisher of every published crate,
# on crates.io, in one pass instead of ten trips through the web UI.
#
# A trusted publisher is a crates.io-side statement that "this crate may be
# published by this workflow, in this repository, running in this
# environment", and nothing else. The upload then authenticates as the
# workflow itself through OIDC (`.github/workflows/crates.yml`), so no token
# is stored anywhere (RELEASING.md).
#
# The crate list comes from the workspace, so a new published crate is
# registered by rerunning this, not by editing a list here.
#
#   scripts/trusted-publishers.sh                      # what it would do
#   CRATES_IO_TOKEN=cio... scripts/trusted-publishers.sh --apply
#   CRATES_IO_TOKEN=cio... scripts/trusted-publishers.sh --list
#
# The token is a crates.io API token (https://crates.io/settings/tokens)
# used once, from a laptop, and revoked afterwards -- it is not the
# publishing credential and belongs in no secret. The web UI does the same
# thing, one crate at a time, at
# https://crates.io/crates/<crate>/settings/trusted-publishing.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

WORKFLOW="crates.yml"
ENVIRONMENT="release"
API="https://crates.io/api/v1/trusted_publishing/github_configs"

MODE=plan
case "${1:-}" in
    --apply) MODE=apply ;;
    --list) MODE=list ;;
    "") ;;
    *) echo "trusted-publishers: unknown option $1" >&2; exit 2 ;;
esac

# The repository the tag will be pushed to, from the remote rather than from
# a string typed twice.
remote="$(git remote get-url origin)"
slug="$(sed -E 's#^.*github\.com[:/]##; s#\.git$##' <<<"$remote")"
OWNER="${slug%%/*}"
REPO="${slug##*/}"

# Every workspace member that is actually published.
# bash 3.2 is what macOS ships: no mapfile.
CRATES=()
while IFS= read -r crate; do
    CRATES+=("$crate")
done < <(cargo metadata --no-deps --format-version 1 | python3 -c '
import json, sys
meta = json.load(sys.stdin)
for p in sorted(meta["packages"], key=lambda p: p["name"]):
    if p.get("publish") != []:
        print(p["name"])
')
(( ${#CRATES[@]} > 0 )) || { echo "trusted-publishers: no publishable crates found" >&2; exit 1; }

echo "repository:  $OWNER/$REPO"
echo "workflow:    $WORKFLOW"
echo "environment: $ENVIRONMENT"
echo "crates:      ${#CRATES[@]}"

if [[ "$MODE" == plan ]]; then
    printf '  %s\n' "${CRATES[@]}"
    cat <<'PLAN'

Nothing was sent. To register them:

  CRATES_IO_TOKEN=<a crates.io API token> scripts/trusted-publishers.sh --apply

then revoke the token, and delete the CARGO_REGISTRY_TOKEN repository secret.
PLAN
    exit 0
fi

: "${CRATES_IO_TOKEN:?set CRATES_IO_TOKEN to a crates.io API token}"
UA="$OWNER (galata-vault trusted publisher setup)"

if [[ "$MODE" == list ]]; then
    curl -sS -H "Authorization: $CRATES_IO_TOKEN" -A "$UA" "$API" \
        | python3 -c '
import json, sys
for c in json.load(sys.stdin).get("github_configs", []):
    env = c.get("environment") or "-"
    print(f"  {c[\"crate\"]}: {c[\"repository_owner\"]}/{c[\"repository_name\"]} {c[\"workflow_filename\"]} env={env} (id {c[\"id\"]})")
'
    exit 0
fi

failed=0
for crate in "${CRATES[@]}"; do
    body=$(python3 -c '
import json, sys
crate, owner, repo, workflow, environment = sys.argv[1:]
print(json.dumps({"github_config": {
    "crate": crate,
    "repository_owner": owner,
    "repository_name": repo,
    "workflow_filename": workflow,
    "environment": environment,
}}))
' "$crate" "$OWNER" "$REPO" "$WORKFLOW" "$ENVIRONMENT")

    response=$(curl -sS -o /dev/null -w '%{http_code}' -X POST "$API" \
        -H "Authorization: $CRATES_IO_TOKEN" \
        -H "Content-Type: application/json" \
        -A "$UA" \
        -d "$body" 2>&1) || response="000"

    case "$response" in
        200|201) echo "  $crate: registered" ;;
        409) echo "  $crate: already registered" ;;
        *)
            # Print what crates.io said, which is where the reason is.
            echo "  $crate: FAILED (HTTP $response)" >&2
            curl -sS -X POST "$API" \
                -H "Authorization: $CRATES_IO_TOKEN" \
                -H "Content-Type: application/json" \
                -A "$UA" -d "$body" 2>&1 | sed 's/^/    /' >&2
            failed=1
            ;;
    esac
done

if (( failed )); then
    echo "trusted-publishers: some crates were not registered" >&2
    exit 1
fi

cat <<'DONE'

Registered. Now, on crates.io:
  - check each crate's Settings -> Trusted Publishing page shows the entry;
  - revoke the API token you just used;
  - delete the CARGO_REGISTRY_TOKEN secret from the repository (nothing
    reads it any more: gh secret delete CARGO_REGISTRY_TOKEN).
DONE
