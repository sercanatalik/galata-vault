#!/usr/bin/env bash
#
# The conformance suite (docs/spec/README.md#6) against both targets:
#
#   1. a real `gv-server local` on an ephemeral loopback port, over HTTP;
#   2. the SDK's embedded backend (`galata_vault::embedded::open(dir)`).
#
# Each gets a fresh temporary data directory, removed at the end. One line
# per case from gv-conformance, then one line per target here; exit 1 if
# either target fails a case.
#
# Usage: conformance.sh [root]

set -uo pipefail

ROOT="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
cd "$ROOT"

# The embedded target is gv-conformance's opt-in `embedded` feature.
if ! out=$(cargo build -q -p galata-vault-server -p gv-conformance --features gv-conformance/embedded 2>&1); then
    echo "conformance: FAILED, the binaries do not build" >&2
    echo "$out" | tail -40 >&2
    exit 1
fi
BIN="$ROOT/target/debug"

work="$(mktemp -d "${TMPDIR:-/tmp}/gv-conformance.XXXXXX")"
server_pid=""
cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" 2>/dev/null
        wait "$server_pid" 2>/dev/null
    fi
    rm -rf "$work"
}
trap cleanup EXIT

failed=0

# 1. HTTP: a free port from the kernel, then the server on it.
port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')"
# Data directories must be 0700 (the server and the backend refuse otherwise).
mkdir -m 700 "$work/http"
"$BIN/gv-server" local --data-dir "$work/http" --port "$port" >"$work/server.log" 2>&1 &
server_pid=$!
url="http://127.0.0.1:$port"
up=0
for _ in $(seq 1 100); do
    if curl -s -m 1 -o /dev/null "$url/v1/capabilities" 2>/dev/null; then
        up=1
        break
    fi
    kill -0 "$server_pid" 2>/dev/null || break
    sleep 0.1
done
if (( up )); then
    if "$BIN/gv-conformance" --server "$url"; then
        echo "conformance (gv-server local, $url): ok"
    else
        echo "conformance (gv-server local, $url): FAILED" >&2
        failed=1
    fi
else
    echo "conformance (gv-server local): FAILED, the server did not start" >&2
    tail -20 "$work/server.log" >&2
    failed=1
fi

# 2. Embedded: the same cases in-process, without HTTP (C11 and C15 skip).
if "$BIN/gv-conformance" --embedded "$work/embedded"; then
    echo "conformance (embedded): ok"
else
    echo "conformance (embedded): FAILED" >&2
    failed=1
fi

exit "$failed"
