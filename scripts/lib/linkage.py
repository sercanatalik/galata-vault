#!/usr/bin/env python3
"""Shared engine for the linkage guards.

Reads cargo's RESOLVED graph (`cargo metadata`), so a transitive edge fails
exactly like a direct one. Dev- and build-only edges are ignored: a test may
link client crypto to build real ciphertext, because tests are not the binary.

Usage: linkage.py <root> <table-json> [cargo-metadata-argument...]

Extra arguments go to `cargo metadata`: `--features galata-vault/embedded` checks
the graph the SDK's in-process backend resolves.

The table maps a crate name to:
  direct_ok   workspace crates it may depend on directly (list), or null for any
  forbidden   crate names that must not appear in its normal graph at any depth
"""

import json
import subprocess
import sys


def main() -> int:
    root, table, extra = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3:]
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--format-version", "1", *extra],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )

    by_id = {p["id"]: p for p in meta["packages"]}
    members = set(meta["workspace_members"])
    workspace = {by_id[i]["name"] for i in members}
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}

    def normal_deps(pid):
        for dep in nodes[pid]["deps"]:
            kinds = {k.get("kind") for k in dep.get("dep_kinds", [])}
            if kinds and kinds <= {"dev", "build"}:
                continue
            yield dep["pkg"]

    failures = []
    for crate, rule in table.items():
        root_id = next((i for i in members if by_id[i]["name"] == crate), None)
        if root_id is None:
            failures.append(f"{crate} is not in the workspace; the guard has nothing to hold")
            continue

        direct_ok = rule.get("direct_ok")
        if direct_ok is not None:
            direct = {by_id[d]["name"] for d in normal_deps(root_id)}
            for name in sorted(direct & workspace):
                if name not in direct_ok:
                    failures.append(
                        f"{crate} depends directly on {name}; its permitted set is {sorted(direct_ok)}"
                    )

        # Walk the graph, remembering one path to each crate so a failure
        # names the route rather than just the destination.
        parent = {root_id: None}
        stack = [root_id]
        while stack:
            pid = stack.pop()
            for d in normal_deps(pid):
                if d not in parent:
                    parent[d] = pid
                    stack.append(d)

        forbidden = set(rule.get("forbidden", []))
        for pid in parent:
            name = by_id[pid]["name"]
            if name in forbidden:
                path, cur = [], pid
                while cur is not None:
                    path.append(by_id[cur]["name"])
                    cur = parent[cur]
                failures.append(
                    f"{crate} reaches {name}, forbidden at any depth: {' -> '.join(reversed(path))}"
                )

    for f in failures:
        print(f)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
