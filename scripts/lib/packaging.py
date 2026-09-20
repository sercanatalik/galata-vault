#!/usr/bin/env python3
"""Shared engine for the packaging checks: scripts/check-packaging.sh (the
whole published set) and the publish half of scripts/check-sdk-linkage.sh
(the SDK and what it depends on). Offline: it reads `cargo metadata
--no-deps`, never a registry.

Usage:
  packaging.py <root> set              check every published crate's workspace
                                       dependencies, then print the set
  packaging.py <root> closure <crate>  check <crate> is publishable, then print
                                       it and every workspace crate it reaches
                                       through normal, build or optional edges
  packaging.py <root> metadata         check each published crate's metadata

A crate is published unless its manifest says `publish = false`. The rules:
  - a normal or build dependency on a workspace crate names a version, and
    that crate is published (cargo would refuse either, and crates.io needs
    every such dependency on the registry);
  - a dev-dependency on an unpublished crate is path-only: cargo strips it
    from the package, and tests are not packaged anyway. A versioned one
    would stay in the packaged manifest and have to resolve on crates.io.
Failures are printed one per line, naming both crates; the exit code is 1.
"""

import json
import pathlib
import subprocess
import sys


def load(root):
    meta = json.loads(
        subprocess.run(
            ["cargo", "metadata", "--no-deps", "--format-version", "1", "--offline"],
            cwd=root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
    )
    members = set(meta["workspace_members"])
    return {p["name"]: p for p in meta["packages"] if p["id"] in members}


def published(p):
    return p["publish"] is None or "crates-io" in p["publish"]


def workspace_deps(p, ws, kinds):
    for d in p["dependencies"]:
        if d.get("path") and d["name"] in ws and d["kind"] in kinds:
            yield d


def dep_failures(p, ws):
    out = []
    for d in workspace_deps(p, ws, {None, "build"}):
        if d["req"] == "*":
            out.append(f"{p['name']} depends on {d['name']} by path with no version")
        if not published(ws[d["name"]]):
            out.append(f"{p['name']} depends on {d['name']}, which is publish = false")
    for d in workspace_deps(p, ws, {"dev"}):
        if d["req"] != "*" and not published(ws[d["name"]]):
            out.append(
                f"{p['name']} dev-depends on {d['name']} with a version, but {d['name']} is publish = false; "
                "keep that dev-dependency path-only so cargo strips it"
            )
    return out


def metadata_failures(p, ws_license):
    out = []
    name = p["name"]
    if not p.get("description"):
        out.append(f"{name} has no description")
    if p.get("license") != ws_license:
        out.append(f"{name} is licensed {p.get('license')!r}, not the workspace's {ws_license!r}")
    if not p.get("repository"):
        out.append(f"{name} has no repository (the workspace placeholder is enough until it is set)")
    readme = p.get("readme")
    manifest_dir = pathlib.Path(p["manifest_path"]).parent
    if not readme or not (manifest_dir / readme).is_file():
        out.append(f"{name} has no README file")
    if not p.get("keywords"):
        out.append(f"{name} has no keywords")
    if not p.get("categories"):
        out.append(f"{name} has no categories")
    docsrs = ((p.get("metadata") or {}).get("docs") or {}).get("rs") or {}
    if "docsrs" not in " ".join(docsrs.get("rustdoc-args", [])):
        out.append(f"{name} has no [package.metadata.docs.rs] with rustdoc-args --cfg docsrs")
    return out


def main():
    root, verb = sys.argv[1], sys.argv[2]
    ws = load(root)
    failures, names = [], []
    if verb == "set":
        for p in sorted(ws.values(), key=lambda p: p["name"]):
            if published(p):
                failures += dep_failures(p, ws)
                names.append(p["name"])
        if not names:
            failures.append("no published crate in the workspace; refusing to package nothing")
    elif verb == "closure":
        crate = sys.argv[3]
        if crate not in ws:
            failures.append(f"{crate} is not in the workspace")
        elif not published(ws[crate]):
            failures.append(f"{crate} is publish = false; it must stay publishable")
        else:
            seen, stack = [], [crate]
            while stack:
                n = stack.pop()
                if n in seen:
                    continue
                seen.append(n)
                failures += dep_failures(ws[n], ws)
                stack += [d["name"] for d in workspace_deps(ws[n], ws, {None, "build"})]
            names = seen
    elif verb == "metadata":
        # Every package, the server included, is MIT.
        ws_license = "MIT"
        for p in sorted(ws.values(), key=lambda p: p["name"]):
            if published(p):
                failures += metadata_failures(p, ws_license)
                names.append(p["name"])
    else:
        failures.append(f"unknown verb {verb}")
    if failures:
        print("\n".join(dict.fromkeys(failures)))
        return 1
    print("\n".join(names))
    return 0


if __name__ == "__main__":
    sys.exit(main())
