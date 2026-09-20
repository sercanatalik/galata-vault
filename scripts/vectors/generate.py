#!/usr/bin/env python3
"""Generate galata-vault's protocol test vectors, `testdata/vectors/v1/`,
from an independent Python implementation (`gvvectors`), which shares no code
with the Rust crates. See `docs/spec/README.md#5`.

    uv run --with cryptography --with pynacl scripts/vectors/generate.py          # write the files
    uv run --with cryptography --with pynacl scripts/vectors/generate.py --check  # regenerate and diff

Before generating anything it checks its age implementation against the
vendored C2SP CCTV vectors (`testdata/cctv/age/`), and stops if one disagrees.
`--check` writes nothing; it exits 1 if any committed file differs from what
it generates, naming the file.
"""

from __future__ import annotations

import argparse
import difflib
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

from gvvectors import cctv  # noqa: E402
from gvvectors.cases import VectorFile  # noqa: E402
from gvvectors.constructs import ALL  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true", help="regenerate and diff; write nothing")
    parser.add_argument("--out", type=pathlib.Path, default=ROOT / "testdata" / "vectors" / "v1")
    args = parser.parse_args()

    count, covered = cctv.run(ROOT / "testdata" / "cctv" / "age" / "testdata")
    outcomes = ", ".join(f"{k}: {v}" for k, v in sorted(covered.items()))
    print(f"cctv age: {count} vectors agree ({outcomes})")

    failed = False
    total = 0
    for construct, spec, build in ALL:
        f = VectorFile(construct, spec)
        build(f)
        text = f.render()
        total += len(f.cases)
        path = args.out / f"{construct}.json"
        if args.check:
            old = path.read_text() if path.exists() else ""
            if old != text:
                failed = True
                diff = difflib.unified_diff(old.splitlines(), text.splitlines(), str(path), "generated", lineterm="", n=1)
                print(f"vectors: {path.relative_to(ROOT)} differs from the generator's output:", file=sys.stderr)
                for line in list(diff)[:40]:
                    print("  " + line, file=sys.stderr)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    names = {p.stem for p in args.out.glob("*.json")}
    stray = names - {c for c, _, _ in ALL}
    if stray:
        failed = True
        print(f"vectors: files no generator writes: {sorted(stray)}", file=sys.stderr)
    if failed:
        return 1
    verb = "match the generator" if args.check else "written"
    print(f"vectors: {len(ALL)} files, {total} cases {verb}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
