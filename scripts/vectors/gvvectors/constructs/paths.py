"""Paths (formats.md#3)."""

SPEC = "formats.md#3"


def build(f):
    good = ["acme", "acme/prod", "acme/prod/eu", "a/b/c/d", "0x/9-a", "acme/staging-2", "p/" + "a" * 63]
    for path in good:
        segs = path.split("/")
        f.add("parse", SPEC, f"{path[:40]!r} is a path", {"path": path},
              outputs={"segments": segs, "depth": len(segs), "project": segs[0]})
    bad = [
        ("", "an empty path"),
        ("acme/", "a trailing slash"),
        ("/acme", "a leading slash"),
        ("acme//prod", "an empty segment"),
        ("acme/Prod", "an upper-case letter"),
        ("acme/prod_eu", "an underscore"),
        ("acme/-prod", "a segment starting with '-'"),
        ("acme/pr od", "a space"),
        ("acme/prød", "a non-ASCII letter"),
        ("p/" + "a" * 64, "a 64-character segment"),
        ("a/b/c/d/e", "five segments"),
    ]
    for path, why in bad:
        f.add("parse", SPEC, f"refused: {why}", {"path": path}, "bad_path")
