"""One module per construct; each writes `testdata/vectors/v1/<name>.json`."""

from . import (
    audit, bundles, children, descriptors, envelopes, keys, kits, names, paths, pow,
    records, signatures, strings,
)

# (construct, the spec section the file covers, generator)
ALL = [
    ("strings", "formats.md#2", strings.build),
    ("paths", "formats.md#3", paths.build),
    ("keys", "keys.md#4", keys.build),
    ("names", "keys.md#8", names.build),
    ("descriptors", "records.md#1", descriptors.build),
    ("bundles", "records.md#2", bundles.build),
    ("envelopes", "records.md#3", envelopes.build),
    ("records", "records.md#4", records.build),
    ("children", "records.md#5", children.build),
    ("kits", "records.md#6", kits.build),
    ("signatures", "signatures.md#1", signatures.build),
    ("audit", "audit.md#2", audit.build),
    ("pow", "hosted.md#2", pow.build),
]
