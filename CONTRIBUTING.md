# Contributing to galata-vault

Thank you for helping. galata-vault is a library first: an end-to-end-encrypted
secrets SDK (`galata-vault`), the `gv` command line built on it, a server that
cannot read what it stores, and a Python package. Its promises are specified
in [`docs/spec/`](docs/spec/README.md) and [`docs/threat-model.md`](docs/threat-model.md),
and [`ARCHITECTURE.md`](ARCHITECTURE.md) maps the crates.

**Security issues are not contributions: never open a public issue or pull
request for one.** Follow [SECURITY.md](SECURITY.md).

## Terms: the Developer Certificate of Origin

Contributions are accepted under the [Developer Certificate of Origin
1.1](https://developercertificate.org/) (DCO). There is no contributor
licence agreement. By signing off a commit you certify the DCO for it: that
you wrote the change, or otherwise have the right to submit it under the
project's licence.

Sign off every commit with `git commit -s`, which adds a line with your name
and email:

```text
Signed-off-by: Your Name <you@example.com>
```

Use a name and address you are happy to publish; they become part of the
public history. A CI check (`.github/workflows/dco.yml`) refuses a pull
request containing a commit without a `Signed-off-by` line, and names the
commit. To fix one, `git commit --amend -s`, or `git rebase --signoff` for a
series, and force-push the branch.

Contributions are inbound = outbound: unless you say otherwise in the pull
request, what you submit is licensed under the project's terms, MIT (see
[LICENSE-MIT](LICENSE-MIT)), with no additional terms or conditions.
The project will not relicense to a more restrictive licence; that is why it
asks for a DCO and not a CLA.

If an AI assistant helped write a change, say so in the pull request. You are
still the one certifying the DCO, and you are expected to understand and
stand behind every line.

## Before you open a pull request

One command runs what CI runs:

```sh
scripts/check-all.sh
```

It runs, in order:
- every structural guard in `scripts/check-*.sh` (the linkage guards that
  keep decryption code out of the server and the MCP server and host-process
  code out of the SDK, the packaging guard, the spec label registry, the
  response types), each also proved able to fail by `scripts/test-guards.sh`;
- `cargo fmt --check`, clippy with `-D warnings` for every feature set, and
  every test;
- the adversarial suite against a malicious server, and its plant self-test;
- the spec tables, the protocol vectors (Rust, and the independent Python
  generator), and the conformance suite;
- the Python package end to end.

Without `uv` or `maturin`, the checks that need them print `SKIPPED`, which
is never a pass; CI has both. Run `cargo fmt --all`
before committing.

Keep a pull request to one change. Say what it changes and why; link the
issue it closes. User-visible
changes get a line under `Unreleased` in [CHANGELOG.md](CHANGELOG.md).

## Changing a format starts in the spec

Formats (strings, framing, descriptors, records, bundles, kits, the audit
chain, the HTTP API) are specified in [`docs/spec/`](docs/spec/README.md).
Code follows the spec, never the other way round:

1. Change the specification first, in the same pull request or one before
   it. A new format gets a new version string; an existing one never changes
   silently ([`docs/spec/stability.md`](docs/spec/stability.md)).
2. Regenerate the test vectors with the independent Python generator
   (`uv run --with cryptography --with pynacl scripts/vectors/generate.py`),
   which shares no code with the Rust crates. Never edit a vector file by
   hand.
3. Change the Rust code until `scripts/check-all.sh` passes: the vector
   tests, the spec tables, the label registry guard and the conformance
   suite all read the spec or the vectors.

Data written in a format version stays readable by every later release of
the same major version. A change that would break that is a new format.

## Crate boundaries are the security design

Some crates must never link some code, and the guards fail the build if
they do: the server crates link no decryption, the MCP server links no value
crypto, the client transport links neither value crypto nor host-process
code, and the SDK links no keychain, prompt, CLI or Python code. If a change
needs to cross one of those lines, open an
[issue](https://github.com/sercanatalik/galata-vault/issues) to discuss it
first.

## Code of conduct

Everyone taking part is expected to follow the
[Code of Conduct](CODE_OF_CONDUCT.md).
