# Releasing galata-vault

A release is one command and one push:

```sh
scripts/release.sh 0.2.0                    # bump, changelog, gate, commit, tag
git push origin HEAD && git push origin v0.2.0
```

The tag is the decision. Nothing after it is approved or clicked.

## What the tag starts

| What | Where | Built and published by |
|---|---|---|
| `galata-vault` and the nine `galata-vault-*` crates, one shared version | crates.io | `cargo publish --workspace` (`.github/workflows/crates.yml`) |
| `gv`, `gv-server`, `gv-mcp` binaries and installers | the GitHub release | dist (`dist-workspace.toml`, `.github/workflows/release.yml`) |
| The `galata-vault` Python package (wheels and sdist) | PyPI | maturin (`.github/workflows/wheels.yml`) |

The three run in parallel off the same `v<version>` tag, and each one checks
that the tag and the tree name the same version before it uploads anything
(`scripts/check-version.sh`, which CI runs on every push too).

`gv-py`, `gv-adversary` and `gv-conformance` are `publish = false` and never
reach crates.io. Cargo works out the order of the rest itself and waits for
each crate to appear in the index, so no dependency list is maintained by
hand anywhere.

## Credentials

| Name | Kind | Used by |
|---|---|---|
| crates.io trusted publisher | per crate: this repository, `crates.yml`, environment `release` | the crates.io upload |
| PyPI trusted publisher | project `galata-vault`: this repository, `wheels.yml`, environment `pypi` | the PyPI upload |
| `HOMEBREW_TAP_TOKEN` | secret: fine-grained token, contents: write on the tap repository only | dist's Homebrew job -- only if the tap comes back (`dist-workspace.toml`) |

**No release token is stored.** Both uploads authenticate as the workflow
itself, through OIDC, and both are bound to a named workflow file and a named
environment: a credential that leaks out of a different workflow does not
exist to leak. The `release` and `pypi` environments restrict deployments to
`v*` tags, which is what makes pushing the tag the gate.

`CARGO_REGISTRY_TOKEN` carried the 0.1.0 publish, because trusted publishing
cannot create a crate that does not exist yet. Every name exists now, so the
publisher takes over and the secret goes.

### Registering the trusted publishers

Ten crates means ten configurations. `scripts/trusted-publishers.sh` makes
them all from the workspace, so a new published crate is registered by
rerunning it:

```sh
scripts/trusted-publishers.sh                       # what it would register
CRATES_IO_TOKEN=cio... scripts/trusted-publishers.sh --apply
CRATES_IO_TOKEN=cio... scripts/trusted-publishers.sh --list
```

That token is a crates.io API token used once from a laptop and revoked
afterwards; it is not the publishing credential and belongs in no secret.
The web UI does the same thing one crate at a time, under **Settings ->
Trusted Publishing** on each crate, which is also where the entries are
checked and removed:

| Field | Value |
|---|---|
| Repository owner | `sercanatalik` |
| Repository name | `galata-vault` |
| Workflow filename | `crates.yml` |
| Environment | `release` |

All four must match what the workflow actually is, and the environment is
the part that is easy to leave blank: an empty environment would let any
`v*` tag run of `crates.yml` publish, which is exactly the binding being
bought here. Afterwards, delete the now-unused secret:
`gh secret delete CARGO_REGISTRY_TOKEN`.

## What `scripts/release.sh` does

1. Refuses a dirty tree, and a tag that exists here or on the remote.
2. Sets `[workspace.package] version` and every workspace path dependency.
3. Turns `## [Unreleased]` in `CHANGELOG.md` into today's entry, and writes
   its link definitions. An entry already written by hand for that version is
   kept and dated.
4. `cargo update --workspace`, so `Cargo.lock` names the new version.
5. `scripts/check-version.sh`, then `scripts/check-all.sh` -- the gate CI
   runs. `--no-verify` skips the second one; nothing else does.
6. `git commit -s` and an annotated tag. It never pushes.

Between releases the tree carries the version that was last released, and
notes accumulate under `## [Unreleased]`. Nothing is pre-bumped; the version
and the changelog move together, in the release commit, and
`scripts/check-version.sh` fails the build if they ever do not.

Raising the MSRV is a minor release and gets a changelog line. In 0.x, a
`0.y` bump is breaking and a `0.y.z` bump is not; CI's `semver` job
(cargo-semver-checks) fails a pull request that breaks a published API
without one.

## When a release goes wrong

Each of the three uploads is independent, and each refuses to overwrite, so
recovery is always "rerun the part that failed".

- **crates.io:** rerun the failed `crates` run. Cargo refuses a version that
  is already there, so the crates that landed stay landed; if a *later* crate
  in the set is broken, fix it, release the next patch version, and leave the
  half-published one alone. Never yank to "retry": a published version stays
  published.
- **dist:** rerun the failed jobs of `release.yml` for the tag. To rebuild
  from scratch, delete the GitHub release (not the tag) and rerun.
- **PyPI:** rerun `wheels` by hand with `publish` set. A file already on PyPI
  is refused; nothing is overwritten.

A release that is broken or insecure is **yanked, never deleted**, and the
fix ships as a new patch release: `cargo yank --version <v> <crate>` for
every crate in the set, yank the PyPI release with a reason, and mark the
GitHub release as not the latest, saying why in its notes. A security fix
also gets a GitHub security advisory and a RustSec entry (`SECURITY.md`).

## Verifying a release

- `gh attestation verify <binary> --repo sercanatalik/galata-vault` for each
  binary (dist attests every artifact);
- `cargo audit bin <binary>` lists the dependencies compiled into it
  (`cargo-auditable`);
- every install line in the README works on a clean machine.

## Still to do

- **Homebrew.** The tap does not exist and no README offers `brew install`.
  To add it: create `sercanatalik/homebrew-tap` and its `HOMEBREW_TAP_TOKEN`,
  restore the three lines `dist-workspace.toml` names, regenerate
  `release.yml` with `dist generate`, and put the install lines back.
- **The response time in `SECURITY.md`.**
- `.github/workflows/release.yml` is generated: after changing
  `dist-workspace.toml`, run `dist generate` and commit the result. Its
  `plan` step fails when the two disagree.

## 1.0

1.0 waits for three things: the external review published under `audit/`
with every high-severity finding fixed, the format declared frozen in
`docs/spec/`, and OpenSSF Best Practices "passing".
