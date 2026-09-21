# Releasing galata-vault

How a release is cut, how to recover when one goes wrong, and which
credentials exist. The repository is public; nothing here has run yet, and
the workflows below have never been exercised on a runner.

## What is released, and by what

| What | Where | Built and published by |
|---|---|---|
| `galata-vault` and the nine `galata-vault-*` crates, one shared version | crates.io | release-plz (`release-plz.toml`, `.github/workflows/release-plz.yml`) |
| `gv`, `gv-server`, `gv-mcp` binaries, installers, Homebrew formulae | GitHub release, the Homebrew tap | dist (`dist-workspace.toml`, `.github/workflows/release.yml`) |
| The `galata-vault` Python package (wheels and sdist) | PyPI | maturin (`.github/workflows/wheels.yml`) |

`gv-py`, `gv-adversary` and `gv-conformance` are `publish = false` and never
go to crates.io.

Every published crate shares the workspace version (`[workspace.package]
version`) and releases together. In 0.x, a `0.y` bump is breaking and a
`0.y.z` bump is not.

## Credentials and environments

| Name | Kind | Scope | Used by |
|---|---|---|---|
| `release` | GitHub environment, required reviewer: a maintainer | | `release-plz.yml` (`release` job) |
| `pypi` | GitHub environment, required reviewer: a maintainer | | `wheels.yml` (`publish` job) |
| `CARGO_REGISTRY_TOKEN` | secret: crates.io API token | publish | the `release` job, **today**. Trusted publishing cannot create a crate, so this stands in until every name exists |
| crates.io trusted publisher | per crate: this repository, `release-plz.yml`, environment `release` | publish | the `release` job **once the crates exist**, through `rust-lang/crates-io-auth-action`; delete the secret then |
| PyPI trusted publisher | project `galata-vault`: this repository, `wheels.yml`, environment `pypi` | upload | `publish` job |
| `RELEASE_PLZ_TOKEN` | secret: GitHub App or fine-grained token | contents and pull requests: write, this repository only | release-plz. The default `GITHUB_TOKEN` cannot be used: a tag it pushes starts no workflow |
| `HOMEBREW_TAP_TOKEN` | secret: fine-grained token | contents: write, the tap repository only | dist's `publish-homebrew-formula` job |

No PyPI token is stored: that upload is OIDC only, and its trusted publisher
names `wheels.yml` and the `pypi` environment.

crates.io is the exception, and it is the documented one: trusted publishing
cannot create a crate, so a `CARGO_REGISTRY_TOKEN` secret carries the first
publish of each name. A long-lived token in a secret is the weaker
arrangement -- it does not expire on its own, and it is not bound to a
workflow the way a trusted publisher is -- so the `release` environment's
required reviewer stands in for that binding, and the secret is deleted once
every crate exists and the trusted publisher takes over.

## Placeholders to set before the first release

The repository (`https://github.com/sercanatalik/galata-vault`) and the
Homebrew tap (`sercanatalik/homebrew-tap`) are set; both must exist before
the first release. Still marked `TBD` in the tree:

- the response time in `SECURITY.md`;
- `.github/workflows/release.yml`, which is generated: run `dist generate`
  against `dist-workspace.toml` and commit the result. It is deliberately not
  written by hand, because the `plan` step compares the two and fails when
  they disagree;
- the `RELEASE_PLZ_TOKEN` and `HOMEBREW_TAP_TOKEN` secrets, which can exist
  only once the repository and the tap do;
- the `release` and `pypi` environments, each with a maintainer as required
  reviewer, and the two trusted publishers that name them.

The contact address in `CODE_OF_CONDUCT.md` is set, and every action in every
workflow is pinned to a commit SHA.

## The first release, 0.1.0 (by hand)

crates.io trusted publishing cannot create a crate, so the first publish uses
a token. Do it from a clean checkout of the release commit, on one day, once
the repository is public.

1. Re-check every name, the same day: `curl -s -A "<you>"
   https://crates.io/api/v1/crates/<name>` must answer 404 for each crate,
   and `https://pypi.org/pypi/galata-vault/json` must answer 404. If any name
   is taken, stop. Do not publish under a variant.
2. `scripts/check-all.sh`, then `scripts/check-packaging.sh verify`.
3. Create a crates.io token with the `publish-new` and `publish-update`
   scopes, limited to the `galata-vault*` crate names, expiring in a day.
4. Publish in dependency order, one crate at a time, checking each off:

   | # | Crate | Needs |
   |---|---|---|
   | 1 | `galata-vault-proto` | |
   | 2 | `galata-vault-keys` | 1 |
   | 3 | `galata-vault-seal` | 1, 2 |
   | 4 | `galata-vault-store` | 1 |
   | 5 | `galata-vault-server-core` | 1, 4 |
   | 6 | `galata-vault-client` | 1, 2 |
   | 7 | `galata-vault-server` | 1, 4, 5 |
   | 8 | `galata-vault` | 1, 2, 3, 4, 5, 6 |
   | 9 | `galata-vault-cli` | 1, 2, 8 |
   | 10 | `galata-vault-mcp` | 1, 2, 6 |

   ```sh
   cargo publish -p galata-vault-proto      # then -p galata-vault-keys, and so on
   ```

   `cargo publish` is not atomic across crates. If one fails, fix the cause
   and continue from that crate: crates.io refuses a version that is already
   there, so a rerun of an earlier crate fails harmlessly. Never yank to
   "retry"; a published version stays published.
5. Revoke the token.
6. For every crate: add the trusted publisher (this repository,
   `release-plz.yml`, environment `release`), then turn on "enforce trusted
   publishing". A token upload is refused from then on.
7. PyPI: add a pending trusted publisher for `galata-vault` (this
   repository, `wheels.yml`, environment `pypi`), then run `wheels` by hand
   with `publish` set. A pending publisher does not reserve the name, so do
   this the same day.
8. Push the tag `v0.1.0`. dist builds the binaries, installers and Homebrew
   formulae, attests them and creates the GitHub release. Then verify:
   - `gh attestation verify <binary> --repo sercanatalik/galata-vault` for
     each binary;
   - `cargo audit bin <binary>` lists the dependencies;
   - every install line in the README works on a clean machine.
9. The next release, 0.1.1, goes through the automated path, with a
   maintainer watching, to prove trusted publishing end to end.

## A routine release

1. Merged changes accumulate; release-plz keeps a release PR open with the
   next version, the `CHANGELOG.md` entry and cargo-semver-checks' report.
   CI's `semver` job fails the PR if the public API of `galata-vault` or
   `galata-vault-cli` broke without a breaking bump.
2. Edit the changelog entry in the PR if it needs it, then merge.
3. Approve the `release` environment. release-plz publishes every crate
   whose version is not on crates.io yet and pushes `v<version>`.
4. The tag starts dist (`release.yml`) and the wheels (`wheels.yml`);
   approve the `pypi` environment for the upload.

Raising the MSRV is a minor release and gets a changelog line.

## Recovering from a partial publish

- **crates.io:** rerun `release-plz` by hand (`workflow_dispatch`). Its
  `release` step skips every version already published and continues with
  the rest. If a crate itself is broken, fix it, bump the patch version, and
  release that; the half-published version stays.
- **dist:** rerun the failed jobs of `release.yml` for the tag. If the
  release must be rebuilt, delete the GitHub release (not the tag) and rerun.
- **PyPI:** rerun `wheels` by hand with `publish` set. A file that is
  already on PyPI is refused; nothing is overwritten.

## Yanking

A release that is broken or insecure is yanked, never deleted. The fix ships
as a new patch release.

- crates.io: `cargo yank --version <v> <crate>` for every crate in the
  release (it is one version across the set).
- PyPI: yank the release in the project's settings, with a reason.
- GitHub release: mark it as not the latest, and say why in its notes.

A security fix also gets a GitHub security advisory and a RustSec entry
(`SECURITY.md`).

## Rotating a token

- `HOMEBREW_TAP_TOKEN`: create a new fine-grained token on the tap
  repository only (contents: write, the shortest expiry you will keep up
  with), replace the secret, run `release.yml`'s Homebrew job or wait for
  the next release to prove it, then revoke the old token.
- `RELEASE_PLZ_TOKEN`: the same, on this repository. A GitHub App token
  needs no rotation beyond the app's key.
- A token that may have leaked is revoked first and replaced second.

## 1.0

1.0 waits for three things: the external review published under `audit/`
with every high-severity finding fixed, the
format declared frozen in `docs/spec/`, and OpenSSF Best Practices "passing".
