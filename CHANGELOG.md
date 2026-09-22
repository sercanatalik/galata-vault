# Changelog

Every change to galata-vault that a user would notice, newest first. The
format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the
project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html),
with the pre-1.0 rule that a `0.y` release may break the API and a `0.y.z`
release does not ([README.md](README.md)).

The wire and file formats are versioned separately from the crates, by their
own markers; [docs/spec/stability.md](docs/spec/stability.md) says what a
marker guarantees.

## [Unreleased]

### Changed

- **Ten published crates became one.** `galata-vault` is now the only crate on
  crates.io; `galata_vault::proto`, `::keys`, `::seal`, `::client`,
  `::backend` (was `galata-vault-store`), `::server_core`, `::server`,
  `::cli` and `::mcp` are its modules, each behind the feature that needs it.
  Code that depended on `galata-vault` and used its re-exports is unaffected.
  Code that depended on one of the nine directly moves to the matching
  module: `galata_vault_proto::api::Scope` becomes
  `galata_vault::proto::api::Scope`, and so on. The nine names stay on
  crates.io at 0.2.0 and are not updated again.
- **The separation the crates enforced is now enforced by features, and
  checked.** `server` does not enable `sdk`, so a server build compiles no
  value- or name-crypto code and links none of those crates; the SDK's
  default build links no database, HTTP server or async runtime. The four
  linkage guards are replaced by one, `scripts/check-linkage.sh`, which
  reads the dependency graph per feature set *and* reads the source for a
  serving module that names `crate::keys`, `crate::seal` or `crate::client`
  -- the half the compiler used to do for free.
- **The binaries moved to unpublished crates** (`crates/gv`,
  `crates/gv-server`, `crates/gv-mcp`), thin wrappers that exist so each
  keeps its own release target list. `gv` is therefore no longer installable
  with `cargo install galata-vault-cli`: use the installer from a release,
  the Python package, or `cargo install --git`.
- Match arms that existed only because an enum was `#[non_exhaustive]` in
  another crate are gone; inside one crate the compiler proves them
  unreachable, and a new variant now fails the build at each site instead of
  falling into a fallback.

## [0.3.0] - 2026-09-21

### Changed

- **A release is now a tag, and nothing else.** `scripts/release.sh <version>`
  sets the version everywhere it is written down, dates the changelog entry,
  runs the gate, commits and tags; pushing that tag publishes the crates
  (`.github/workflows/crates.yml`, one `cargo publish --workspace`), the
  wheels and the binaries, in parallel, with nothing left to approve. Both
  uploads authenticate as their workflow through OIDC, so no publishing token
  is stored. release-plz and its release pull request are gone, along with
  the by-hand dependency order the ten crates used to be published in --
  cargo works that out itself. [`RELEASING.md`](RELEASING.md) is the whole
  procedure.

### Added

- `scripts/check-version.sh`, which fails the build when the workspace
  version, the versions its path dependencies carry and the newest changelog
  entry disagree -- or, in a release workflow, when they disagree with the
  tag that started it. The tree is no longer bumped ahead of a release: it
  carries the released version, and notes wait under `## [Unreleased]`.
- `scripts/trusted-publishers.sh`, which registers this repository as the
  trusted publisher of every published crate on crates.io in one pass,
  reading the crate list from the workspace.

## [0.2.0] - 2026-09-21

The `gv ui` screenshots in the README and `docs/local-ui.md`, a logo, and
package badges. Version bumped as a minor release at the maintainer's
request: the changes below are additive, so a 0.1.x would also have been
accurate.

### Added

- The audit chain records a token receiving the vault's token list, as
  `token_list` (code 13). The owner's own status reads are not recorded --
  an environment opens with one, and the chain would fill with them -- and a
  lesser scope reading status is not an attempt to list, so it is not a
  refusal either.

### Changed

- `scripts/check-packaging.sh verify` builds every published crate from its
  own `.crate` again. It was skipped for 0.1.0 because verification resolves
  each crate's siblings from a registry, and they were not published yet.
  It no longer passes `--offline`: a machine that has only built this
  workspace has never downloaded these crates, because the workspace uses
  path dependencies.

## [0.1.0] - 2026-09-21

The first release. Ten crates on crates.io, the `galata-vault` package on
PyPI, and `gv`, `gv-server` and `gv-mcp` binaries with installers and build
attestations on the GitHub release.

### Fixed

- **Rotation now reports a lost race as stale, not as a missing secret.**
  Two owners rotating at once: the loser could fail with `not_found`
  (`secret NAME has no version N`) instead of `stale_generation`. A rotation
  that lands re-indexes every record under the new generation's name key, so
  the loser's index — computed with the generation it opened — stops
  resolving partway through gathering. The retry loop could not recover,
  because it absorbed only a revision conflict. Gathering a record that
  vanishes now rebuilds, and the generation guard then reports it as stale.
  No data was at risk: the winner's chain was always intact and no
  acknowledged write was lost. The error was the bug.
- `scripts/conformance.sh` waited about 10 seconds for `gv-server local` and
  reported "the server did not start" when it was merely slow to first-exec
  after being relinked. The budget is now 60 seconds; a server that really
  fails still reports immediately, because the wait ends as soon as the
  process does.
- An absent token list no longer reads as an empty one. `VaultStatus.tokens`
  is optional to distinguish "you may not see this" from "there are none",
  and two callers flattened that away. One of them was the guard that
  refuses to mint while a token of a scope this client does not know exists
  — so it waved everything through in exactly the case it was written for.
- `galata_vault::mcp`'s stdio test gave `gv-mcp` 20 seconds to answer while
  `gv-mcp` itself allows 60 for the vault opens it does first, so a slow
  open failed the test rather than the code. It now waits for the readiness
  line before speaking the protocol.

### Added

- **An `admin` token can list and revoke tokens through `gv` and the SDK**, as
  the specification has always said it may (`docs/spec/http-api.md#2`). The
  server allowed it; only the command line refused, telling the holder that
  "a token cannot do it, whatever its scope". `gv token ls` and
  `gv token revoke` now accept one, `Vault::tokens()` and `Vault::revoke()`
  give the SDK the same view an owner gets, and revoking through a token
  raises the same forward-only warning, since a token cannot rotate.
  `gv token revoke --rotate` still needs the owner key, and says why.
- Continuous integration: `.github/workflows/ci.yml` runs
  `scripts/check-all.sh` on every pull request and push, `dco.yml` enforces
  the sign-off `CONTRIBUTING.md` requires, and `deny.yml` runs
  `cargo deny check` on pull requests and on a daily schedule.
- [`deploy/README.md`](deploy/README.md): running a server for machines
  other than your own, and what this build deliberately does not implement.
- This changelog, and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).

[Unreleased]: https://github.com/sercanatalik/galata-vault/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/sercanatalik/galata-vault/releases/tag/v0.3.0
[0.2.0]: https://github.com/sercanatalik/galata-vault/releases/tag/v0.2.0
[0.1.0]: https://github.com/sercanatalik/galata-vault/releases/tag/v0.1.0
