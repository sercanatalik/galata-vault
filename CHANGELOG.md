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

Nothing has been released yet. This section is what 0.1.0 will carry.

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
- `galata-vault-mcp`'s stdio test gave `gv-mcp` 20 seconds to answer while
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

[Unreleased]: https://github.com/sercanatalik/galata-vault/commits/main
