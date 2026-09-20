# galata-vault

End-to-end encrypted secrets with no account. Your machine encrypts every
secret before it leaves; the server keeps ciphertext it cannot read, and
every value you read carries a signature this package verifies.

> **galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.**

This package gives you:

- **`galata_vault`**, a token client for applications, for secrets and
  config documents;
- **`gv`**, the full command line: create projects and environments, set
  secrets, mint tokens, and `gv run -- <cmd>`.

```sh
pip install galata-vault
```

## Quick start

Start a server on your machine (it needs the `gv-server` binary; see the
[project README](https://github.com/sercanatalik/galata-vault#readme)), then
create a project and an environment:

```sh
gv-server local &
gv init acme --server http://127.0.0.1:8750      # writes acme-recovery.gvkit: keep it safe
gv env add acme/prod
printf %s "postgres://..." | gv set DATABASE_URL --env acme/prod
gv token mint --scope read --env acme/prod       # prints a gvt1_ token once
```

In the application:

```python
import galata_vault

vault = galata_vault.Vault.from_env()   # GV_SERVER, and GV_TOKEN or GV_TOKEN_FILE
url = vault.get("DATABASE_URL")

for secret in vault.list():
    print(secret.name, secret.version, secret.updated_at)

vault.load_env()                        # readable secrets into os.environ (existing ones kept)

app = vault.get_config("app")           # name, format, version, text, data (exact bytes)
settings = app.parse()                  # a dict, for toml and json
vault.set_config("app", new_text, "toml", expect_version=app.version)

head = vault.verify_audit(kept_head)    # keep it; a server that rewrote history is caught
```

`set_config` checks the body before any request. It must parse in its
format, and a credential literal (a key, a token, a PEM block) is refused
unless `allow_literals=True`. With `expect_version`, an edit made from a stale
read raises `ConflictError` and overwrites nothing.

A token can also come from a file: `Vault.from_token_file(path, server)`, or
`GV_TOKEN_FILE` with `from_env()`. The file must have mode 0600 or 0400
(checked before it is read) and hold one token. Setting both `GV_TOKEN` and
`GV_TOKEN_FILE` is refused.

## What a token can do

| Scope | `list` | `get` | `set` | `get_config` | `set_config` |
|---|---|---|---|---|---|
| `meta` | ✓ | | | | |
| `append` | ✓ | | ✓ | | ✓ |
| `read` | ✓ | ✓ (optionally only listed names) | | ✓ | |
| `admin` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `config` | ✓ | | | ✓ | |
| `config-write` | ✓ | | | ✓ | ✓ |

A `meta` or `append` token cannot decrypt a value even in principle: it
never receives the vault key. A `config` or `config-write` token receives
the config key only, so it reads configs and never a secret; a
`config-write` token cannot write a secret either, because it never
receives the key that signs one.

## Errors

Every error derives from `galata_vault.GalataVaultError` and has a stable
`code`, the same string the Rust SDK reports:

- `AuthenticationError`: `invalid_token`, `unauthorized`, `token_expired`;
- `NotFoundError`;
- `ForbiddenError`;
- `ConflictError`: another writer changed the secret or config first;
- `TransportError`: the server is unreachable;
- `IntegrityError`: something the server served does not verify
  (`bad_signature`, `key_mismatch`, `binding_mismatch`, `version_rollback`,
  `generation_rollback`, `audit_mismatch`);
- `GalataVaultError` itself for everything refused before a request, among
  them `invalid_config`, `credential_literal`, `unsupported_format`,
  `invalid_token_file` and `invalid_environment`.

No error message or `repr` contains a token, a key, a secret value or a
config body.

A server may expire vaults after a period without use (local mode does
not). When it announces an expiry less than 14 days away,
`galata_vault.ExpiryWarning` is issued.

## Notes

- Python strings cannot be wiped from memory, so values you read live as
  long as your references to them.
- The library never changes process limits or touches the OS keychain; the
  `gv` command does.
- Supported: CPython 3.11 and later, on Linux and macOS.
