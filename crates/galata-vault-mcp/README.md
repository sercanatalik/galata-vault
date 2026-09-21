# galata-vault-mcp

`gv-mcp`, a metadata-only MCP server for galata-vault over stdio, with four
tools: `list_secrets`, `diff_envs`, `audit` and `status`.

It cannot return or write a value. It holds only `meta` tokens, whose
bundles carry the name key and no vault or writer key, and the binary links
no value-decryption code: a guard in the repository fails the build if
`galata-vault-seal` or `age` ever appears in its dependency graph. It
verifies what it reports: the descriptor from the pinned vault id, the
record signatures behind every listed name, and the audit chain.

> galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.

## Install and use

```sh
cargo install galata-vault-mcp     # the gv-mcp binary
gv mcp setup acme                  # mints one meta token per environment
gv mcp                             # or run gv-mcp [--config <mcp.toml>] from your agent
```

The library half (`galata_vault_mcp`) follows the workspace version with no
separate semver promise.

Licensed under the MIT licence.
