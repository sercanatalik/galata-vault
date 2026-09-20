# Using galata-vault

A guide to the concepts behind `gv` and the SDK: the key tree, delegation,
tokens, config documents, durability, expiry, the local UI and the MCP
server. The [README](../README.md) is the short version;
[`docs/spec/`](spec/README.md) is the normative one, and
[`threat-model.md`](threat-model.md) says what each actor can and cannot do.

galata-vault has not been independently audited. Its formats may change
before 1.0. Use it at your own risk.

## Projects and environments are a key tree

A project is one random 256-bit key: the recovery kit holds it (`gvk1_…`).
Every environment key is derived from its parent's key with a one-way HKDF,
so `acme/prod` and `acme/dev` come from `acme`, and `acme/prod/eu` from
`acme/prod`. Paths are at most four lowercase segments.

- **Each node is one vault**, identified by a hash of its owner key. Nobody
  else can claim that id, even after the vault expires.
- **Rediscovery:** every vault holds an owner-only children record, sealed to
  the owner and signed by the owner; no token can read or write it. Any node
  key alone rediscovers its whole subtree: `gv recover acme-recovery.gvkit`
  on a new machine brings back every environment.
- **Typos are caught locally:** `--env acme/prdo` is refused with "did you
  mean acme/prod?", before any request is made.
- **Selection:**
  - `--env`, then `GV_ENV`, then a `.gv.toml` containing only `env = "…"`.
  - A repository file cannot point `gv` at another server. The server URL is
    pinned per project when you run `init`.

## Delegation, and ownership transfer

`gv key export acme/dev` writes a kit that makes its holder the **owner** of
`acme/dev` and everything below it. HKDF is one-way, so the holder has no
path to `acme/prod` or `acme`.

`gv rekey acme/dev` re-roots the subtree: `acme/dev` gets a fresh random key,
and it and every environment below it are re-created at new vault ids with
fresh keys and their data carried over. The old vaults are deleted last, and
every token for them dies with them; `gv` lists the tokens to re-mint. If you
hold the parent's key, the parent's children record is relinked to the new
key; if you don't, the subtree leaves your tree. Afterwards, nothing held
before (the old key, an ancestor's key, old tokens) can derive or read
anything in the subtree. This is how ownership moves without accounts.

The new kit is written before anything changes on the server, and the
re-root is resumable: `gv rekey --resume` finishes an interrupted run, and
`gv rekey --abort` removes new vaults that were never linked.

## No recovery, by design

There is no account, email or operator reset. If you lose every copy of a
project key, its secrets are gone. `gv init` will not finish until you
confirm the recovery kit is stored. Exported environment kits give partial
recovery of their own subtrees.

## Config documents

Besides secrets, a vault holds config documents. These are whole `toml`,
`json`, `yaml` or `text` files, versioned like secrets.

```sh
gv config set app --format toml --env acme/prod < app.toml
gv config get app --env acme/prod               # exactly the bytes written
gv token mint --scope config --env acme/prod    # reads configs, never a secret
```

- **Their own keys.** Each generation has a config keypair and a config
  writer key. A `config` token holds the config key and the name key, never
  the vault key, so it cannot decrypt a secret whatever it is given. A
  `config-write` token also holds the config writer key, and neither the
  vault key nor the secret writer key.
- **Checked before they are sent.**
  - Every body must be UTF-8, and a `toml` or `json` body must parse.
  - A body is refused if it holds a credential literal: a valid `gvt1_`
    token or `gvk1_` key, a PEM private key,
    or `0x` followed by 64 hex digits. The error names the line, since every
    config reader could read the literal. `--allow-literals` overrides this
    for one write.
- **Edits don't cross.** A write can name the version it read. A stale edit
  then fails, naming both versions, and overwrites nothing.

## Tokens, and what revocation means

| Scope | Can | Holds |
|---|---|---|
| `meta` | list names, history, audit, status | the name key |
| `append` | list, create and update secrets and configs; never read | the name key and both writer keys |
| `read` | list and read secrets and configs (optionally only listed secret names) | the vault key and the config key; no writer key |
| `admin` | read and write secrets and configs, list tokens, revoke without rotating | every key of the generation |
| `config` | list, history, audit, status, and read configs | the config key, never the vault key |
| `config-write` | as `config`, and create, update and delete configs; never a secret | the config key and the config writer key |

**Minting, rotation, rekey and deleting an environment need the owner key.**
Bundles and descriptors are owner-signed, so no token, whatever its scope,
can produce them.

**Revocation is forward-only.** Revoking a token stops it at the server. A
holder may already have unwrapped the keys its scope holds, and with a copied
key can decrypt any ciphertext it already copied, or sign a write the server
would refuse only by policy. `gv token revoke <id> --rotate` (owner-only)
moves the whole vault to a new generation in one atomic step: fresh keys,
every retained version re-encrypted and re-signed, a new descriptor linked to
the old one. After that, the old keys open and sign nothing that is stored,
including values written later. Change any secret you believe was actually
read.

Tokens are checksummed (`gvt1_…`, 92 characters after the prefix, carrying
the vault id), so a mistyped token is rejected before it reaches the server.
Whoever holds a leaked token can revoke it without ever sending it:
`gv token report` reads it from a file or stdin and sends a signature made
with the token's own request-signing key.

## Durability and the loss window

- The database is SQLite in WAL mode, in the data directory.
- **Revocations, rotations and vault deletions are journaled** (a rekey is
  durable through the deletions of the vaults it retires). Each is written to
  the journal before it is acknowledged. If the journal cannot be written,
  these operations return 503 (`unavailable`) and change nothing; ordinary
  writes carry on. Before a server serves anything, and before an embedded
  application's first request, the journal is replayed, so an older copy of
  the database cannot bring back a revoked token, undo a rotation, or revive
  a deleted vault.
- **On one machine** (local mode, a self-hosted server, the embedded
  backend) the journal is a directory beside the database, on the same disk.
  It protects against an older copy of the database, not against losing the
  disk: the data directory is the only copy, so back it up
  ([deploy/README.md](../deploy/README.md)).
- **Ordinary writes** (setting a secret) are acknowledged once committed. A
  write that was lost is simply absent: the version history shows what
  survived.

## Expiry

**No vault expires for inactivity.** No server in this repository deletes a
vault because nothing touched it: responses carry no `X-GV-Expires-At`,
status shows no expiry, the capabilities report `idle_expiry_days: null`, and
`gv` sends no keep-alive requests.

The protocol still allows a server to expire idle vaults
([spec/hosted.md](spec/hosted.md)), so `gv` keeps handling one that does.
When a server announces expiry, in its capabilities or its responses:
- Every response carries `X-GV-Expires-At`, and `gv` warns you, naming the
  environment, when that is less than 14 days away.
- While you use any environment, `gv` touches its ancestors at most once a
  day, so a project root outlives environments you use daily.
- `gv env repair <path>` re-creates an expired vault at its same id and
  relists its children. The expired vault's secrets are not recoverable.

## Residual metadata

End-to-end encryption hides contents, not everything. The server, or anyone
with its data, can see:
- how many vaults exist, and each one's size, number of names and versions,
  and write and read times;
- how many config documents each vault holds, with each one's ciphertext
  size and number of versions (configs and secrets are stored apart, so they
  can be told apart);
- token ids, scopes and expiry times, and which token touched which record
  index and version (the audit chain);
- secret- and config-name indexes, which are stable within a generation, so
  repeated access to "the same secret" is visible, though not which secret it
  is.

It can also infer some things:
- **Timing links a project's vaults.** Environments created seconds apart
  from one address are probably one project. Nothing on the server records
  the tree, but timing can suggest it.
- Client IP addresses are not written to the database, logs or metrics; a
  test enforces this. Your TLS terminator's logs are your own to manage.

## Abuse controls

Quotas keep every vault small, in every build:
- secrets: 200 names, 16 KiB per value, 20 versions per name;
- configs: 64 documents, 256 KiB each, 20 versions each;
- 4 MiB per vault across secrets and configs, and 128 tokens.

Every quota is configurable. Nothing the server returns is renderable in a
browser. There is no proof of work, there are no rate limits and nothing
expires: a server that strangers can reach belongs behind a proxy that
limits requests. A configuration asking for any of those is refused at
startup, naming the setting, rather than started without it.

## A local UI: `gv ui`

`gv ui` serves the vault to your browser from the `gv` process itself, on
`127.0.0.1` at a port the OS picks. It prints a one-time link and opens it.
The vault server does not change: it still serves no HTML and cannot
decrypt.

- **Keys stay in `gv`.**
  - The page gets names and metadata, and a value only when you reveal it.
  - A revealed value hides again after 10 seconds.
  - The page never gets a key, a bundle or a token.
- **Copying doesn't show the value.** Copy sends the value from `gv` straight
  to the clipboard (`pbcopy`, or `wl-copy`, `xclip` or `xsel`). It is cleared
  after 30 seconds, unless you have copied something else since.
- **The terminal decides.**
  - Minting a token, revoking one, rotating a vault and deleting an
    environment all wait for `y` in the terminal running `gv ui`. The
    terminal shows the same 4-digit code as the page.
  - Revoking a token that holds a key rotates the vault in the same step, as
    the owner.
  - The terminal lists every reveal, copy and write as it happens.
- **Sessions are short.**
  - A link works once, and lapses after 60 seconds if unused.
  - A session ends after 15 minutes idle, when you press `lock`, or when
    Enter prints a new link.
  - Ctrl-C locks and quits.
  - Opening the browser passes the link as an argument to `open` or
    `xdg-open`; `--no-open` avoids that.
- **What it cannot protect:**
  - A browser extension with access to local pages can read whatever the page
    shows. Use a browser profile without extensions if that matters to you.
  - Clipboard managers may keep a history of what you copy.
- **Key custody stays in the CLI.** `gv init`, `gv recover`, `gv key` and
  `gv rekey` are not available in the UI.

The UI's threat model and manual checklist are in
[docs/local-ui.md](local-ui.md).

## For AI agents: metadata only

`gv mcp setup acme` mints one `meta` token per environment. `gv mcp` then
runs a local stdio MCP server with four tools: `list_secrets`, `diff_envs`,
`audit` and `status`.
- It cannot return or write a value. Its tokens carry no vault key and no
  writer key, and the binary links no value decryption; a CI guard checks
  both.
- It verifies what it reports: the descriptor from the pinned vault id, the
  record signatures behind every listed name, and the audit chain.
- `diff_envs` compares environments on your machine, from independent
  requests, so the server never learns they are related.
