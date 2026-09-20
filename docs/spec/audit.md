# Audit chain

Status: **draft** (docs/spec/README.md#1).

Every vault has a hash-chained audit log, computed by the server and
verifiable by every client. Notation: `‖` is concatenation; integers are
big-endian. Vectors: `testdata/vectors/v1/audit.json` (row encodings and
hashes in both row formats, and the verification algorithm over served
pages).

<a id="1"></a>
## 1. Rows

A server appends one row, in the same transaction as the action, for every
vault creation, rotation and deletion, children write, token mint,
revocation and report, record write, deletion and value read, and every
authenticated attempt refused by a scope, precondition, generation, version
or quota check (result `refused`). A row served by `GET /v1/audit` is a JSON
object with these fields, in this order:

| Field | Value | Meaning |
|---|---|---|
| `v` | number | the row format (§4) |
| `seq` | `u64` | the row's position in the vault's chain, from 1 |
| `ts` | `i64` | when it happened, Unix seconds |
| `actor` | `{"kind":"owner"}` or `{"kind":"token","id":<hex>}` | who acted |
| `action` | a name from §3 | what was done |
| `name_hmac` | hex, or `null` | the record index the action concerned |
| `subject` | hex; omitted when none | the token an action was done to (minted, revoked, reported) |
| `result` | `"ok"` or `"refused"` | whether the action happened |
| `version` | `u64` | the record version written or read; 0 where none applies |
| `ct_hash` | hex; omitted when none | SHA-256 of the stored ciphertext written or read; for a rotation, the new descriptor's hash |
| `prev` | hex | the previous row's `hash`; 32 zero bytes for the first row |
| `hash` | hex | this row's hash (§2) |

Rows hold no value, no plaintext name and no address. A client that reads a
value can check the ciphertext it was served against the `ct_hash` of the
verified row that recorded the write.

<a id="2"></a>
## 2. Encoding and hash

A row's hash covers every field but `hash`, as these bytes:

```
row     =  v(u8) = 1 ‖ fields
fields  =  seq(u64) ‖ ts(i64) ‖ opt(actor token id) ‖ action(u16) ‖ opt(name_hmac)
           ‖ result(u8) ‖ opt(subject) ‖ version(u64) ‖ opt(ct_hash) ‖ prev(32)
opt(x)  =  0x00 when absent, 0x01 ‖ x when present
```

- The owner as actor is an absent `opt`; a token actor is `0x01 ‖ token id`.
- `action` is the action's code (§3); `result` is 0 for ok and 1 for
  refused.
- `hash = BLAKE3(derive-key mode, context "galata-vault v1 audit row", bytes)`,
  32 bytes. The leading `v` byte is the row format, so a row in a later
  format can never hash as a format 1 row.

<a id="3"></a>
## 3. Actions and results

| Code | Action |
|---|---|
| 1 | `vault_create` |
| 2 | `vault_rotate` |
| 4 | `vault_delete` |
| 5 | `vault_expire` |
| 6 | `children_write` |
| 10 | `token_mint` |
| 11 | `token_revoke` |
| 12 | `token_report` |
| 20 | `secret_put` |
| 21 | `secret_delete` |
| 22 | `secret_read` |
| 30 | `config_write` |
| 31 | `config_delete` |
| 32 | `config_read` |

Code 3 is unassigned and MUST NOT be assigned. A new action gets a new code, only ever appended; a code is never
renumbered. A new `result` value, or any new field, needs a new row format
(§4), because the encoding has no room for one.

<a id="4"></a>
## 4. Row formats and reading a page

- **Format 1** is the only row format: `"v": 1` on the wire, and the marker
  as the first hashed byte (§2).

A row refuses any field it does not have, because every field is hashed. A
page (`{"rows": […], "head": …}`) is a response like any other and tolerates
fields it does not know (http-api.md#7). A client reads a page's rows in
order:
1. a row without `v` is malformed (`bad_encoding`);
2. a row whose `v` is greater than the newest format the client knows stops
   the rows the client can verify: that row and every row after it are
   unverifiable in a newer format (`unverifiable_newer_format`), and are not
   kept;
3. a row in a known format that names an action (§3) or an actor kind the
   client does not know also stops the rows it can verify: it cannot be
   hashed, so verification refuses it (`unknown_value`; the SDKs report
   `unsupported_by_client`, http-api.md#7);
4. any other row that does not parse as its format, including a row with a
   field its format does not have, is malformed (`bad_encoding`).

A row in a newer format is never reported as tampered, and never as
verified.

<a id="5"></a>
## 5. Verification

A client verifies every row a server served after the head `known` it
verified last (all pages, in order), the head the server reported, and where
reading the rows stopped (§4), if it did. The algorithm, as
`galata_vault_proto::audit::verify_rows` implements it:
1. With a known head, the server's head MUST NOT be behind it (`rollback`),
   and MUST NOT differ from it at the same position (`fork`). A server that
   reports no head at all is behind any known head (`rollback`).
2. The base is the known head. With no known head, the base is the first row
   served: its `seq − 1` and its `prev`. A client with no head therefore
   trusts where the server's rows begin; older rows may have moved to an
   archive.
3. Each row MUST have the next `seq`, MUST name the previous row's hash (or
   the base) as `prev`, and MUST hash to its own `hash` (§2); otherwise
   `chain_break`.
4. Unless reading stopped early, the last verified row MUST be the server's
   head (`chain_break`).
5. A stop at an unknown action or actor refuses the verification
   (`unknown_value`). A stop at a newer format ends it: the rows before it
   are verified, and the new head is the last of them.

A client MUST store the new head only when the verification succeeds, and
then only up to the last verified row. Every scope may fetch and verify its
vault's chain. Pages are fetched with `GET /v1/audit?after=<seq>&limit=<n>`;
a server returns at most 1000 rows per page (http-api.md#2).

<a id="6"></a>
## 6. What verification cannot detect

The chain is computed by the server, with no key. So:
- a server can show different clients different, individually consistent
  histories (a fork), and a client detects it only at a position it verified
  before;
- a client with no stored head can be shown any consistent history,
  including one with rows removed from the end or a different past;
- a server can withhold rows a client has not yet seen, or delete the vault;
- a server can stop serving rows at the start of a newer format.

Detection is relative to the heads clients store. Detecting a fork between
clients that never compare heads needs an external witness, which the
protocol does not have. See the threat model (`docs/threat-model.md`).
