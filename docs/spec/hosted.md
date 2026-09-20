# Hosted appendix

Status: **draft** (docs/spec/README.md#1).

<a id="1"></a>
## 1. Scope of this appendix

A server configured for callers it does not trust may add controls that
`gv-server`, `gv-server local` and the SDK's embedded backend never apply:
proof of work before a vault is created, idle expiry, and rate limits. This
appendix specifies what a client meets from such a server. A client MUST
understand all of it even though most servers use none of it, because it
cannot know in advance which kind of server it talks to: the capabilities
document says (`http-api.md#6`).

**No server in this repository implements this appendix.** `gv-server`
reports `proof_of_work` and `idle_expiry_days` as null, answers
`POST /v1/challenges` with 404, sends no `X-GV-Expires-At`, and limits no
request. What follows is what a third-party server MAY do, and therefore
what a client MUST handle.

<a id="2"></a>
## 2. Proof of work

A server that wants a proof of work sets `proof_of_work` in its capabilities
to `{"difficulty": n}`. A server that sets it to null MUST NOT require a
challenge, MUST answer `POST /v1/challenges` with 404 `not_found`, and MUST
NOT check a challenge a creation request carries.

<a id="2.1"></a>
### 2.1 Challenges

`POST /v1/challenges` with `{"purpose": "create_vault"}` answers
`{"challenge": string, "difficulty": u8, "expires_at": i64}`. A challenge is
stateless:

```text
payload   = id(16, random) ‖ expires_at(i64) ‖ difficulty(u8)        25 bytes
tag       = BLAKE3-keyed(server_key, payload)[..16]
challenge = base64url(payload ‖ tag)                                  41 bytes, 55 characters
```

`server_key` is 32 random bytes the server holds and never publishes; a
server MAY draw a new one at every start, which invalidates outstanding
challenges. A challenge is valid for 600 seconds.

Only the server that issued a challenge opens it. It checks, in order, and
refuses at the first failure:

1. the text is unpadded base64url of exactly 41 bytes (`bad_encoding` in the
   vectors);
2. the tag is the keyed hash of the payload, compared in constant time
   (`bad_signature`);
3. the difficulty is at most 40 (`bad_encoding`);
4. the current time is not after `expires_at` (`expired`).

A challenge is single-use: the server remembers its id, until its expiry,
once a creation that carries it has verified (signature, descriptor and
owner bundle), and refuses it afterwards.

<a id="2.2"></a>
### 2.2 Solving and verifying

A solution is a nonce, a u64, such that

```text
BLAKE3-derive-key("galata-vault v1 proof-of-work", challenge_text ‖ le64(nonce))
```

has at least `difficulty` leading zero bits, counted from the most
significant bit of the first byte. `challenge_text` is the challenge string's
ASCII bytes, as issued. Expected work is `2^difficulty` hashes. Difficulty 0
accepts any nonce. A nonce that does not solve the challenge is `bad_proof`
in the vectors.

<a id="2.3"></a>
### 2.3 Admission

A creation sends the challenge and nonce in `CreateVaultRequest`'s
`challenge` and `nonce` (`http-api.md#8.2`). A server that asks for proof of
work MUST refuse a creation:

- with no challenge, a challenge it did not issue, or a nonce that does not
  solve it: 400 `invalid_proof_of_work`;
- with an expired challenge: 400 `challenge_expired`;
- with a challenge already spent: 409 `challenge_reused`.

It checks the challenge before anything else about the creation. A difficulty
of 24 is about two seconds on a laptop; the maximum a client accepts before
it refuses to search is 40.

<a id="3"></a>
## 3. Idle expiry

A server with an idle-expiry window of `d` days reports `idle_expiry_days: d`
in its capabilities; one without reports null. Unset and 0 both mean never.

- A vault expires `d` days after its last authenticated request. Every
  authenticated request, from the owner or any token, moves that time.
- A server with a window MUST send `X-GV-Expires-At` (Unix seconds) on every
  answer after authentication, success or error, and MUST NOT send it on an
  answer given before the caller authenticated.
- An expired vault authenticates nothing: every request to it, and to every
  token of it, gets the uniform 401 (`http-api.md#3.2`), before and after the
  sweep that deletes it.
- A vault's id is the hash of its owner key, so nobody else can claim an
  expired vault's id; its owner can create it again at the same id, with none
  of the expired contents.
- A client MUST keep a project's ancestors alive, and warn when an expiry is
  less than 14 days away, only when the server announces expiry, in its
  capabilities or its responses.
- `gv-server`, `gv-server local` and the embedded backend MUST NOT expire a
  vault for inactivity.

<a id="4"></a>
## 4. Rate limits

A server with rate limits advertises the `rate_limits` feature
(`http-api.md#6.2`). Representative budgets:

| Budget | Default | Counted |
|---|---|---|
| challenges per address per hour | 120 | each `POST /v1/challenges` |
| creations per address per hour | 20 | each vault created (201) |
| failed authentications per address per minute | 30 | each 401; over the budget, the address is refused outright, credential or not, until the window resets |
| leak reports per address per hour | 60 | each `POST /v1/tokens/report` |
| requests per token per minute | 600 | each authenticated request by that token |
| requests per vault per minute | 1200 | each authenticated request to that vault |

A request over a budget MUST be answered 429 `rate_limited` with
`Retry-After` in seconds, and changes nothing. A client SHOULD wait at least
that long before trying again. The address is the connection's peer, or,
behind a TLS-terminating proxy the operator declared, the rightmost
`X-Forwarded-For` entry. A server MUST keep client addresses only in memory,
for the length of a window, and MUST NOT write them to its database, audit
chain, archive, logs or metrics.

<a id="5"></a>
## 5. Leak reports

`POST /v1/tokens/report` is served by every core, not only one that
applies this appendix (the `token_report` feature). Whoever holds a leaked
token string proves possession with the token's own token-auth key and never
sends the string (`signatures.md#7`, `protocol.md#11`). A server with rate
limits limits it per address (#4).
