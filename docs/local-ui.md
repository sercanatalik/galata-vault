# `gv ui`: the local UI's threat model

`gv ui` adds a local HTTP surface to `gv`. This file covers only that
surface. The client cryptography it relies on is covered by
[threat-model.md](threat-model.md) and is unchanged.

## Shape

```
 browser tab                     gv ui (the gv process)                gv-server (unchanged)
 ┌───────────────────────┐  HTTP ┌──────────────────────────────┐  /v1  ┌──────────────────┐
 │ HTML, CSS, a little JS │ ────▶ │ keychain · session · crypto  │ ────▶ │ ciphertext only  │
 │ session cookie         │ ◀──── │ terminal: the trusted input  │ ◀──── │ serves no HTML   │
 │ what is on screen      │       └──────────────────────────────┘       └──────────────────┘
 └───────────────────────┘ 127.0.0.1:<OS-assigned port>
```

- **One thread owns all state:** the owner session and its credential store,
  the browser session, the pending confirmation, a minted token awaiting
  hand-over, and the clipboard timers.
- **Code:** `crates/galata-vault-cli/src/ui/`. The HTTP plumbing and checks are in
  `web.rs`, the loop and handlers in `app.rs`, templates in `pages.rs`, and
  the clipboard in `clip.rs`.

## What is at stake

| Asset | Where it lives | Reaches the page? |
|---|---|---|
| Node keys, vault keys, bundles | the `gv` process, the keychain | never |
| Token strings | the `gv` process, until handed over | never (copied, or saved to a 0600 file) |
| Secret values | decrypted in `gv` per request | only in the response to one reveal |
| Names, versions, metadata | decrypted in `gv` | yes |

## Threats and controls

| Threat | Control | Where tested (`crates/galata-vault-cli/tests/ui.rs`) |
|---|---|---|
| Another site in the same browser posts to `gv ui` (CSRF) | `SameSite=Strict` cookie. Every `POST` needs `Origin` equal to `http://127.0.0.1:<port>` and `X-GV-UI: 1`. No CORS headers are sent, so cross-origin reads fail. `GET` changes nothing | `every_request_is_checked_and_every_response_hardened` |
| DNS rebinding (a name that resolves to 127.0.0.1) | An exact `Host` match, checked before any handler; otherwise 421 with an empty body | same |
| Another local user or process connects to the port | A 128-bit single-use code, exchanged for a 256-bit session cookie. One session at a time. Loopback only | same (reused code, stale session after a new link) |
| XSS through vault content (names, values) | `maud` escapes every interpolation. The CSP is `default-src 'none'` with `script-src 'self'` and `style-src 'self'`: no inline script, no `style` attribute anywhere | same (a markup-shaped name) |
| A compromised page tries to keep access | No key or token is reachable. Values come only through reveals, each audited and listed in the terminal. Mint, revoke, rotate and environment delete wait for `y` in the terminal, with a 4-digit code shown on both sides | `a_full_session_leaks_no_key_and_shows_values_only_when_revealed`, `changes_that_matter_wait_for_the_terminal` |
| A stale or copied link, or browser history | The code is in the URL fragment (never sent to a server), spent on first use, lapses after 60 s, and is removed from the address bar immediately | same as the first row |
| A value left on the clipboard | The value goes to the tool on stdin, never in an argument. It is cleared after 30 s, and when `gv ui` exits, but only if the clipboard still holds that value | `the_clipboard_is_cleared_only_while_it_holds_the_value` |
| An unattended session | Locked after 15 minutes without a request (the liveness ping doesn't count). The page removes what it showed on its next 401 | `an_idle_session_locks` |
| A value or credential in a URL | Only the query keys `name`, `with` and `all` are accepted, and none may contain `gvt1_` or `gvk1_` | `every_request_is_checked_and_every_response_hardened`, `web.rs` unit tests |
| `gv ui` started without a terminal, so no confirmation channel | It refuses to start unless stdin and stdout are TTYs | `gv_ui_needs_a_terminal`, and the Python suite |
| The server gains decryption code or HTML | The server is unchanged. The linkage guards and the `Accept: text/html` test still pass | `scripts/check-all.sh` |

## Residual risks, accepted

- **Browser extensions** with access to local pages can read whatever is on
  screen, including a value while it is revealed. The mitigation is the
  default use of copy over reveal, and a clean browser profile.
- **Page memory.** Hiding a value is a courtesy: page memory is outside
  `gv`'s control until the tab closes.
- **Clipboard managers** may keep a history of copied values. Marking
  clipboard content as concealed needs native APIs, and is an open question
  in the design.
- **The one-time code briefly appears in `open`'s or `xdg-open`'s
  arguments.** Another user who wins that race gets the session, and the real
  tab then shows "this link has been used". The terminal prints every session
  start. `--no-open` avoids the race entirely.
- **Secret names appear in page URLs** (history, compare), and therefore in
  browser history. Values and credentials never do.
- **Loopback traffic is plain HTTP.** Only root can read it, and root is out
  of scope.

## Manual checklist

Run this against the Galata Vault UI canvas
(https://claude.ai/artifact/2QTpFnAAaavL7PU8RetZqY) before
a release that touches `ui/`. Check each item in light and dark mode.

- [ ] `gv ui` prints the banner and a link, and opens the browser; `--no-open`
  doesn't.
- [ ] The link opens the projects page, and the address bar shows no `#c=`.
- [ ] Reopening the same link shows "this link has been used"; Enter in the
  terminal prints a new one.
- [ ] Projects: projects and environments with their key kind; add an
  environment; delete one only after `y` in the terminal.
- [ ] Secrets:
  - values masked;
  - reveal shows one value with a countdown, and hides it;
  - copy shows the toast, and the terminal lists the copy;
  - add a secret; delete one; the history sheet; restore.
- [ ] Compare: a shared value is flagged; no value appears on the page.
- [ ] Tokens:
  - mint shows a code;
  - the terminal shows the same code;
  - `y` finishes it, and the token can be copied or saved once;
  - revoking a `read` token says it rotated.
- [ ] Audit: "chain verified", and the reads made through the UI appear.
- [ ] `lock` shows the locked state, and the page keeps nothing.
- [ ] Ctrl-C in the terminal: the page shows "gv ui has stopped" within a
  few seconds.
- [ ] Esc closes dialogs; focus rings are visible when tabbing.
