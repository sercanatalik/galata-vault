# Security policy

galata-vault keeps other people's secrets, so a security report is the most
useful thing anyone can send us. This policy says which versions get fixes,
how to report, and what happens next.

> **galata-vault has not been independently audited. Its formats may change
> before 1.0. Use it at your own risk.** This notice is replaced by a link
> to the report once an external review is published in `audit/`.

## Supported versions

| Version | Security fixes |
|---|---|
| Latest `0.y` release | Yes |
| Any older `0.y` | No: upgrade to the latest `0.y` |

Before 1.0, only the latest `0.y` release receives security fixes. From
1.0, the latest minor release does, and the previous minor release does too
for six months after its successor ships.

This covers every package the project publishes: the crates on crates.io
(`galata-vault` and the `galata-vault-*` crates), the `galata-vault` Python
package on PyPI, and the `gv`, `gv-server` and `gv-mcp` release binaries.

## Reporting a vulnerability

**Report privately, through GitHub private vulnerability reporting:**
<https://github.com/sercanatalik/galata-vault/security/advisories/new>, the
"Report a vulnerability" button on the repository's Security tab. That is the
preferred route: it keeps the report, the discussion and the advisory in one
private place.

**If that is unavailable to you**, or you get no acknowledgement within a
week, mail <sercanatalik@gmail.com> instead. Say only that you have a
galata-vault security report and how to reach you; wait for a reply before
sending details, since that mailbox is ordinary email and not end-to-end
encrypted.

Either way: do not open a public issue, pull request or discussion, and do
not post details anywhere else until a fix is released.

Please include:
- the affected crate, package or binary, and its version or commit;
- what an attacker needs (which of the actors in the threat model they are)
  and what they gain;
- steps or a proof of concept that reproduce it.

**Check the finding against the [threat model](docs/threat-model.md) first.**
It says what each actor (a malicious server or operator, a leaked token, a
network attacker, another local user) can and cannot do, and what is out of
scope, such as a compromised machine while it is unlocked. A way to do
something the threat model says is impossible is a vulnerability. Behaviour
the threat model already describes (for example, that a server can withhold
data, or that a client with no kept state can be shown an old history) is
not, though hardening suggestions are welcome as ordinary issues.

**Tell us if an AI tool helped.** If you used an AI assistant or automated
tool to find the issue or to write the report, please say so, and confirm
that you reproduced the finding yourself. This helps us triage, and it is
not held against a report.

## What happens next

- **Response time: `TBD (maintainer)`.** Suggested: an acknowledgement
  within 7 days and a first assessment within 14 days. galata-vault has one
  maintainer, so these are promises that can be kept, not a service level.
- We confirm the issue, agree a disclosure date with you, and prepare a fix
  privately (in a GitHub security advisory's private fork).
- Fixes ship as a patch release of every affected package.
- Every fixed vulnerability in a published crate is published as a **GitHub
  security advisory** and filed with the **RustSec** advisory database
  ([rustsec/advisory-db](https://github.com/rustsec/advisory-db)), with the
  GitHub advisory id listed as an alias in the RustSec entry. Both name the
  fixed version.
- You are credited in the advisory unless you ask not to be.

Nothing here offers a bug bounty.
