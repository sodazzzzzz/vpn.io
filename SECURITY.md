# Security policy

vpn.io carries other people's traffic and runs a privileged service on their
machines. If you have found a way to break that, this page is how to tell me.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/sodazzzzzz/vpn.io/security/advisories/new).
It is private between you and me until an advisory is published, and it needs no
email address from either of us.

Please do **not** open a public issue for anything that would let someone read
traffic, impersonate a client, bypass revocation, or gain privilege through the
helper. Everything else — crashes, bad error messages, hardening ideas — is fine
in the open tracker.

Useful in a report, in rough order of value:

- what an attacker gains, in one sentence;
- the position they need to start from (on the same network? a local account on
  the user's machine? a stolen profile?);
- steps to reproduce, or the code path if a proof of concept is impractical;
- the version or commit you looked at.

If it is easier to send a patch than a description, send the patch.

## What to expect

This is a personal project maintained by one person, so these are honest
timelines rather than a corporate SLA:

| | |
|---|---|
| Acknowledgement | within 7 days |
| Assessment (is it real, how bad) | within 14 days |
| Fix for something actively exploitable | as fast as I can, days not weeks |
| Fix for everything else | in the next release |
| Credit | yes, if you want it — tell me the name to use |
| Bounty | none. There is no budget, and pretending otherwise would waste your time |

You will hear back either way. A report that turns out not to be a
vulnerability still gets a reply explaining why.

## What counts as a vulnerability

Anything that breaks a protection this project claims. Those claims are written
down in [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md); the short list:

- reading or modifying tunnel traffic without the client's key;
- connecting without a certificate signed by the CA, or with a revoked one;
- one client reaching or impersonating another client;
- privilege escalation via the helper service or its IPC socket — including any
  way for an unprivileged local process to drive the tunnel or extract a key;
- key material leaking into logs, error messages, telemetry or crash reports;
- installing or updating in a way that lets an attacker run code as root or
  Administrator (signature bypass in the update path, an installer that can be
  tricked into running a file from a writable location).

## What does not count

Not because these do not matter, but because they are known and documented
rather than a surprise:

- **DPI detection or IP blocking.** The transport is ordinary TLS on a fixed
  address; censorship resistance is explicitly not a goal.
- **Traffic analysis by an observer who sees both ends.** No padding, no cover
  traffic.
- **Anything a compromised server or a hostile VPS provider can do.** The server
  terminates the tunnel by design.
- **Anything requiring the CA private key, the release signing key, or admin
  access to the user's machine.** Those are the trust roots, not targets to
  defend against once they are gone.
- **Unsigned installers** on Windows and macOS. Known and tracked.

Read the threat model before reporting one of these — if you think a case is
genuinely outside what is written there, say so, and I would rather hear it.

## How a fix is handled

1. Reproduce it, and work out what else is affected by the same root cause.
2. Fix it on a private branch, with a regression test.
3. Cut a release. Server operators update with `vpn-update`; desktop users need
   the new installer.
4. Publish the advisory with what was affected, which versions, and what an
   operator should do beyond updating (rotate a key? revoke a certificate?).
5. Notify the people running it. For a small self-hosted circle that means a
   direct message, not a blog post.

Disclosure timing is negotiable — if you want a specific date, ask. The default
is: advisory published once a fixed release is out and the servers I know about
have taken it.

## Supported versions

The latest release. There are no maintenance branches: fixes go into the next
release and users update.
