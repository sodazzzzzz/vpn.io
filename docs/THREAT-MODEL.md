# Threat model

What this project protects, what it deliberately does not, and what it assumes.
Written plainly, because a VPN that is vague about its limits is how people end
up relying on it for something it was never built to do.

The short version: **vpn.io hides your traffic from the network you are sitting
on, and moves the place where it becomes visible to a server you control.** It
does not make you anonymous, and it is not built to survive a censor who is
actively looking for it.

## What it protects

**The content and destination of your traffic, from the network you are on.**
Everything between the client and the server runs inside TLS 1.3 with mutual
certificate authentication (`crypto/tls`, pinned to 1.3, no downgrade). A café
Wi-Fi, a hotel network, your ISP, or anyone passively watching that segment sees
one TLS connection to one IP address and nothing about what is inside it.

**Who may connect at all.** Access is a client certificate signed by your CA —
not a password, not a shared key. There is nothing to guess, phish or reuse, and
each person has a distinct identity that can be revoked on its own
(`vpn-ca revoke -name …`, enforced by the server on the next connection).

**Clients from each other.** The server is hub-and-spoke with anti-spoofing:
packets are routed by the address the server assigned, and a client cannot
address another client or forge a source address to impersonate one. Being on
the same tunnel as someone does not put you on a LAN with them.

**Your traffic from leaking around the tunnel.** Routes and DNS are applied
per-OS and removed on exit, with leak protection while the tunnel is up. That
protection differs by platform today — see [the gaps](#known-gaps) below.

**Your credentials at rest.** Keys are written owner-only and checked at
startup; the profile bundle is a secret file. See
[SECURITY-KEYS.md](SECURITY-KEYS.md).

## What it does NOT protect against

Stated without softening. Each of these is a real limit, not a hypothetical.

**A compromised server.** The server terminates your tunnel and forwards your
traffic — it necessarily sees every destination you connect to, and the content
of anything not separately encrypted (i.e. anything not HTTPS). Whoever controls
that machine can watch all of it. This is not a flaw in the design; it is what a
VPN *is*. The mitigation is that the machine is yours.

**Your VPS provider, and their jurisdiction.** They own the hardware, the
hypervisor and the network. They can see traffic at the exit, and can be
compelled to act. A self-hosted VPN moves your trust from an ISP to a hosting
company — it does not eliminate it.

**Anyone who can see both ends.** An observer watching your local network *and*
the server's network can correlate timing and volume and tell that you are
talking to a given destination, without breaking any crypto. Nothing here
defends against traffic analysis at that scale: packet sizes and timings are not
padded, and there is no cover traffic.

**A determined censor.** The transport is ordinary TLS on a fixed port to a
fixed address. It does not imitate other protocols, does not rotate endpoints,
and does not disguise its handshake. A DPI system looking for VPN-shaped traffic
can find it, and blocking the server's IP is enough to stop it. This project is
built for privacy on untrusted networks, **not** for censorship circumvention.

**Metadata on the server itself.** The server logs connection events: source IP,
certificate CommonName, assigned tunnel IP, timestamps, session duration,
failures. "Who connected, from where, when, for how long" exists on that
machine, and the operator can read it.

At the default log level nothing about the traffic itself is written. At
`-log-level debug` the picture changes: dropped packets are logged with their
destination address (client-isolation drops, and outbound packets discarded
because a client's queue was full). That is a debugging affordance, not a
per-connection log of where you went, but it does mean **debug logging on a
server carrying other people's traffic is not privacy-neutral**. A systematic
audit of every logging path is tracked in #292.

**A compromised client device.** Malware or another user with your account on
your own machine can read the profile, the key, and your traffic before it ever
reaches the tunnel. Nothing on the server side can compensate.

**Anonymity.** You are not anonymous to your server, and your server's IP is a
stable identifier shared by everyone using it. Sites see one address that maps
to a small group of people. If your threat model needs anonymity rather than
privacy, use Tor.

**Profile delivery over Telegram.** When the bot is used, the `.vpnio` file —
which contains the client's private key — travels through Telegram's servers.
Telegram sees that file. That is a deliberate convenience trade documented in
[BOT.md](BOT.md); deliver profiles by hand if it is unacceptable to you.

**Anything after the exit.** Traffic leaving the server towards the internet is
as exposed as it would be from any other machine. The tunnel ends there.

## Assumptions

The design is only sound while these hold:

1. **The CA root key is not copied.** Whoever has it can mint an identity the
   server accepts, and revocation cannot help — the deny-list works by serial,
   and they can mint serials that were never issued.
2. **The operator is trustworthy and their machine is not compromised.** That is
   you: you hold the CA, you run the server, you can read the logs.
3. **The clocks are roughly right.** Certificate validity is time-based on both
   sides.
4. **TLS 1.3 and the Go standard library implementation are sound.** No custom
   cryptography is used anywhere in the data path.
5. **The people you give profiles to keep them private.** A shared profile is a
   shared identity; the fix is to revoke and re-issue, not to detect it.

## Known gaps

Current state, not aspiration:

- **Leak protection is complete only on Linux.** There, a full kill switch makes
  egress default-deny while the tunnel is up. On macOS and Windows only IPv6 is
  blocked (which stops the dual-stack leak the data plane would otherwise have),
  so if the tunnel drops on those platforms, IPv4 traffic goes out in the clear
  until it reconnects. Full backends are tracked in #268 (pf) and #269 (WFP).
- **Revocation applies on the next connection.** An already-established session
  survives until it reconnects (#253).
- **No external security audit.** None of this has been reviewed by anyone
  outside the project.
- **Binaries are unsigned** on Windows and macOS, so users are trained to click
  past OS warnings during install — which is itself a security property, and not
  a good one (#272, #273).

## Reporting a problem

If you have found something that breaks one of the protections above, use
GitHub's private vulnerability reporting rather than a public issue — see
[SECURITY.md](../SECURITY.md).
