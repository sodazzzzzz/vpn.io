# Key handling: what exists, where it lives, how it rotates

Every secret this project depends on, what it protects, and what to do when one
of them is lost or leaks. If a key is not on this page, it should not exist.

The short version: two keys can end the project — the **CA root key** (mints
identities the server trusts) and the **release signing key** (mints updates
every server and desktop trusts). Everything else is recoverable in an
afternoon.

## Inventory

| Key | Where it lives | Mode | Lifetime | If it leaks |
|---|---|---|---|---|
| **CA root** `ca.key` | CA host (owner's machine). Also on the bot host if the bot is deployed — see [BOT.md](BOT.md) | `0600` | 10 years | **Rebuild everything.** [Below](#ca-root-key). |
| **Release signing** minisign secret key | Owner's machine + GitHub Actions secret `MINISIGN_SECRET_KEY`. Public key pinned in `packaging/server/vpn-update.sh` | — | no expiry | **Rotate the pin, re-sign, tell every server.** [Below](#release-signing-key). |
| **Server** `server.key` | VPS `/etc/vpn-server/server.key` (issued on the CA host) | `0400`–`0600` | 1 year | Re-issue and redeploy; treat the VPS as compromised. |
| **Client** `<name>.key` | The person's machine (profile store, `0600`) + a copy in `ca-data/clients/` + inside the `.vpnio` bundle | `0600` | 1 year | `vpn-ca revoke -name <name>`. |
| **Telegram bot token** | VPS `/etc/vpn-bot/bot.env` (systemd `EnvironmentFile`) | `0600` | until revoked | Revoke in BotFather, issue a new one, check what was minted meanwhile. |
| **Invite tokens** | VPS `/etc/vpn-bot/invite-tokens.json` | `0600` | 7 days, single use (`invite.DefaultInviteTTL`) | Delete the unused ones; a used one is already spent. |
| **TLS session ticket keys** | Memory only, inside `vpn-server` | — | rotated by `crypto/tls`, gone on restart | Nothing to do — restart the server. |

Nothing on this list is in the repository, and nothing on it should ever be.
`.gitignore` blocks `*.key`, `*.pem`, `*.vpnio`, `*.vpnio-ca` and `/ca-data/`,
but that is a backstop for accidents, not the reason they are absent.

## Who has access

One person: the owner. There is no shared credential, no team vault, no service
account with standing access. Two consequences worth stating plainly:

- **GitHub Actions holds the release signing secret** (`MINISIGN_SECRET_KEY`).
  Anyone who can push a workflow change to `main` can sign a release. That is
  the price of signing in CI; it is why branch protection on `main` matters more
  than it looks.
- **The bot host holds `ca.key`** when the bot is deployed. That is a deliberate
  trade documented in [BOT.md](BOT.md): self-service onboarding requires signing
  certificates on demand. An intermediate CA would contain the blast radius
  (tracked in #264).

## Rotation

| Key | Planned rotation | How |
|---|---|---|
| CA root | Not routine — 10-year lifetime, and a rotation invalidates every profile in circulation. Revisit when intermediate CAs land (#264). | New CA, re-issue everything, redeliver every profile. |
| Server cert | Yearly, or on any suspicion about the VPS. | `vpn-ca issue-server -hosts …`, copy the pair to the VPS, `systemctl restart vpn-server`. Brief drop of active tunnels — zero-downtime rotation is #266. |
| Client certs | Yearly, before `NotAfter`. | `vpn-ca issue-client -name <name>` (this revokes the certificate it replaces), then re-export and redeliver the profile. Renewal without re-onboarding is #265. |
| Bot token | On suspicion only. | BotFather → revoke → new token → update `/etc/vpn-bot/bot.env` → restart. |
| Release signing key | On suspicion only. | See below — it needs a coordinated pin update, so do not do it casually. |

**Expiry is silent.** A client certificate that runs out produces an opaque TLS
failure, not a message saying "your certificate expired" — `vpn-ca list` shows
the CA's own expiry, and each profile carries its `NotAfter`. Until #265 lands,
watching that date is a manual habit.

## Permission checks in code

Modes are checked where the keys are used, not just asserted in this document:

- `vpn-server` warns at startup if `server.key` is readable beyond its owner.
  It warns rather than refuses: the tunnel is what people depend on, and nobody
  can fix a file mode from a VPN that will not start. The warning names the
  file and the `chmod` that fixes it.
- `vpn-ca` runs the same check on `ca.key`, `server/server.key` and — on
  `export-profile` — the client key, on every command that opens the CA. So an
  ordinary `vpn-ca list` reports a mode that widened months ago.

Both use `internal/keyperm`. On Windows the check is a no-op: Windows ignores
Unix modes (`os.Stat` synthesises `0666` there), so checking them would warn on
every key and train the operator to ignore it. Access there comes from the ACL
on the install directory that the installer creates.

The common way a key ends up world-readable is `scp` — it lands `0644` — which
is why [SERVER.md](SERVER.md) has an explicit `chmod 0400` step after copying.

## When a key leaks

### CA root key

The worst case. Whoever has it can mint a client certificate the server accepts,
and **revocation cannot help**: the deny-list works by serial, and they can mint
serials that were never issued. There is no partial containment.

1. Assume every certificate signed by that CA is untrustworthy.
2. Work out how the copy happened *before* rebuilding — a new CA on a machine
   that is still leaking is theatre.
3. New CA (`vpn-ca init`), new server certificate, redeploy the server.
4. Re-issue every client and redeliver every profile. Everyone loses access the
   moment the server picks up the new CA, so tell people first.
5. Take a fresh backup ([CA-RECOVERY.md](CA-RECOVERY.md)) of the new CA.

Losing the key without leaking it is the same rebuild, minus the urgency —
which is what the encrypted backup exists to prevent.

### Release signing key

Second worst, and easy to underestimate: `vpn-update.sh` pins the public key and
verifies fail-closed, so a stolen secret key lets an attacker publish an
"authentic" update that servers install as root.

1. Generate a new keypair (`minisign -G`).
2. Update the pinned `MINISIGN_PUBKEY` in `packaging/server/vpn-update.sh` and
   the `MINISIGN_SECRET_KEY` secret in GitHub Actions.
3. Re-sign and re-publish the current release with the new key.
4. **Update every server by hand.** A server still pinning the old key will not
   accept the new signatures — the pin is the whole point — so each one needs
   the new `vpn-update.sh` copied over manually.
5. Check the release history for anything published that you did not publish.

### Server key

Someone holding `server.key` can impersonate the server to clients, but only
with a network position that lets them intercept the connection. Assume the VPS
itself is compromised: rotate the server certificate, rotate the bot token and
the invite store if the bot runs there, and rebuild the machine rather than
cleaning it.

### Client key

Contained by design, and the one case with a real fix:

```bash
vpn-ca revoke -name <name>     # every certificate ever issued to that name
```

The server hot-reloads the deny-list, so the next connection attempt is
rejected without a restart. An **already-established** session survives until it
reconnects — closing live sessions on revocation is #253. Then re-issue and
deliver a fresh profile.

### Bot token or invite tokens

The bot signs certificates, so a stolen token means someone could hand out
profiles. Revoke the token in BotFather, restart the bot with the new one, then
audit: `vpn-ca list` for names you did not issue, and the invite store for
tokens redeemed by someone unexpected (each entry records `usedBy` and
`usedAt`). Revoke anything that looks wrong.

## Related

- [CA-RECOVERY.md](CA-RECOVERY.md) — backing up the CA and restoring it
- [SERVER.md](SERVER.md) — where the server's keys go on a node
- [BOT.md](BOT.md) — why the bot host holds `ca.key`, and how it is contained
- [RELEASES.md](RELEASES.md) — how releases are signed and verified
