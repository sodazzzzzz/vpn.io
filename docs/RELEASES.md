# Releases & updating the VPS

Updates ship as **GitHub Releases**: pushing a `vX.Y.Z` tag builds everything in
CI and attaches it to a release; the VPS then pulls it with one command you run
yourself. Nothing auto-restarts the server — see [the trade-off](#why-not-fully-automatic).

## Cut a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

`.github/workflows/release.yml` builds and attaches, for that tag:

| Asset | What |
|-------|------|
| `vpn-server` | Linux/amd64 server binary |
| `vpn-bot` | Linux/amd64 onboarding-bot binary |
| `vpn-ca` | Linux/amd64 CA tool |
| `vpn-io-setup.exe` | Windows one-click installer |
| `vpn.io.pkg` | macOS installer |
| `SHA256SUMS` | checksums for the above |
| `SHA256SUMS.minisig` | minisign signature over `SHA256SUMS` (the trust anchor) |

(The repo is public, so release assets download without authentication.)

## Release signing (one-time setup)

`SHA256SUMS` ships alongside the binaries, so on its own it only catches
corruption — anyone who can replace a release asset can regenerate the sums too.
To make a tampered release detectable, CI signs `SHA256SUMS` with a
[minisign](https://jedisct1.github.io/minisign/) key that never appears in a
release, and `vpn-update.sh` verifies that signature against a **pinned public
key** before trusting any hash. Until this is set up, both `release.yml` and
`vpn-update.sh` fail closed.

1. Generate the keypair once, on a trusted machine (not the VPS). Give the secret
   key a password when prompted:

   ```bash
   minisign -G -p vpn-io.pub -s vpn-io.key
   ```

2. Pin the public key in `packaging/server/vpn-update.sh`: replace the
   `MINISIGN_PUBKEY="RWQPLACEHOLDER…"` line with the **second** line of
   `vpn-io.pub` (the one starting with `RW`).

3. Add two repository secrets (Settings → Secrets and variables → Actions):
   - `MINISIGN_SECRET_KEY` — the full contents of `vpn-io.key`.
   - `MINISIGN_PASSWORD` — the password you set in step 1.

4. Keep `vpn-io.key` offline (a password manager / hardware token). It only ever
   lives in the GitHub secret; it must never land on the VPS or in a release.

Rotating the key later means repeating steps 1–3 and shipping the updated
`vpn-update.sh` (new pinned key) before the next release the old VPS pulls.

## Update the VPS

The updater lives at `packaging/server/vpn-update.sh`. `install.sh` puts it at
`/usr/local/sbin/vpn-update` for you; to fetch it standalone (long URLs get
mangled when pasted into a terminal, so build it from short pieces):

```bash
U=https://raw.githubusercontent.com/sodazzzzzz/vpn.io
U=$U/main/packaging/server/vpn-update.sh
curl -fL "$U" -o /usr/local/sbin/vpn-update
chmod +x /usr/local/sbin/vpn-update
```

Then, whenever you cut a release:

```bash
vpn-update            # update the bot + the installers it serves, restart the bot
vpn-update --server   # ALSO replace vpn-server and restart it (prompts first)
```

- Plain `vpn-update` is safe — it only touches the bot and the installer files it
  hands out; the tunnel is untouched.
- `--server` additionally swaps the server binary and restarts it, which **drops
  active tunnels for a moment**, so it asks before doing it (`--yes` to skip the
  prompt). Run it when a release actually changes the server.

It downloads the latest release, verifies `SHA256SUMS`'s minisign signature
against the pinned key, checks the binaries against `SHA256SUMS`, installs them,
refreshes `/etc/vpn-bot/installers/`, and restarts the relevant service.

## Unattended updates (the safe half)

`packaging/server/install.sh` installs the updater as `/usr/local/sbin/vpn-update`
together with a systemd timer, but leaves the timer **off**. Turn it on when you
want the bot and the installers it hands out to keep themselves current:

```bash
sudo systemctl enable --now vpn-update.timer
systemctl list-timers vpn-update.timer     # when it next fires
journalctl -u vpn-update                   # what it did last time
```

It runs `vpn-update` with **no flags** — daily, plus up to six hours of jitter so
every installation of this project does not hit GitHub in the same second. On a
release that is already installed it exits immediately without downloading
anything (the tag it last installed is remembered in
`/var/lib/vpn-update/installed-tag`; `--force` re-installs anyway).

**`--server` is never automated.** Replacing `vpn-server` restarts it and drops
active tunnels — a bad release doing that at 4am is debugged by nobody, and the
people it disconnects are exactly the ones who cannot reach you. That half stays
a decision you make while looking at it.

The argument that used to keep *everything* manual — "an unattended update could
pull a tampered release" — is answered since v0.2.0: releases are signed with
minisign, the public key is pinned in `vpn-update.sh`, and verification is
fail-closed. An update that does not verify installs nothing, exits non-zero and
leaves the unit in a failed state, so `systemctl status vpn-update` and
`systemctl list-timers` both show it rather than reporting a quiet success.
