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

The updater lives at `packaging/server/vpn-update.sh`. Install it once, then it's
a command. To fetch it the first time (long URLs get mangled when pasted into a
terminal, so build it from short pieces):

```bash
U=https://raw.githubusercontent.com/sodazzzzzz/vpn.io
U=$U/main/packaging/server/vpn-update.sh
curl -fL "$U" -o /usr/local/bin/vpn-update
chmod +x /usr/local/bin/vpn-update
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

## Why not fully automatic

A cron/timer that pulled and restarted on its own would be convenient, but a bad
release could silently drop everyone's tunnel at an unattended hour — and the
people on it can't debug it. For a self-hosted personal VPN, predictability beats
convenience, so the human stays in the loop: you decide when `--server` runs.
