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

(The repo is public, so release assets download without authentication.)

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

It downloads the latest release, verifies it against `SHA256SUMS`, installs the
binaries, refreshes `/etc/vpn-bot/installers/`, and restarts the relevant service.

## Why not fully automatic

A cron/timer that pulled and restarted on its own would be convenient, but a bad
release could silently drop everyone's tunnel at an unattended hour — and the
people on it can't debug it. For a self-hosted personal VPN, predictability beats
convenience, so the human stays in the loop: you decide when `--server` runs.
