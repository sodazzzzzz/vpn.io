# Telegram onboarding bot (`vpn-bot`)

`vpn-bot` hands out client profiles without you running `vpn-ca` and sending
files by hand: you generate a **one-time invite token**, give it to a person,
they message it to the bot, and the bot replies with a ready-to-import `.vpnio`
file — and, optionally, the app installer for their OS (see `-installers`).

```
  you ──vpn-bot token -name alice──▶ token  ──(any channel)──▶  friend
  friend ──token──▶ bot ──issue-client + bundle──▶ alice.vpnio (+ installer) ──▶ friend ──▶ imports in the app
```

## ⚠️ Trust trade-off (read this)

The bot **signs client certificates**, so it needs `ca.key`. Running it
always-on means `ca.key` lives on that host. If you run it on the VPN VPS, a VPS
compromise lets an attacker mint **any** client *and* server certificate (full
access + the ability to impersonate the server). That is strictly weaker than
the default model, where `ca.key` never leaves your trusted machine.

Mitigations applied below: a dedicated unprivileged user, `ca.key` `0600`,
systemd hardening, and no inbound port (the bot only makes outbound calls to
Telegram). A future hardening is an **intermediate CA**: keep the root key
offline on your Mac and give the bot only an intermediate — then a VPS breach is
contained to a revocable intermediate.

## 1. Create the bot

In Telegram, message **@BotFather** → `/newbot` → follow the prompts → copy the
**bot token** (looks like `123456:ABC-DEF...`). Keep it secret.

## 2. Build

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o vpn-bot ./cmd/vpn-bot
```

## 3. Put the CA on the host

The bot needs the CA directory **including `ca.key`**:

```
/etc/vpn-bot/ca-data/ca.crt
/etc/vpn-bot/ca-data/ca.key      ← the signing key (this is the trade-off)
/etc/vpn-bot/ca-data/clients/    ← issued client certs land here
```

Lock it down:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin vpn-bot
sudo install -d -m 0750 -o vpn-bot -g vpn-bot /etc/vpn-bot /etc/vpn-bot/ca-data
sudo install -m 0600 -o vpn-bot -g vpn-bot ca.key /etc/vpn-bot/ca-data/ca.key
sudo install -m 0644 -o vpn-bot -g vpn-bot ca.crt /etc/vpn-bot/ca-data/ca.crt
sudo install -m 0755 vpn-bot /usr/local/bin/vpn-bot
```

## 4. Run it as a service

`/etc/systemd/system/vpn-bot.service`:

```ini
[Unit]
Description=vpn.io Telegram onboarding bot
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=vpn-bot
Group=vpn-bot
WorkingDirectory=/etc/vpn-bot
# The bot reads the token from $TELEGRAM_TOKEN (EnvironmentFile, 0600) and is
# NOT passed as a flag, so it never appears in argv / `ps`:
#   echo 'TELEGRAM_TOKEN=123456:ABC-DEF...' | sudo tee /etc/vpn-bot/bot.env
EnvironmentFile=/etc/vpn-bot/bot.env
ExecStart=/usr/local/bin/vpn-bot serve \
    -dir /etc/vpn-bot/ca-data \
    -server 203.0.113.5:8443 \
    -store /etc/vpn-bot/invite-tokens.json \
    -installers /etc/vpn-bot/installers \
    -owner 123456789
# -owner is optional: that Telegram user ID can mint tokens with /invite
# (send /whoami to the bot to learn yours). Drop the line to disable.
Restart=on-failure
RestartSec=3

# Hardening — the bot only reads the CA dir and talks to Telegram.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/etc/vpn-bot
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
ProtectClock=yes
ProtectKernelLogs=yes

[Install]
WantedBy=multi-user.target
```

```bash
echo 'TELEGRAM_TOKEN=123456:ABC-DEF...' | sudo tee /etc/vpn-bot/bot.env
sudo chmod 0600 /etc/vpn-bot/bot.env && sudo chown vpn-bot:vpn-bot /etc/vpn-bot/bot.env
sudo systemctl daemon-reload && sudo systemctl enable --now vpn-bot
journalctl -u vpn-bot -f
```

Set `-server` to the address clients connect to (must match the server
certificate's `-hosts` SAN — see [SERVER.md](SERVER.md)).

### App installers (optional, `-installers`)

With `-installers DIR`, after sending the `.vpnio` the bot shows **Windows /
macOS / Linux** buttons and sends the matching installer when one is tapped — so
a person gets *both* files from one chat. Drop the latest build artifacts there;
the bot serves the newest file matching each OS by extension:

```
/etc/vpn-bot/installers/vpn-io-setup.exe   ← Windows  (*.exe)
/etc/vpn-bot/installers/vpn.io.pkg         ← macOS    (*.pkg)
/etc/vpn-bot/installers/vpn-io_*.deb       ← Linux    (*.deb)
```

```bash
sudo install -d -m 0755 -o vpn-bot -g vpn-bot /etc/vpn-bot/installers
# copy each installer (from the CI artifacts) into it, e.g.:
sudo install -m 0644 -o vpn-bot -g vpn-bot vpn.io.pkg /etc/vpn-bot/installers/
```

A button only appears for an OS that has a file present. Installers aren't secret
(useless without a profile), so they need no token. Omit `-installers` to send
just the profile.

## 5. Onboard someone

Generate a one-time token for them (as the `vpn-bot` user so the store stays
owned correctly):

```bash
sudo -u vpn-bot vpn-bot token -name alice -store /etc/vpn-bot/invite-tokens.json
```

Send the printed token to the person by any channel. They open a chat with your
bot, send the token, and get back `alice.vpnio` (plus, if you set `-installers`,
buttons to download the app for their OS). The token is **single-use** —
redeeming it again is rejected. In the app they choose **“Import a profile
file”** and pick the file.

### Or manage clients from the bot (`-owner`)

With `-owner <your-telegram-id>` set, you can manage clients by messaging the
bot — no SSH. In a **private** chat with the bot:

- **`/whoami`** → your Telegram ID (set it as `-owner` and restart the bot).
- **`/invite alice`** → a single-use token for `alice`.
- **`/revoke alice`** → cut alice off (the server drops her on her next
  connection — see [SERVER.md](SERVER.md) for `-revoked`).
- **`/unrevoke alice`** → undo a revoke.
- **`/revoked`** → list revoked clients.

These work only for that one Telegram ID and only in a private chat (a token or
client list is never printed into a group); everyone else just gets the
greeting. Revocations land in the same `revoked.json` the server enforces, so
point the server's `-revoked` at the CA directory's `revoked.json`.

`/revoke` blocks the **issued certificate** (by serial). A later `/invite alice`
for the same name issues a *new* certificate that is not on the deny-list — so
re-inviting a revoked name restores access (use a different name if you don't
want that).

## Notes

- The token is 128-bit random and single-use; brute-forcing it is infeasible and
  Telegram rate-limits bots, so no extra throttling is configured.
- The bot processes requests one at a time — fine for a personal deployment.
- Revocation isn't built yet: to cut off a client, re-issue the CA or (future)
  add a deny-list.
