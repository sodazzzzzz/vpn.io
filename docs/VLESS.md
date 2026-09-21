# The second service: VLESS/REALITY

The vpn.io server needs the vpn.io app: it speaks our own mTLS protocol and
nothing else does. That rules out phones, and it makes a Windows install a
matter of a service and a driver.

The second service fixes that by not being ours. A node can run **VLESS over
REALITY**, spoken by the upstream [Xray-core](https://github.com/XTLS/Xray-core)
binary, and anyone with a third-party client — [Happ](https://happ.su) on a
phone, v2rayN, sing-box — imports a single link and connects.

```
  friend ──token──▶ bot ──▶ vless:// link ──▶ Happ ──▶ node :443 (REALITY)
                     │
                     └──▶ alice.vpnio ──▶ vpn.io app ──▶ node :8443 (mTLS)
```

Both services run on one node. They share the machine and nothing else.

## What this service does not do

Read this before handing links to people, because the two services are not
equivalent and the difference is not visible to the person using them.

- **No kill switch, no leak protection.** The vpn.io app blocks traffic that
  would escape the tunnel; a third-party client does what its own settings say,
  which by default is usually less. If the connection drops, traffic goes out in
  the clear.
- **It is a proxy, not a full tunnel.** What gets routed through it is the
  client app's decision, not the node's.
- **Revocation takes a restart.** Removing someone takes effect when the service
  restarts (a second), not instantly.

What it does give you is reach: a device that cannot run our app can still use
the node.

## Why it can share a node with vpn-server

Nothing overlaps:

| | `vpn-server` | `vpn-xray` |
|---|---|---|
| Port | 8443 | 443 |
| Shape | L3 tunnel: TUN device, 10.8.0.0/24, MASQUERADE | proxy: outbound sockets from the node's own stack |
| Privileges | root (TUN, routes, firewall) | `vpn-xray` user + `CAP_NET_BIND_SERVICE` |
| Keys | our CA | its own X25519 pair |

The NAT rule `setup-nat.sh` installs is scoped to the tunnel subnet and the WAN
interface, and Xray's traffic never enters that path — it leaves through the
local stack, not through FORWARD.

Two consequences of one node are worth accepting deliberately:

- **One IP, one fate.** If the address is blocked, both services die together,
  and both share whatever reputation that IP earns (captchas and rate limits
  follow the address, not the service).
- **The 8443 neighbour.** REALITY's premise is that the address looks like an
  ordinary web server. A scanner also finds 8443 answering with a TLS server
  that demands a client certificate, which is not what an ordinary site does. It
  does not break anything; it does dent the story. Moving `vpn-server` to a less
  remarkable port is the cheap mitigation if that matters to you.

## Install

On the node, as root. First make sure the updater is current — a node updated
before this service existed has a `vpn-update` that knows nothing about
`vpn-vless` (long URLs get mangled when pasted into a terminal, so build it from
short pieces):

```bash
U=https://raw.githubusercontent.com/sodazzzzzz/vpn.io
curl -fL "$U/main/packaging/server/vpn-update.sh" -o /usr/local/sbin/vpn-update
chmod +x /usr/local/sbin/vpn-update
```

Then install the service itself:

```bash
curl -fL "$U/main/packaging/server/install-xray.sh" -o install-xray.sh
bash install-xray.sh
```

It installs a pinned, checksummed Xray-core release, the `vpn-xray` service user
and unit, the reload units (see [Applying changes](#applying-changes)), and opens
443/tcp in ufw. Run standalone like this, it fetches the unit files it needs.
It does **not** start anything: there are no keys yet.

Now the node has `/etc/vpn-xray`, which is what tells the updater this node runs
the service — so `vpn-vless` arrives with the next update:

```bash
vpn-update --force
```

Finally, generate this node's REALITY identity and start it:

```bash
vpn-vless init -address vpn.example.com
systemctl enable --now vpn-xray
systemctl status vpn-xray
```

`init` writes `/etc/vpn-xray/node.json` (address, keys, the site being
impersonated) and a config with no clients. The private key never leaves the
node and is in no backup we ship — losing it means reissuing every link.

### Choosing the site to impersonate

REALITY works by forwarding any handshake it cannot authenticate to a real,
third-party site, so a scanner gets that site's genuine TLS answer. `-dest` and
`-sni` name it. The default is `www.apple.com:443`.

A good choice:

- speaks TLS 1.3 and HTTP/2;
- **has a small certificate chain** — see below, this one bites;
- is reachable and unremarkable from the networks your users are on — a site
  their ISP sees all day is better than one nobody there visits;
- stays up, and is **not yours**: a domain connected to you ties the node back
  to you the moment anyone looks.

`init` checks the target before adopting it, and you can check any candidate
without changing anything:

```bash
vpn-vless check-dest www.apple.com:443
```

#### The certificate-chain trap

REALITY presents no certificate of its own: it relays the target's real
handshake and substitutes only the signature. Those relayed records go through a
fixed buffer, so a target whose certificates do not fit produces a handshake
that never completes.

The symptom is the worst kind. The node is healthy, the port answers, a scanner
sees the real site — and the client says **connected while passing no traffic**.
Nothing in the node's own logs says otherwise; the only one who finds out is the
person holding the link.

Measured (chain size as sent on the wire):

| Target | Chain | Works |
|---|---|---|
| `www.microsoft.com` | 5879 B | **no** |
| `dl.google.com` | ~4.9 KB | yes |
| `www.bing.com` | ~4.0 KB | yes |
| `www.apple.com` | 3231 B | yes |
| `www.cloudflare.com` | ~2.6 KB | yes |

`check-dest` refuses anything over 4096 bytes and warns past 3072.

Changing the target later means every issued link is wrong (the SNI travels in
the link), so decide before handing out access. To change it:

```bash
vpn-vless check-dest <new-target>:443     # first, confirm it is usable
# edit "dest" and "serverNames" in /etc/vpn-xray/node.json
vpn-vless render && systemctl restart vpn-xray
vpn-vless link <name>                      # reissue every link
```

## Handing out access

Through the bot, with the same one-time invite flow as profiles. Add the
directory to the bot's unit (`packaging/server/vpn-bot.service` has the line
commented out) and restart it:

```
    -vless-dir /etc/vpn-xray \
```

The bot must be in the `vpn-xray` group; `install-xray.sh` puts it there if the
bot was installed first. If you installed in the other order, run
`usermod -aG vpn-xray vpn-bot && systemctl restart vpn-bot`.

Then, in a private chat with the bot:

```
/invite anna vless     → a token that hands over a vless:// link
/invite anna both      → token for a link AND an app profile
/invite anna           → app profile only (the default, unchanged)
/vless                 → who currently has VLESS access
/revoke anna           → cuts BOTH services for that person
```

Without the bot, on the node:

```bash
vpn-vless add anna       # prints the link
vpn-vless list
vpn-vless link anna      # print it again
vpn-vless remove anna
```

The link **is** the access — anyone holding it is that client. Send it the way
you would send a profile: a private chat, never a group.

## Importing into Happ

1. Copy the link the bot sent (tap it; it is one line starting with `vless://`).
2. Open Happ and use **+** → **Add from clipboard** (Happ reads the link from
   the clipboard; other clients call this "import from URL").
3. The server appears in the list under this node's label.
4. Tap connect.

It works when the client shows a connected state and your IP, checked in a
browser, is the node's. If it does not:

- **Connects, no traffic** — first suspect the masquerade target:
  `vpn-vless check-dest <the dest from node.json>`. An oversized certificate
  chain produces exactly this (see [the trap](#the-certificate-chain-trap)).
  After that, check the SNI in the link matches `serverNames` on the node.
- **Never connects** — the link may predate a change to the node's keys or
  address, or the person may have been revoked. `vpn-vless list` settles it.
- **Worked, then stopped** — check `systemctl status vpn-xray` first; a failed
  restart leaves the old config running or the service down.

## Applying changes

Xray reads its config once, at start-up, so adding or revoking someone takes
effect on a restart. Nobody restarts it by hand: `vpn-xray-reload.path` watches
`/etc/vpn-xray/config.json` and runs a root-owned oneshot
(`/usr/local/lib/vpn-xray/apply-config.sh`) that waits three seconds — so a
burst of edits costs one restart — and then restarts `vpn-xray`, but **only if
the config is actually newer than the running process**.

That last condition is not paranoia. A path unit can fire again after the
service it triggered finishes, and sleep-then-restart without a guard becomes a
service that restarts every three seconds forever. The service's own log looks
fine (repeated clean starts); what users see is connections that die
mid-handshake. If you ever suspect it, `journalctl -u vpn-xray | tail -30` shows
the cadence immediately.

That indirection exists because the writer is `vpn-bot`, which runs unprivileged
with `NoNewPrivileges=yes` — it cannot elevate through sudo even with a rule,
and granting it the right to restart units would be a larger grant than this
needs. What it can do without any privilege is *ask* systemd whether the service
came back, which it does after every change: if the restart failed, the owner is
told, rather than the friend discovering it.

**A restart drops live connections for about a second.** Clients reconnect on
their own.

## Moving the node

When the node's address changes, this service needs the same treatment as the
first one (see the node-address procedure in `docs/`):

1. Edit `address` in `/etc/vpn-xray/node.json`.
2. `vpn-vless render && systemctl restart vpn-xray`.
3. Reissue every link — the address is baked into each one. `vpn-vless link
   <name>` prints the current link per person; the UUIDs do not change, so
   nobody has to be re-added.

## IPv6

`init` binds `::` when the host has IPv6 and `0.0.0.0` when it does not, and
records the choice as `listen` in `node.json`.

It matters more than it looks: mobile networks are frequently IPv6-only, and a
node bound to IPv4 only is simply unreachable from them. Nothing on the node
shows this — the service is healthy, the link is valid, and only the person on
that network finds out. To change it later, edit `listen` in `node.json`, then
`vpn-vless render && systemctl restart vpn-xray`. The link does not change.

Note that the node's address in the link is still what clients dial; publishing
an IPv6 address there is a separate decision (a second node entry, effectively).

## Files

| Path | What | Mode |
|---|---|---|
| `/etc/vpn-xray/node.json` | address, keys, impersonated site | 0660 |
| `/etc/vpn-xray/clients.json` | who has access | 0660 |
| `/etc/vpn-xray/config.json` | what Xray reads, rendered from the two above | 0660 |

The directory is `2770`, owned by `vpn-xray:vpn-xray`. Two accounts write there
— the bot and root with the CLI — and the setgid bit keeps files readable by
both. Everything in it is a key or a credential; the directory is what keeps the
rest of the box out.

## Upgrading Xray-core

The version and its checksum are pinned in `install-xray.sh`. To move:

```bash
curl -fsSL https://github.com/XTLS/Xray-core/releases/download/<tag>/Xray-linux-64.zip.dgst
```

Take the `SHA2-256` line, update `XRAY_VERSION` and both `XRAY_SHA256_*`
constants together, and re-run the script. It replaces the binary only when the
pinned version differs, then restarts nothing on its own — restart `vpn-xray`
when you are ready to drop connections for a second.
