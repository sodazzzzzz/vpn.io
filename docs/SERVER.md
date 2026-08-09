# Deploying the vpn.io server

How to run `vpn-server` on a rented VPS (e.g. bagevm) as a persistent systemd
service. Three machines, each with different access to secrets:

```
  CA host (trusted, e.g. your laptop)        Rented VPS              Desktop
  ca.crt + ca.key  (root — never leaves)  →  ca.crt              ←  ca.crt
  issues server.* and clients/<you>.*        server.crt + key       <you>.crt + key
                                             vpn-server (root)      + server address
                                             :8443/tcp (mTLS)
```

The CA private key (`ca.key`) stays on the trusted host and is **never** copied
to the VPS, so a compromised VPS cannot issue new client certificates.

## Fast path: provision a fresh VPS

`packaging/server/provision.sh` does everything on this page that can be done on
the VPS itself — packages, the signed release binary, forwarding, NAT, the unit,
the firewall rule — and stops at the one step it must not do:

```bash
sudo bash provision.sh --server vpn.example.com:8443
```

It is **idempotent**: re-running never overwrites a tuned `server.env`, never
restarts a healthy node for no reason, and skips anything already in place. Use
it to rebuild a node, to move to a new machine, or to check a machine still
matches what it should be (`--dry-run` prints the diff without touching
anything).

What it will not do is put certificates on the box — `ca.key` never leaves the
CA host, so the last step is yours, and the script finishes by printing the
exact commands for it. A node without certificates does not start, which is the
correct failure.

The manual walkthrough below is still the reference: read it once so you know
what the script did.

## 1. On the CA host (once)

```bash
vpn-ca init                                   # → ca-data/ca.crt, ca.key
vpn-ca issue-server -hosts vpn.example.com    # or -hosts 203.0.113.5 (your VPS domain/IP)
                                              # → ca-data/server/server.{crt,key}
vpn-ca issue-client  -name mylaptop           # → ca-data/clients/mylaptop.{crt,key}
```

`-hosts` **must** contain the address clients connect to (domain and/or IP): it
goes into the certificate SAN, and each client verifies the server against it.

Back the CA up now, while it holds only one client — the habit is what matters,
and losing `ca.key` later means re-issuing and re-delivering every profile:

```bash
vpn-ca backup -out ca-backup.vpnio-ca         # encrypted; store it off this machine
```

See [CA-RECOVERY.md](CA-RECOVERY.md) for where to keep it and how to restore.

## 2. Provision the VPS

- OS: **Ubuntu Server 24.04 LTS** or **Debian 12** — iptables-based NAT, which is
  what this setup uses. 1 vCPU / 1–2 GB RAM with generous bandwidth is plenty for
  ~15 full-tunnel users.
- Open **8443/tcp** (the listen port) in the provider's firewall / security group.

## 3. Install

Build the binary (on any machine with Go — it's a self-contained linux/amd64
binary):

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -o vpn-server ./cmd/vpn-server
```

Copy the repo (or just `vpn-server`, `packaging/server/`, `scripts/`) to the VPS
and run:

```bash
sudo packaging/server/install.sh ./vpn-server
```

This installs the binary, the NAT helper and the systemd unit, and creates
`/etc/vpn-server/server.env` from the template.

## 4. Configure

Copy the three CA-issued files onto the VPS (NOT `ca.key`):

```
/etc/vpn-server/ca.crt
/etc/vpn-server/server.crt
/etc/vpn-server/server.key
```

Then lock down the private key — after an `scp` it is often left world-readable
(`0644`):

```bash
sudo chmod 0400 /etc/vpn-server/server.key
```

Edit `/etc/vpn-server/server.env`:

- `VPN_WAN` — your public interface. Find it with `ip route get 1.1.1.1` (the
  word after `dev`, commonly `eth0` / `ens3` / `enp1s0`).
- `VPN_PUSH_ROUTES` — `0.0.0.0/0` for a full tunnel (the default).
- Leave subnet / gateway / DNS as-is unless you have a reason to change them.

## 5. Start

```bash
sudo systemctl enable --now vpn-server
systemctl status vpn-server
journalctl -u vpn-server -f
```

Before the server starts (and on every boot), the unit enables IPv4 forwarding
and adds the NAT rule via `setup-nat.sh`.

## 6. On the desktop

Install the app (see [INSTALL.md](INSTALL.md)), import the three client files
plus the server address (`vpn.example.com:8443`), and connect.

---

## Revoking a client

To cut off a client (lost device, removed person), revoke its certificate on
the CA host:

```sh
vpn-ca revoke -name mylaptop      # add it to ca-data/revoked.json
vpn-ca list                       # shows a "Revoked:" section
vpn-ca unrevoke -name mylaptop    # undo, if needed
```

Point the server at that deny-list so it enforces it — set `VPN_REVOKED` in
`server.env` to the `revoked.json` path (e.g. `/etc/vpn-server/revoked.json`,
or the `revoked.json` in your CA directory) and `systemctl restart vpn-server`
once. After that the server **hot-reloads** the file: each `vpn-ca revoke` takes
effect on the client's next connection, no restart needed.

`revoke` denies **every** certificate ever issued to that name, including ones
replaced by an earlier re-issue — the CA keeps an append-only record of its
issuances in `ca-data/issued.json` for exactly this reason. Re-issuing a name
(`issue-client`, or `/invite` in the bot) revokes the certificate it replaces,
so one name always means one live profile; `unrevoke` lifts the revocation on
the client's *current* certificate only, and never resurrects a replaced one.

---

## Troubleshooting

- **Service won't start** → `journalctl -u vpn-server -e`. "interface not found"
  means `VPN_WAN` is wrong (step 4).
- **Connects but no internet** → NAT/forwarding: check `VPN_WAN` and that the
  provider doesn't block IP forwarding.
- **Can't reach the server at all** → `8443/tcp` not open in the provider's
  firewall, or the connect address doesn't match the server certificate's
  `-hosts` SAN.

## Decommissioning a node

One command, on the node:

```bash
sudo packaging/server/uninstall.sh
```

It stops and unregisters the service and the update timer, reverts the NAT rule
before deleting the helper that knows how, and removes the binaries — leaving
`/etc/vpn-server` (config and certificates) for you to inspect or purge.

On the CA host, nothing needs revoking: client certificates are bound to the
**CA**, not to a node, so they keep working against whichever node you point
people at next. The server certificate belongs to the retired machine — if it
may have been copied, treat it as compromised (see
[SECURITY-KEYS.md](SECURITY-KEYS.md)) and issue a new one for the replacement
rather than moving the old pair over.

If the node is being replaced rather than retired, the thing that actually needs
planning is the address in people's profiles: a profile points at a host:port,
so a new machine at a new address means every profile has to learn about it.
Keep the old node serving until they have.

## Updating

Rebuild the binary, copy it over, then:

```bash
sudo packaging/server/install.sh ./vpn-server   # replaces the binary + unit
sudo systemctl restart vpn-server
```
