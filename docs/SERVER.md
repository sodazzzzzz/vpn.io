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

## Changing a node's address

A profile points at an address, so moving the node to a new IP or name is the
one operation that can lock everyone out at once — the July move happened
exactly this way: the VPS died with its lease and every profile pointed at an
address that no longer answered.

What makes it survivable is that a profile can carry **several addresses for the
same node**, and the client walks them: nothing is pinned to one IP.

### Before you need it

Hand out profiles that already list a spare address, and the move costs nobody
anything:

```bash
vpn-ca export-profile -name alice \
    -server vpn.example.com:8443 \
    -also "203.0.113.5:8443=direct ip"
```

A name plus its current IP is the cheapest pair: if DNS is what breaks, the IP
still works; if the IP changes, the name still resolves. Note that a
multi-address profile needs an app new enough to read it — single-address
profiles stay readable by every released version, which is why `export-profile`
only writes the newer format when you actually ask for more than one address.

### The move itself

1. **Bring the new node up in parallel.** Issue a server certificate whose
   `-hosts` covers **both** the old and the new address, and install it on both
   machines. One certificate valid for both means clients verify either one
   without a profile change.
2. **Keep the old node serving.** This is the whole trick: overlap, do not cut
   over. A client that reconnects during the window lands on whichever answers.
3. **Point the name at the new address**, if the profiles use a name. Most
   clients follow within a DNS TTL and never notice anything happened.
4. **Watch who is left.** `curl -s localhost:9443/readyz` on the old node
   reports its session count; when it stays at zero for a day or two, the
   stragglers have moved.
5. **Retire the old node.**

### For people whose profile does not list the new address

There is no way around handing them a new file: the address has to reach them
somehow, and the server has no channel to a client that cannot connect to it.
Re-invite them through the bot (`/invite <name>`), which mints a replacement
profile and revokes the old one, or export and send the file yourself.

Plan for this **before** step 5 — once the old address stops answering, anyone
still on it is offline until that file arrives.

## Updating

Rebuild the binary, copy it over, then:

```bash
sudo packaging/server/install.sh ./vpn-server   # replaces the binary + unit
sudo systemctl restart vpn-server
```
