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

## Troubleshooting

- **Service won't start** → `journalctl -u vpn-server -e`. "interface not found"
  means `VPN_WAN` is wrong (step 4).
- **Connects but no internet** → NAT/forwarding: check `VPN_WAN` and that the
  provider doesn't block IP forwarding.
- **Can't reach the server at all** → `8443/tcp` not open in the provider's
  firewall, or the connect address doesn't match the server certificate's
  `-hosts` SAN.

## Updating

Rebuild the binary, copy it over, then:

```bash
sudo packaging/server/install.sh ./vpn-server   # replaces the binary + unit
sudo systemctl restart vpn-server
```
