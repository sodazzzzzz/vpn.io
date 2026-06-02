#!/usr/bin/env bash
#
# Install the vpn.io server as a systemd service.
#
# Usage:  sudo packaging/server/install.sh [path-to-vpn-server-binary]
# Default binary path: ./vpn-server
#
# Build the binary first (on any machine with Go):
#     GOOS=linux GOARCH=amd64 go build -trimpath -o vpn-server ./cmd/vpn-server
#
# See docs/SERVER.md for the full deployment walkthrough.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BIN="${1:-./vpn-server}"

if [[ ! -x "$BIN" ]]; then
    echo "error: vpn-server binary not found at '$BIN'" >&2
    echo "build it:  GOOS=linux GOARCH=amd64 go build -trimpath -o vpn-server ./cmd/vpn-server" >&2
    echo "then run:  sudo $0 ./vpn-server" >&2
    exit 1
fi

echo "* binary       -> /usr/local/bin/vpn-server"
install -m 0755 "$BIN" /usr/local/bin/vpn-server

echo "* setup-nat.sh -> /usr/local/lib/vpn-server/"
install -d -m 0755 /usr/local/lib/vpn-server
install -m 0755 "$REPO_ROOT/scripts/setup-nat.sh" /usr/local/lib/vpn-server/setup-nat.sh

echo "* config dir   -> /etc/vpn-server (0750)"
install -d -m 0750 /etc/vpn-server
if [[ ! -e /etc/vpn-server/server.env ]]; then
    install -m 0640 "$SCRIPT_DIR/server.env.example" /etc/vpn-server/server.env
    echo "               created server.env from the example"
else
    echo "               server.env exists — left unchanged"
fi

echo "* systemd unit -> /etc/systemd/system/vpn-server.service"
install -m 0644 "$SCRIPT_DIR/vpn-server.service" /etc/systemd/system/vpn-server.service
systemctl daemon-reload

cat <<'NEXT'

Installed. Next steps:
  1. Copy your CA-issued files into /etc/vpn-server/ (from the CA host):
         ca.crt  server.crt  server.key        (NOT ca.key)
  2. Edit /etc/vpn-server/server.env — set VPN_WAN (find it: ip route get 1.1.1.1)
     and the subnet / push-routes / push-dns if the defaults don't fit.
  3. Open the listen port (default 8443/tcp) in your provider's firewall.
  4. Start it:
         sudo systemctl enable --now vpn-server
         journalctl -u vpn-server -f

See docs/SERVER.md for the full walkthrough.
NEXT
