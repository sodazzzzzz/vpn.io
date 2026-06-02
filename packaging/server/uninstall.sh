#!/usr/bin/env bash
#
# Remove the vpn.io server systemd service. Leaves /etc/vpn-server (your config
# and certs) in place; delete it yourself to purge.

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

systemctl disable --now vpn-server.service 2>/dev/null || true
rm -f /etc/systemd/system/vpn-server.service
systemctl daemon-reload || true

rm -f /usr/local/bin/vpn-server
rm -rf /usr/local/lib/vpn-server

echo "Removed vpn-server. Left /etc/vpn-server (config + certs) — 'sudo rm -rf /etc/vpn-server' to purge."
echo "NAT/forwarding rules from setup-nat.sh are not reverted; run scripts/teardown-nat.sh <subnet> <wan> if you want them gone."
