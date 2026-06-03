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

# Revert the NAT rule BEFORE deleting the helper scripts (we're about to remove
# the teardown script along with /usr/local/lib/vpn-server). Subnet and WAN come
# from the config we deliberately leave in place; skip quietly if either the
# config or the teardown script is missing. ip_forward is left as teardown-nat.sh
# leaves it (a shared sysctl — flipping it might surprise other services).
ENV_FILE=/etc/vpn-server/server.env
TEARDOWN=/usr/local/lib/vpn-server/teardown-nat.sh
if [[ -r "$ENV_FILE" && -x "$TEARDOWN" ]]; then
    # shellcheck disable=SC1090
    . "$ENV_FILE"
    if [[ -n "${VPN_SUBNET:-}" && -n "${VPN_WAN:-}" ]]; then
        echo "* reverting NAT rule ($VPN_SUBNET via $VPN_WAN)"
        "$TEARDOWN" "$VPN_SUBNET" "$VPN_WAN" || true
    fi
fi

rm -f /usr/local/bin/vpn-server
rm -rf /usr/local/lib/vpn-server

echo "Removed vpn-server. Left /etc/vpn-server (config + certs) — 'sudo rm -rf /etc/vpn-server' to purge."
