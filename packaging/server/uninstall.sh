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
# The update timer, if it was ever enabled. Left behind it would keep firing
# against a machine that no longer runs any of this.
systemctl disable --now vpn-update.timer 2>/dev/null || true
rm -f /etc/systemd/system/vpn-update.timer /etc/systemd/system/vpn-update.service
systemctl daemon-reload || true

# Revert the NAT rule BEFORE deleting the helper scripts (we're about to remove
# the teardown script along with /usr/local/lib/vpn-server). Subnet and WAN come
# from the config we deliberately leave in place; skip quietly if either the
# config or the teardown script is missing. ip_forward is left as teardown-nat.sh
# leaves it (a shared sysctl — flipping it might surprise other services).
ENV_FILE=/etc/vpn-server/server.env
TEARDOWN=/usr/local/lib/vpn-server/teardown-nat.sh
# read_env extracts one key from a systemd EnvironmentFile WITHOUT `.`-sourcing
# it. The file is literal KEY=VALUE (root-owned 0640); sourcing it as shell would
# EXECUTE a value containing $( ), backticks or spaces that systemd otherwise
# takes literally (#160). last-wins like systemd; everything after the first '=';
# one layer of surrounding quotes stripped.
read_env() {
    local v
    v="$(grep -E "^$1=" "$ENV_FILE" | tail -n1 | cut -d= -f2- || true)"
    v="${v%\"}"; v="${v#\"}"; v="${v%\'}"; v="${v#\'}"
    printf '%s' "$v"
}

if [[ -r "$ENV_FILE" && -x "$TEARDOWN" ]]; then
    VPN_SUBNET="$(read_env VPN_SUBNET)"
    VPN_WAN="$(read_env VPN_WAN)"
    if [[ -n "$VPN_SUBNET" && -n "$VPN_WAN" ]]; then
        echo "* reverting NAT rule ($VPN_SUBNET via $VPN_WAN)"
        "$TEARDOWN" "$VPN_SUBNET" "$VPN_WAN" || true
    fi
fi

rm -f /usr/local/bin/vpn-server
rm -rf /usr/local/lib/vpn-server
rm -f /usr/local/sbin/vpn-update
rm -rf /var/lib/vpn-update

echo "Removed vpn-server. Left /etc/vpn-server (config + certs) — 'sudo rm -rf /etc/vpn-server' to purge."
