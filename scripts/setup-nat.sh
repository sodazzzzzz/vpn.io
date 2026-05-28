#!/usr/bin/env bash
#
# Enable IPv4 forwarding and add a MASQUERADE rule so tunneled clients can
# reach the public internet through the server's WAN interface.
#
# Usage:  sudo scripts/setup-nat.sh <subnet> <wan-iface>
# Example: sudo scripts/setup-nat.sh 10.8.0.0/24 eth0
#
# To undo, run teardown-nat.sh with the same arguments.
#
# This is Linux-only. For learning purposes it touches the running config
# only — nothing is persisted across reboots; add the equivalent rules to
# your distro's firewall manager (ufw/firewalld/iptables-persistent) if
# you want them survive.

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: sudo $0 <subnet> <wan-iface>" >&2
    echo "example: sudo $0 10.8.0.0/24 eth0" >&2
    exit 2
fi

SUBNET="$1"
WAN="$2"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this script is Linux-only (detected: $(uname -s))" >&2
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "error: must run as root (sysctl + iptables)" >&2
    exit 1
fi

if ! ip link show "$WAN" >/dev/null 2>&1; then
    echo "error: interface '$WAN' not found. Available:" >&2
    ip -o link show | awk -F': ' '{print "  " $2}' >&2
    exit 1
fi

echo "* enabling IPv4 forwarding"
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# Add the MASQUERADE rule only if it isn't already there — re-running this
# script must be safe.
if iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE 2>/dev/null; then
    echo "* MASQUERADE rule already present, skipping"
else
    echo "* adding MASQUERADE rule for $SUBNET out $WAN"
    iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
fi

# FORWARD policy on some distros defaults to DROP — make sure tunneled
# traffic can transit. Same idempotency check.
add_forward_rule() {
    local args=("$@")
    if iptables -C FORWARD "${args[@]}" 2>/dev/null; then
        echo "* FORWARD rule already present: ${args[*]}"
    else
        echo "* adding FORWARD rule: ${args[*]}"
        iptables -A FORWARD "${args[@]}"
    fi
}

add_forward_rule -s "$SUBNET" -o "$WAN" -j ACCEPT
add_forward_rule -d "$SUBNET" -i "$WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo
echo "NAT is active. Clients on $SUBNET will egress via $WAN."
echo "To undo: sudo scripts/teardown-nat.sh $SUBNET $WAN"
