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

# FORWARD policy on some distros defaults to DROP, and hosts running Docker or
# ufw already have terminal REJECT/DROP rules sitting near the top of the
# FORWARD chain. Appending (-A) would land our ACCEPTs *after* those, where they
# never match — the script prints "NAT is active" but clients still have no
# internet. Insert at the top (-I FORWARD 1) so tunneled traffic is accepted
# before any pre-existing reject. The -C existence check is position-independent,
# so re-running stays idempotent.
add_forward_rule() {
    local args=("$@")
    if iptables -C FORWARD "${args[@]}" 2>/dev/null; then
        echo "* FORWARD rule already present: ${args[*]}"
    else
        echo "* inserting FORWARD rule at top: ${args[*]}"
        iptables -I FORWARD 1 "${args[@]}"
    fi
}

# Let the operator know when the FORWARD chain isn't ours alone: ufw/Docker put
# their own reject/jump rules here, and our rules only work because we insert
# above them.
if iptables -S FORWARD 2>/dev/null | grep -qiE 'ufw|docker'; then
    echo "* note: FORWARD already contains ufw/Docker rules — inserting ours at the top to take effect before them" >&2
fi

add_forward_rule -s "$SUBNET" -o "$WAN" -j ACCEPT
add_forward_rule -d "$SUBNET" -i "$WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT

echo
echo "NAT is active. Clients on $SUBNET will egress via $WAN."
echo "To undo: sudo scripts/teardown-nat.sh $SUBNET $WAN"
