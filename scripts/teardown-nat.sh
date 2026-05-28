#!/usr/bin/env bash
#
# Undo the rules added by setup-nat.sh. Forwarding is left enabled (it's a
# sysctl, not a per-VPN flag — flipping it back to 0 might surprise other
# services on the host). Comment out the corresponding line below to revert
# that too.
#
# Usage:  sudo scripts/teardown-nat.sh <subnet> <wan-iface>
# Example: sudo scripts/teardown-nat.sh 10.8.0.0/24 eth0

set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: sudo $0 <subnet> <wan-iface>" >&2
    exit 2
fi

SUBNET="$1"
WAN="$2"

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "error: this script is Linux-only" >&2
    exit 1
fi

if [[ "$EUID" -ne 0 ]]; then
    echo "error: must run as root" >&2
    exit 1
fi

del_rule_if_present() {
    local table="$1"; shift
    local chain="$1"; shift
    local args=("$@")
    if iptables -t "$table" -C "$chain" "${args[@]}" 2>/dev/null; then
        echo "* removing -t $table $chain ${args[*]}"
        iptables -t "$table" -D "$chain" "${args[@]}"
    fi
}

del_rule_if_present nat    POSTROUTING -s "$SUBNET" -o "$WAN" -j MASQUERADE
del_rule_if_present filter FORWARD     -s "$SUBNET" -o "$WAN" -j ACCEPT
del_rule_if_present filter FORWARD     -d "$SUBNET" -i "$WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT

# Uncomment to also disable forwarding system-wide:
# sysctl -w net.ipv4.ip_forward=0 >/dev/null

echo "NAT teardown complete for $SUBNET out $WAN."
