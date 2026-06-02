#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi

# On purge, drop the config and the group we created.
if [ "$1" = "purge" ]; then
    rm -f /etc/default/vpn-helper
    groupdel vpn-io 2>/dev/null || true
fi

exit 0
