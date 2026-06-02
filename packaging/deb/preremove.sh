#!/bin/sh
set -e

if [ -d /run/systemd/system ]; then
    systemctl disable --now vpn-helper.service || true
fi

exit 0
