#!/bin/sh
# Remove the vpn.io helper systemd system service. Run as root.
set -eu

UNIT_DST=/etc/systemd/system/vpn-helper.service

if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: must run as root" >&2
	exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
	echo "uninstall.sh: systemctl not found" >&2
	exit 1
fi

# disable --now stops and disables; tolerate an already-removed unit.
systemctl disable --now vpn-helper.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload

echo "vpn-helper service removed."
