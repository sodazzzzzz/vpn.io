#!/bin/sh
# Remove the vpn.io helper LaunchDaemon. Run as root.
set -eu

LABEL=io.vpnio.helper
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"

if [ "$(id -u)" -ne 0 ]; then
	echo "uninstall.sh: must run as root" >&2
	exit 1
fi

# Stop and unload; tolerate an already-removed daemon.
launchctl bootout system "$PLIST_DST" 2>/dev/null || true
rm -f "$PLIST_DST"

echo "vpn-helper LaunchDaemon removed."
