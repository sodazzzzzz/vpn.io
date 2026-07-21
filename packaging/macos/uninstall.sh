#!/usr/bin/env bash
#
# Uninstall the vpn.io macOS .pkg install: stop and remove the privileged helper
# LaunchDaemon and everything the installer placed outside /Applications. The
# .pkg leaves a running root daemon and a world-connectable (0666) control
# socket behind otherwise (#150).
#
# Run with sudo, then trash the app:
#   sudo /Applications/vpn.io.app/Contents/Resources/uninstall.sh
#   (then drag vpn.io.app to the Trash)

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: macOS only" >&2
    exit 1
fi
if [[ "$EUID" -ne 0 ]]; then
    echo "error: run with sudo (the helper is a root LaunchDaemon)" >&2
    exit 1
fi

LABEL="io.vpnio.helper"
PLIST="/Library/LaunchDaemons/${LABEL}.plist"

echo "* stopping the helper daemon"
# bootout by label and by path — either form works depending on macOS version;
# both are no-ops if it's already gone.
launchctl bootout "system/${LABEL}" 2>/dev/null || true
launchctl bootout system "$PLIST" 2>/dev/null || true

echo "* removing installed files"
rm -f "$PLIST"
rm -f /usr/local/bin/vpn-helper
rm -f /var/run/vpn-io-helper.sock
rm -f /var/log/vpn-io-helper.log
rm -f /etc/newsyslog.d/vpn-io-helper.conf

echo "* forgetting the package receipt"
pkgutil --forget io.vpnio.pkg 2>/dev/null || true

echo
echo "Done. The root helper is stopped and removed."
echo "Finish by dragging /Applications/vpn.io.app to the Trash."
