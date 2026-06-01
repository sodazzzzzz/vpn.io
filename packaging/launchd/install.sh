#!/bin/sh
# Install the vpn.io helper as a macOS LaunchDaemon.
#
# Run as root. This does not build the helper — point BIN at the binary
# (default /usr/local/bin/vpn-helper), e.g.:
#     go build -o /usr/local/bin/vpn-helper ./cmd/vpn-helper
#     sudo packaging/launchd/install.sh
set -eu

BIN="${BIN:-/usr/local/bin/vpn-helper}"
LABEL=io.vpnio.helper
PLIST_SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/${LABEL}.plist"
PLIST_DST="/Library/LaunchDaemons/${LABEL}.plist"

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: must run as root" >&2
	exit 1
fi
if [ ! -x "$BIN" ]; then
	echo "install.sh: helper binary not found at $BIN" >&2
	echo "  build it first: go build -o $BIN ./cmd/vpn-helper" >&2
	exit 1
fi

install -m 0644 -o root -g wheel "$PLIST_SRC" "$PLIST_DST"

# Replace any previous instance, then load and start.
launchctl bootout system "$PLIST_DST" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DST"
launchctl enable "system/${LABEL}"

echo "vpn-helper LaunchDaemon loaded."
echo "  status: sudo launchctl print system/${LABEL}"
echo "  logs:   /var/log/vpn-io-helper.log"
