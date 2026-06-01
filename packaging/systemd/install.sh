#!/bin/sh
# Install the vpn.io helper as a systemd system service.
#
# Run as root. This does not build the helper — point BIN at the binary
# (default /usr/local/bin/vpn-helper), e.g.:
#     go build -o /usr/local/bin/vpn-helper ./cmd/vpn-helper
#     sudo packaging/systemd/install.sh
set -eu

BIN="${BIN:-/usr/local/bin/vpn-helper}"
UNIT_SRC="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/vpn-helper.service"
UNIT_DST=/etc/systemd/system/vpn-helper.service

if [ "$(id -u)" -ne 0 ]; then
	echo "install.sh: must run as root" >&2
	exit 1
fi
if ! command -v systemctl >/dev/null 2>&1; then
	echo "install.sh: systemctl not found (is this a systemd system?)" >&2
	exit 1
fi
if [ ! -x "$BIN" ]; then
	echo "install.sh: helper binary not found at $BIN" >&2
	echo "  build it first: go build -o $BIN ./cmd/vpn-helper" >&2
	exit 1
fi

install -m 0644 "$UNIT_SRC" "$UNIT_DST"
systemctl daemon-reload
systemctl enable --now vpn-helper.service

echo "vpn-helper installed and started."
echo "  status: systemctl status vpn-helper"
echo "  logs:   journalctl -u vpn-helper -f"
