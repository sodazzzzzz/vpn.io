#!/bin/sh
set -e

# Group whose members may drive the helper (peer-credential check + socket
# group ownership). Create it and record its gid for the unit's -allow-gid.
if ! getent group vpn-io >/dev/null 2>&1; then
    groupadd --system vpn-io
fi
GID="$(getent group vpn-io | cut -d: -f3)"
printf 'VPNIO_GID=%s\n' "${GID}" > /etc/default/vpn-helper
chmod 0644 /etc/default/vpn-helper

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable --now vpn-helper.service || true
fi

# Convenience: add the installing (sudo) user to the group.
if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    usermod -aG vpn-io "${SUDO_USER}" || true
    echo "vpn.io: added '${SUDO_USER}' to group 'vpn-io' — log out and back in for it to take effect."
else
    echo "vpn.io: add your desktop user to the 'vpn-io' group, then re-login:"
    echo "        sudo usermod -aG vpn-io <user>"
fi

exit 0
