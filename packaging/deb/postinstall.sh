#!/bin/sh
set -e

# The 'vpn-io' group gives a member filesystem access to the control socket in
# /run/vpn-io (the unit runs with Group=vpn-io). Authorisation itself is by uid:
# SO_PEERCRED reports the peer's uid + primary gid, NOT supplementary groups, so
# adding a user to vpn-io alone wouldn't pass the peer-cred check — we record the
# user's uid in /etc/default/vpn-helper for -allow-uid.
if ! getent group vpn-io >/dev/null 2>&1; then
    groupadd --system vpn-io
fi

# Write the uid file only on first install — never on upgrade. An unattended
# upgrade (apt) has no SUDO_USER, so re-writing here would blank VPNIO_UID and
# silently lock out the desktop user. If it already exists, leave it as the
# admin configured it.
if [ ! -e /etc/default/vpn-helper ]; then
    VPNIO_UID=""
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
        VPNIO_UID="$(id -u "${SUDO_USER}" 2>/dev/null || true)"
        usermod -aG vpn-io "${SUDO_USER}" || true   # filesystem access to the socket
    fi
    # Default to 0 (root, always allowed) rather than empty: an empty value
    # would make systemd pass a bare `-allow-uid` and the daemon crash-loop.
    # Root-only is the safe degraded state; the admin sets the real uid later.
    printf 'VPNIO_UID=%s\n' "${VPNIO_UID:-0}" > /etc/default/vpn-helper
    chmod 0644 /etc/default/vpn-helper

    if [ -n "${VPNIO_UID}" ]; then
        echo "vpn.io: authorised '${SUDO_USER}' (uid ${VPNIO_UID}). Log out and back in once (group 'vpn-io') before connecting."
    else
        echo "vpn.io: could not detect your desktop user — authorise it manually:"
        echo "        echo \"VPNIO_UID=\$(id -u <user>)\" | sudo tee /etc/default/vpn-helper"
        echo "        sudo usermod -aG vpn-io <user>"
        echo "        sudo systemctl restart vpn-helper   # then log out and back in"
    fi
fi

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
    systemctl enable --now vpn-helper.service || true
fi

exit 0
