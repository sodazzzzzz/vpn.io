#!/bin/sh
set -e

# dpkg calls prerm as "remove" on uninstall and "upgrade <new>" when replacing
# the package. On upgrade we only stop the service (postinst re-enables/starts
# it): disabling here would drop the autostart symlink, and if postinst then
# fails the service would stay disabled forever.
if [ -d /run/systemd/system ]; then
    case "$1" in
        remove)
            systemctl disable --now vpn-helper.service || true
            ;;
        upgrade | deconfigure)
            systemctl stop vpn-helper.service || true
            ;;
    esac
fi

exit 0
