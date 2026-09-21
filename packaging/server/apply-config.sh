#!/usr/bin/env bash
#
# apply-config.sh — restart the VLESS service so it picks up a changed config.
#
# Run by vpn-xray-reload.service, which vpn-xray-reload.path triggers when
# /etc/vpn-xray/config.json changes. Not meant to be run by hand, though doing
# so is harmless.
#
# Two things matter here, and both are about not restarting more than necessary:
#
#   * The debounce. Adding two people in a row writes the config twice, and
#     restarting twice drops live connections twice for no reason.
#
#   * The guard. A path unit can fire again after the service it triggered
#     finishes — and with a three-second sleep in front of a restart, that turns
#     into a service that restarts every three seconds forever, killing every
#     connection mid-handshake. (It did: the symptom was clients that connected
#     and immediately died, with nothing in the service's own log but repeated
#     clean starts.) So this compares the config's timestamp against the time
#     the service last came up, and does nothing when the running process is
#     already newer than the file. Any loop ends on its second iteration.
set -euo pipefail

CONF="${1:-/etc/vpn-xray/config.json}"
UNIT="${2:-vpn-xray.service}"
DEBOUNCE="${VPN_XRAY_DEBOUNCE:-3}"

[ -s "$CONF" ] || { echo "no config at $CONF — nothing to apply"; exit 0; }

sleep "$DEBOUNCE"

changed="$(stat -c %Y "$CONF")"
started_raw="$(systemctl show "$UNIT" -p ActiveEnterTimestamp --value || true)"
started=0
if [ -n "$started_raw" ]; then
  started="$(date -d "$started_raw" +%s 2>/dev/null || echo 0)"
fi

if [ "$started" -gt "$changed" ]; then
  echo "$UNIT started $(date -d "@$started" '+%F %T'), config changed $(date -d "@$changed" '+%F %T') — already applied"
  exit 0
fi

echo "config changed $(date -d "@$changed" '+%F %T') — restarting $UNIT"
exec systemctl restart "$UNIT"
