#!/usr/bin/env bash
# vpn-update.sh — pull the latest GitHub Release and update this VPS. Run as root.
#
#   vpn-update.sh            update vpn-bot + the installers it serves, restart bot
#   vpn-update.sh --server   ALSO replace vpn-server and restart it
#                            (briefly drops the tunnel; prompts unless --yes)
#   vpn-update.sh --all      same as --server
#   vpn-update.sh --yes      don't prompt before the server restart
#
# Nothing here auto-runs: you run it when you want a new release live. The bot
# update is safe (no tunnel impact); the server update is opt-in because its
# restart drops active VPN connections for a moment.
set -euo pipefail

REPO="sodazzzzzz/vpn.io"
BOT_BIN="/usr/local/bin/vpn-bot"
SERVER_BIN="/usr/local/bin/vpn-server"
INSTALLERS="/etc/vpn-bot/installers"

do_server=0
assume_yes=0
for a in "$@"; do
  case "$a" in
    --server|--all) do_server=1 ;;
    --yes|-y)       assume_yes=1 ;;
    -h|--help)      sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "==> latest release of $REPO"
# Fetch fully into a variable first, then parse. Piping curl straight into
# `grep -m1` makes grep close the pipe on the first match, so curl aborts its
# still-pending write with exit 23 — which `set -o pipefail` then treats as a
# failure even though the tag was read fine.
api="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
tag="$(printf '%s\n' "$api" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
[ -n "$tag" ] || { echo "could not determine the latest release tag" >&2; exit 1; }
echo "    $tag"

base="https://github.com/$REPO/releases/download/$tag"
dl() { echo "    download $1"; curl -fSL --retry 3 -o "$tmp/$1" "$base/$1"; }

# Always refresh the bot and the installers it hands out.
dl vpn-bot
dl vpn-io-setup.exe
dl vpn.io.pkg
dl SHA256SUMS   # required — we refuse to install anything we can't verify
[ "$do_server" = 1 ] && dl vpn-server

# Integrity check against the release's published sums. Fail closed: every
# downloaded file must have a matching entry, and the hashes must verify — an
# empty or short match set (e.g. the asset names drifted) is a failure, not a
# silent pass (`sha256sum -c` on an empty list returns success).
echo "==> verify checksums"
( cd "$tmp"
  : > _check
  want=0
  for f in vpn-bot vpn-server vpn-io-setup.exe vpn.io.pkg; do
    [ -f "$f" ] || continue
    want=$((want + 1))
    grep -E "[[:space:]]${f}\$" SHA256SUMS >> _check || true
  done
  got=$(grep -c . _check || true)
  [ "$want" -gt 0 ] && [ "$got" -eq "$want" ] || {
    echo "checksum entries missing ($got/$want matched) — refusing to install" >&2
    exit 1
  }
  sha256sum -c _check )

echo "==> update bot + installers"
install -m 0755 "$tmp/vpn-bot" "$BOT_BIN"
install -m 0644 -o vpn-bot -g vpn-bot "$tmp/vpn-io-setup.exe" "$INSTALLERS/vpn-io-setup.exe"
install -m 0644 -o vpn-bot -g vpn-bot "$tmp/vpn.io.pkg"       "$INSTALLERS/vpn.io.pkg"
systemctl restart vpn-bot
echo "    vpn-bot restarted"

if [ "$do_server" = 1 ]; then
  if [ "$assume_yes" != 1 ]; then
    printf "Restart vpn-server now? This briefly drops the tunnel. [y/N] "
    read -r ans
    case "$ans" in y|Y) ;; *) echo "    skipped server restart"; echo "==> done ($tag)"; exit 0 ;; esac
  fi
  echo "==> update server"
  install -m 0755 "$tmp/vpn-server" "$SERVER_BIN"
  systemctl restart vpn-server
  echo "    vpn-server restarted"
fi

echo "==> done ($tag)"
