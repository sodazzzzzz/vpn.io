#!/usr/bin/env bash
# vpn-update.sh — pull the latest GitHub Release and update this VPS. Run as root.
#
#   vpn-update.sh            update vpn-bot + the installers it serves, restart bot
#   vpn-update.sh --server   ALSO replace vpn-server and restart it
#                            (briefly drops the tunnel; prompts unless --yes)
#   vpn-update.sh --all      same as --server
#   vpn-update.sh --yes      don't prompt before the server restart
#   vpn-update.sh --force    re-install even if the latest release is already on
#
# The bot update is safe (no tunnel impact) and can run unattended — see
# vpn-update.timer, which runs exactly this script with no flags. The server
# update stays manual and opt-in: its restart drops active VPN connections, and
# an unattended bad release at 4am is debugged by nobody.
set -euo pipefail

REPO="sodazzzzzz/vpn.io"
BOT_BIN="/usr/local/bin/vpn-bot"
SERVER_BIN="/usr/local/bin/vpn-server"
INSTALLERS="/etc/vpn-bot/installers"
# Tag of the release currently installed. Written only after a run succeeds, so
# a failed update never records itself as done. It is what makes the timer cheap
# and quiet: an unattended daily run on an unchanged release does nothing at all
# instead of re-downloading and bouncing the bot every night.
STATE_FILE="/var/lib/vpn-update/installed-tag"

# Pinned minisign public key — the independent trust anchor for releases. The
# checksum file (SHA256SUMS) is downloaded over the same channel as the binaries,
# so whoever can alter release assets can regenerate the sums too; only a
# signature made with a key that never touches the release lets us catch a
# tampered release. We verify SHA256SUMS.minisig against THIS key before trusting
# any hash — install is refused otherwise.
#
# One-time setup (see docs/RELEASES.md): generate the keypair once, keep the
# secret key OFF the VPS (it lives only as the MINISIGN_SECRET_KEY release
# secret), and paste the SECOND line of the .pub file (starts with "RW") below:
#     minisign -G -p vpn-io.pub -s vpn-io.key
MINISIGN_PUBKEY="RWTgDmnwVFmjgUVlyCF0Hz+ATSdQdswF/ac6tj/bgbE0SbsDLGEzWEH0"

# record_tag remembers the release just installed. Called only after everything
# has succeeded: a failure anywhere earlier leaves the previous value (or none),
# so the next run retries instead of believing the update happened.
record_tag() {
  install -d -m 0755 "$(dirname "$STATE_FILE")"
  printf '%s\n' "$tag" > "$STATE_FILE"
}

do_server=0
assume_yes=0
force=0
for a in "$@"; do
  case "$a" in
    --server|--all) do_server=1 ;;
    --yes|-y)       assume_yes=1 ;;
    --force)        force=1 ;;
    -h|--help)      sed -n '2,14p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (try --help)" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required" >&2; exit 1; }

# Refuse to run until the operator has pinned the real release key: a placeholder
# key can't verify anything, and silently skipping the signature check would
# defeat the whole point.
case "$MINISIGN_PUBKEY" in
  RWQPLACEHOLDER*|"") echo "MINISIGN_PUBKEY is not pinned — edit vpn-update.sh and paste the release public key (see docs/RELEASES.md)" >&2; exit 1 ;;
esac

# minisign verifies the release signature. It's a small dependency; install it
# rather than fall back to an unverified install.
if ! command -v minisign >/dev/null; then
  echo "==> installing minisign (required to verify the release signature)"
  { command -v apt-get >/dev/null && apt-get update -qq && apt-get install -y -qq minisign; } || {
    echo "minisign is required but could not be installed automatically; install it and retry" >&2
    exit 1
  }
fi

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

# Nothing to do if this exact release is already installed. --server is exempt:
# the recorded tag says the bot was updated, not that the server binary was, so
# an operator who ran the safe update yesterday can still take the server today.
if [ "$force" != 1 ] && [ "$do_server" != 1 ] && [ -f "$STATE_FILE" ] &&
   [ "$(cat "$STATE_FILE")" = "$tag" ]; then
  echo "    already installed — nothing to do (--force to re-install)"
  exit 0
fi

base="https://github.com/$REPO/releases/download/$tag"
dl() { echo "    download $1"; curl -fSL --retry 3 -o "$tmp/$1" "$base/$1"; }

# Always refresh the bot and the installers it hands out.
dl vpn-bot
dl vpn-io-setup.exe
dl vpn.io.pkg
dl SHA256SUMS          # required — we refuse to install anything we can't verify
dl SHA256SUMS.minisig  # the signature over SHA256SUMS (verified below)
[ "$do_server" = 1 ] && dl vpn-server

# Signature check FIRST: prove SHA256SUMS itself is authentic (signed by the
# pinned key) before trusting a single hash in it. Without this, a tampered
# release could ship matching-but-malicious binaries and sums together.
echo "==> verify release signature (minisign)"
minisign -Vm "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" -P "$MINISIGN_PUBKEY" >/dev/null || {
  echo "SHA256SUMS signature did not verify against the pinned key — refusing to install" >&2
  exit 1
}

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
  if [ "$want" -eq 0 ] || [ "$got" -ne "$want" ]; then
    echo "checksum entries missing ($got/$want matched) — refusing to install" >&2
    exit 1
  fi
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
    case "$ans" in y|Y) ;; *) echo "    skipped server restart"; record_tag; echo "==> done ($tag)"; exit 0 ;; esac
  fi
  echo "==> update server"
  install -m 0755 "$tmp/vpn-server" "$SERVER_BIN"
  systemctl restart vpn-server
  echo "    vpn-server restarted"
fi

record_tag
echo "==> done ($tag)"
