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
