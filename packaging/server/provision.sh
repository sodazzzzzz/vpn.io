#!/usr/bin/env bash
#
# provision.sh — take a freshly rented Debian/Ubuntu VPS from nothing to a
# running vpn.io node. Run as root, on the VPS.
#
#   curl -fL <raw-url>/provision.sh -o provision.sh
#   sudo bash provision.sh --wan eth0 --server vpn.example.com:8443
#
# Options:
#   --wan IFACE        public interface for NAT (default: detected)
#   --server ADDR      address clients will connect to, host:port — recorded in
#                      the summary so you can copy the right vpn-ca command
#   --version TAG      release to install (default: latest)
#   --subnet CIDR      tunnel subnet (default: 10.8.0.0/24)
#   --skip-firewall    don't touch ufw
#   --dry-run          print what would change and exit
#
# What it does NOT do, on purpose: put certificates on the box. `ca.key` never
# leaves the CA host, so the last step is always yours — the script finishes by
# printing the exact commands to run there. A node with no certificates simply
# does not start, which is the correct failure.
#
# Re-running is safe. Every step checks the current state first: an existing
# server.env is never overwritten, an already-running node is not restarted
# unless its binary actually changed, and the NAT rule is added only if absent.
set -euo pipefail

REPO="sodazzzzzz/vpn.io"
SUBNET="10.8.0.0/24"
LISTEN_PORT="8443"
WAN=""
SERVER_ADDR=""
VERSION="latest"
SKIP_FIREWALL=0
DRY_RUN=0

while [ $# -gt 0 ]; do
  case "$1" in
    --wan)           WAN="${2:?--wan needs an interface}"; shift 2 ;;
    --server)        SERVER_ADDR="${2:?--server needs host:port}"; shift 2 ;;
    --version)       VERSION="${2:?--version needs a tag}"; shift 2 ;;
    --subnet)        SUBNET="${2:?--subnet needs a CIDR}"; shift 2 ;;
    --skip-firewall) SKIP_FIREWALL=1; shift ;;
    --dry-run)       DRY_RUN=1; shift ;;
    -h|--help)       sed -n '2,25p' "$0"; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
done

say()  { echo "==> $*"; }
skip() { echo "    already done: $*"; }
run()  { if [ "$DRY_RUN" = 1 ]; then echo "    would run: $*"; else "$@"; fi; }

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || { echo "this provisions a Linux node (detected $(uname -s))" >&2; exit 1; }
command -v systemctl >/dev/null || { echo "systemd is required" >&2; exit 1; }
command -v apt-get   >/dev/null || { echo "this script targets Debian/Ubuntu (apt-get not found)" >&2; exit 1; }

# Detect the WAN interface the same way the docs tell a human to: whatever the
# kernel would use to reach the internet.
if [ -z "$WAN" ]; then
  WAN="$(ip route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p' | head -n1)"
  [ -n "$WAN" ] || { echo "could not detect the public interface — pass --wan" >&2; exit 1; }
  say "detected public interface: $WAN"
fi
ip link show "$WAN" >/dev/null 2>&1 || { echo "interface $WAN does not exist" >&2; exit 1; }

say "packages"
missing=""
for pkg in curl iptables minisign; do
  command -v "$pkg" >/dev/null || missing="$missing $pkg"
done
if [ -n "$missing" ]; then
  # shellcheck disable=SC2086  # word splitting is what we want for the package list
  run sh -c "apt-get update -qq && apt-get install -y -qq$missing"
else
  skip "curl, iptables, minisign present"
fi

say "release $VERSION"
if [ "$VERSION" = latest ]; then
  api="$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest")"
  VERSION="$(printf '%s\n' "$api" | grep -m1 '"tag_name"' | cut -d'"' -f4)"
  [ -n "$VERSION" ] || { echo "could not determine the latest release tag" >&2; exit 1; }
fi
echo "    $VERSION"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
base="https://github.com/$REPO/releases/download/$VERSION"

if [ "$DRY_RUN" = 1 ]; then
  echo "    would download vpn-server, SHA256SUMS and its signature from $base"
else
  for f in vpn-server SHA256SUMS SHA256SUMS.minisig; do
    curl -fSL --retry 3 -o "$tmp/$f" "$base/$f"
  done
  # Same trust anchor as vpn-update: the pinned release key. Verify the sums
  # file's signature BEFORE trusting any hash in it, then the binary against
  # that hash. Both fail closed.
  say "verify signature and checksum"
  PUBKEY="$(grep -m1 '^MINISIGN_PUBKEY=' "$(dirname "$0")/vpn-update.sh" 2>/dev/null | cut -d'"' -f2 || true)"
  [ -n "$PUBKEY" ] || PUBKEY="RWTgDmnwVFmjgUVlyCF0Hz+ATSdQdswF/ac6tj/bgbE0SbsDLGEzWEH0"
  minisign -Vm "$tmp/SHA256SUMS" -x "$tmp/SHA256SUMS.minisig" -P "$PUBKEY" >/dev/null || {
    echo "SHA256SUMS signature did not verify against the pinned key — refusing to install" >&2
    exit 1
  }
  ( cd "$tmp" && grep -E "[[:space:]]vpn-server\$" SHA256SUMS > _check && sha256sum -c _check >/dev/null ) || {
    echo "vpn-server checksum did not match — refusing to install" >&2
    exit 1
  }
  chmod +x "$tmp/vpn-server"
fi

say "system config"
if [ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo 0)" = 1 ]; then
  skip "ip_forward already on for this boot"
else
  run sysctl -w net.ipv4.ip_forward=1
fi
# setup-nat.sh enables forwarding at every start, but only for the running
# kernel. Persist it too, so a reboot that races the unit still routes.
if grep -qs '^net.ipv4.ip_forward=1' /etc/sysctl.d/99-vpn-io.conf; then
  skip "ip_forward persisted"
else
  run sh -c 'echo net.ipv4.ip_forward=1 > /etc/sysctl.d/99-vpn-io.conf'
fi

say "install"
# Reuse install.sh — it owns the layout, the unit and the NAT helpers, and this
# script has no business duplicating any of that. It needs the repo's scripts/
# next to packaging/server/, which is how the docs already tell people to copy
# things over; when provision.sh is run standalone, fetch the two helpers.
here="$(cd "$(dirname "$0")" && pwd)"
repo_root="$(cd "$here/../.." 2>/dev/null && pwd || echo "")"
if [ ! -f "$repo_root/scripts/setup-nat.sh" ]; then
  say "fetching NAT helpers"
  raw="https://raw.githubusercontent.com/$REPO/$VERSION"
  run mkdir -p "$here/../../scripts"
  for f in setup-nat.sh teardown-nat.sh; do
    run curl -fsSL -o "$here/../../scripts/$f" "$raw/scripts/$f"
    run chmod +x "$here/../../scripts/$f"
  done
fi
if [ "$DRY_RUN" = 1 ]; then
  echo "    would run install.sh with the downloaded vpn-server"
else
  "$here/install.sh" "$tmp/vpn-server"
fi

say "configure"
env_file=/etc/vpn-server/server.env
if [ "$DRY_RUN" = 1 ]; then
  echo "    would set VPN_WAN=$WAN, VPN_SUBNET=$SUBNET in $env_file"
elif grep -q "^VPN_WAN=$WAN\$" "$env_file" 2>/dev/null; then
  skip "server.env already points at $WAN"
else
  # Edit in place rather than replacing the file: an operator's tuned
  # push-routes and DNS must survive a re-provision.
  sed -i "s#^VPN_WAN=.*#VPN_WAN=$WAN#" "$env_file"
  sed -i "s#^VPN_SUBNET=.*#VPN_SUBNET=$SUBNET#" "$env_file"
  echo "    set VPN_WAN=$WAN, VPN_SUBNET=$SUBNET"
fi

if [ "$SKIP_FIREWALL" = 0 ] && command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'; then
  if ufw status | grep -q "^${LISTEN_PORT}/tcp"; then
    skip "ufw already allows ${LISTEN_PORT}/tcp"
  else
    say "firewall"
    run ufw allow "${LISTEN_PORT}/tcp"
  fi
fi

# Certificates are the one thing this script cannot do for you.
certs_present=1
for f in ca.crt server.crt server.key; do
  [ -s "/etc/vpn-server/$f" ] || certs_present=0
done

echo
if [ "$certs_present" = 1 ]; then
  say "certificates present — starting"
  run systemctl enable --now vpn-server
  run systemctl restart vpn-server
  echo
  echo "Node is provisioned and running ($VERSION)."
  echo "Check it:  curl -s localhost:9443/readyz   |   journalctl -u vpn-server -f"
else
  cat <<EOF
Node is provisioned but NOT started: it has no certificates yet, and that part
has to happen on your CA host — ca.key never comes here.

On the CA host:

    vpn-ca issue-server -hosts ${SERVER_ADDR%%:*}
    scp ca-data/ca.crt ca-data/server/server.crt ca-data/server/server.key root@<this-host>:/etc/vpn-server/

Back here:

    chmod 0400 /etc/vpn-server/server.key
    systemctl enable --now vpn-server
    curl -s localhost:9443/readyz

Then issue a client (\`vpn-ca issue-client\` / the bot's /invite) and connect.
EOF
fi
