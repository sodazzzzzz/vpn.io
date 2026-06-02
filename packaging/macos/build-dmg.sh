#!/usr/bin/env bash
#
# Build an unsigned (ad-hoc signed) macOS .dmg for vpn.io.
#
# We deliberately do NOT buy an Apple Developer certificate / notarize: the app
# is ad-hoc signed (free) and the user does a one-time right-click -> Open (see
# docs/INSTALL.md). The script also encapsulates the codesign workaround we hit
# during dev: `wails build`'s self-sign fails on the com.apple.provenance xattr,
# so we strip xattrs and ad-hoc sign by hand.
#
# Requirements (macOS): Wails CLI, Go, Node/npm, Xcode command-line tools.
# Output: dist/vpn.io.dmg
#
# Env:
#   PLATFORM  wails -platform value (default darwin/universal; Intel + Apple
#             Silicon). Set darwin/arm64 for a faster host-only build.
#   WAILS     path to the wails binary (default: $(go env GOPATH)/bin/wails)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUI_DIR="$REPO_ROOT/cmd/vpn-gui"
DIST="$REPO_ROOT/dist"
APP_NAME="vpn.io"
PLATFORM="${PLATFORM:-darwin/universal}"
WAILS="${WAILS:-$(go env GOPATH)/bin/wails}"

BUILT_APP="$GUI_DIR/build/bin/vpn-gui.app"
APP="$DIST/$APP_NAME.app"
DMG="$DIST/$APP_NAME.dmg"

echo "==> Building GUI ($PLATFORM)"
rm -rf "$BUILT_APP"
# wails' own self-sign can fail on the provenance xattr; the .app is still built,
# so don't abort here — we verify the bundle exists and sign it ourselves below.
( cd "$GUI_DIR" && "$WAILS" build -platform "$PLATFORM" ) || true
if [ ! -d "$BUILT_APP" ]; then
  echo "error: $BUILT_APP was not produced — the build failed" >&2
  exit 1
fi

echo "==> Ad-hoc signing"
mkdir -p "$DIST"
rm -rf "$APP"
cp -R "$BUILT_APP" "$APP"
xattr -cr "$APP"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

echo "==> Creating .dmg"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT   # clean the staging dir even if a step below fails
cp -R "$APP" "$STAGE/"
ln -s /Applications "$STAGE/Applications"
rm -f "$DMG"
hdiutil create -volname "$APP_NAME" -srcfolder "$STAGE" -ov -format UDZO "$DMG" >/dev/null

echo "==> Done"
ls -lh "$DMG"
