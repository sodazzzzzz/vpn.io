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
# wails' own self-sign can fail on the com.apple.provenance xattr AFTER the .app
# is fully built; we re-sign by hand below, so THAT failure is benign. But we must
# not swallow every error with `|| true`: a build that dies mid-way (frontend
# bundle crash, partial resource copy) also leaves a .app directory, and shipping
# that broken bundle is #142. So capture the exit code and log, and tolerate only
# the known self-sign failure on an otherwise-complete bundle.
BUILD_LOG="$(mktemp)"
if ! ( cd "$GUI_DIR" && "$WAILS" build -platform "$PLATFORM" ) >"$BUILD_LOG" 2>&1; then
  if ! grep -qiE 'provenance|codesign|code object is not signed' "$BUILD_LOG"; then
    echo "error: wails build failed:" >&2
    cat "$BUILD_LOG" >&2
    rm -f "$BUILD_LOG"
    exit 1
  fi
  echo "note: tolerating wails self-sign failure (the bundle is re-signed below)" >&2
fi
# A complete bundle needs the .app AND an executable in Contents/MacOS: a build
# that aborted after creating the skeleton leaves the directory but no binary.
if [ ! -d "$BUILT_APP" ] || [ -z "$(ls -A "$BUILT_APP/Contents/MacOS" 2>/dev/null)" ]; then
  echo "error: $BUILT_APP missing or incomplete (no executable in Contents/MacOS) — the build failed" >&2
  cat "$BUILD_LOG" >&2
  rm -f "$BUILD_LOG"
  exit 1
fi
rm -f "$BUILD_LOG"

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
