#!/usr/bin/env bash
#
# Build an unsigned macOS .pkg installer for vpn.io.
#
# Unlike the .dmg (which only drops the .app), the .pkg also installs the
# privileged helper as a LaunchDaemon and starts it — so a non-technical user
# gets a working tunnel from one double-click + admin prompt, with no Terminal.
# We deliberately do NOT buy an Apple Developer cert / notarize: the app is
# ad-hoc signed (free) and the user does a one-time right-click -> Open (see
# docs/INSTALL.md). The .pkg itself is unsigned.
#
# Requirements (macOS): Wails CLI, Go, Node/npm, Xcode command-line tools.
# Output: dist/vpn.io.pkg
#
# Env:
#   VERSION   package version (default 0.0.0)
#   PLATFORM  wails -platform value (default darwin/universal; Intel + Apple
#             Silicon). Set darwin/arm64 for a faster host-only build.
#   WAILS     path to the wails binary (default: $(go env GOPATH)/bin/wails)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
GUI_DIR="$REPO_ROOT/cmd/vpn-gui"
DIST="$REPO_ROOT/dist"
MACOS="$REPO_ROOT/packaging/macos"
APP_NAME="vpn.io"
VERSION="${VERSION:-0.0.0}"
PLATFORM="${PLATFORM:-darwin/universal}"
WAILS="${WAILS:-$(go env GOPATH)/bin/wails}"
IDENTIFIER="io.vpnio.pkg"

BUILT_APP="$GUI_DIR/build/bin/vpn-gui.app"
PKG="$DIST/$APP_NAME.pkg"

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

echo "==> Building helper ($PLATFORM)"
mkdir -p "$DIST"
HELPER="$DIST/vpn-helper"
case "$PLATFORM" in
  */universal)
    GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o "$DIST/vpn-helper.arm64" "$REPO_ROOT/cmd/vpn-helper"
    GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$DIST/vpn-helper.amd64" "$REPO_ROOT/cmd/vpn-helper"
    lipo -create -output "$HELPER" "$DIST/vpn-helper.arm64" "$DIST/vpn-helper.amd64"
    rm -f "$DIST/vpn-helper.arm64" "$DIST/vpn-helper.amd64"
    ;;
  *)
    GOOS=darwin GOARCH="${PLATFORM##*/}" go build -trimpath -ldflags="-s -w" -o "$HELPER" "$REPO_ROOT/cmd/vpn-helper"
    ;;
esac
# lipo strips the per-slice ad-hoc signature the Go linker adds; re-sign so the
# binary runs on Apple Silicon (which refuses unsigned mach-o).
codesign --force --sign - "$HELPER"

echo "==> Staging payload"
PKGROOT="$(mktemp -d)"
trap 'rm -rf "$PKGROOT"' EXIT
mkdir -p "$PKGROOT/Applications" "$PKGROOT/usr/local/bin" "$PKGROOT/Library/LaunchDaemons"

# Ad-hoc sign the .app (wails' self-sign trips on the com.apple.provenance xattr;
# strip xattrs and sign by hand — same workaround as build-dmg.sh).
APP="$PKGROOT/Applications/$APP_NAME.app"
cp -R "$BUILT_APP" "$APP"
xattr -cr "$APP"
codesign --force --deep --sign - "$APP"
codesign --verify --deep --strict "$APP"

install -m 0755 "$HELPER" "$PKGROOT/usr/local/bin/vpn-helper"
install -m 0644 "$MACOS/io.vpnio.helper.plist" "$PKGROOT/Library/LaunchDaemons/io.vpnio.helper.plist"

echo "==> Building .pkg ($VERSION)"
chmod +x "$MACOS/scripts/preinstall" "$MACOS/scripts/postinstall"

# pkgbuild marks .app bundles relocatable by default, so the installer drops the
# app onto an existing copy elsewhere (e.g. a dev build) instead of
# /Applications. Generate a component plist and turn relocation off so the app
# always installs to Applications/vpn.io.app.
COMPONENT="$DIST/component.plist"
pkgbuild --analyze --root "$PKGROOT" "$COMPONENT" >/dev/null
/usr/libexec/PlistBuddy -c "Set :0:BundleIsRelocatable false" "$COMPONENT"

rm -f "$PKG"
pkgbuild \
  --root "$PKGROOT" \
  --component-plist "$COMPONENT" \
  --scripts "$MACOS/scripts" \
  --identifier "$IDENTIFIER" \
  --version "$VERSION" \
  --install-location / \
  "$PKG"
rm -f "$COMPONENT"

echo "==> Done"
ls -lh "$PKG"
