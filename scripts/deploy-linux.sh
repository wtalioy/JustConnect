#!/bin/bash
# Linux deployment script
# Usage: ./scripts/deploy-linux.sh "JustConnect" "JustConnect" "build" "x86_64"

set -euo pipefail

TARGET_NAME="${1:-JustConnect}"
DISPLAY_NAME="${2:-JustConnect}"
BUILD_DIR="${3:-build}"
ARCH="${4:-x86_64}"

# Determine AppImage tool architecture
if [ "$ARCH" = "x86_64" ]; then
    APPIMAGE_ARCH="x86_64"
else
    APPIMAGE_ARCH="aarch64"
fi

# Pin the packaging tools by content; a moved continuous tag must fail closed.
python - "$APPIMAGE_ARCH" <<'PYTOOLS'
import hashlib, json, pathlib, sys, urllib.request
for name, hashes in json.loads(pathlib.Path('scripts/linuxdeploy.json').read_text()).items():
    path = pathlib.Path(name)
    url = f'https://github.com/linuxdeploy/{name}/releases/download/continuous/{name}-{sys.argv[1]}.AppImage'
    contents = path.read_bytes() if path.exists() else urllib.request.urlopen(url, timeout=60).read()
    if hashlib.sha256(contents).hexdigest() != hashes[sys.argv[1]]:
        raise SystemExit(f'{name}: SHA-256 mismatch; review upstream before changing linuxdeploy.json')
    path.write_bytes(contents)
PYTOOLS
export APPIMAGE_EXTRACT_AND_RUN=1

chmod a+x linuxdeploy linuxdeploy-plugin-qt

# Create AppDir structure
mkdir -p AppDir/usr/bin AppDir/usr/lib AppDir/usr/share/applications AppDir/usr/share/icons/hicolor/scalable/apps

# Copy executable
cp "$BUILD_DIR/$TARGET_NAME" AppDir/usr/bin/

# Copy libnss3 libraries (for QtWebEngine in Ubuntu 22.04)
# Ubuntu 24.04 move them to /usr/lib/aarch64-linux-gnu or /usr/lib/x86_64-linux-gnu, so no need to special case them
if [ -d "/usr/lib/$APPIMAGE_ARCH-linux-gnu/nss" ]; then
    cp -R "/usr/lib/$APPIMAGE_ARCH-linux-gnu/nss/" AppDir/usr/lib/
fi

# Copy icon
cp resource/icon.svg "AppDir/usr/share/icons/hicolor/scalable/apps/$TARGET_NAME.svg"

# Create desktop file
cat > "AppDir/usr/share/applications/$TARGET_NAME.desktop" <<EOF
[Desktop Entry]
Name=$DISPLAY_NAME
Exec=$TARGET_NAME
Icon=$TARGET_NAME
Type=Application
Categories=Network;Security;
EOF

# Build AppImage
export EXTRA_QT_PLUGINS="waylandcompositor"
export EXTRA_PLATFORM_PLUGINS="libqwayland.so"
./linuxdeploy --appdir AppDir --plugin qt

cmake --install "$BUILD_DIR" --config Release --component CoreRuntime --prefix "$PWD/AppDir"
NO_STRIP=1 ./linuxdeploy --appdir AppDir --output appimage
