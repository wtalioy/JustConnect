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

# Install dependencies
sudo apt-get install -y libxcb-cursor0 fuse

# Download linuxdeploy tools if not present
if [ ! -f linuxdeploy ]; then
    wget -O linuxdeploy "https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-$APPIMAGE_ARCH.AppImage"
fi

if [ ! -f linuxdeploy-plugin-qt ]; then
    wget -O linuxdeploy-plugin-qt "https://github.com/linuxdeploy/linuxdeploy-plugin-qt/releases/download/continuous/linuxdeploy-plugin-qt-$APPIMAGE_ARCH.AppImage"
fi

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

# Add the core after Qt deployment to preserve its recorded binary checksum.
cp "$BUILD_DIR/core/zju-connect" AppDir/usr/bin/
cp -R "$BUILD_DIR/core/core-provenance" AppDir/usr/bin/
python scripts/build-core.py --verify AppDir/usr/bin
NO_STRIP=1 ./linuxdeploy --appdir AppDir --output appimage
