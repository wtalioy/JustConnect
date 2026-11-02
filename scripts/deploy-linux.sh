#!/bin/bash
# Linux deployment script
# Usage: ./scripts/deploy-linux.sh "JustConnect" "JustConnect" "build" "x86_64"

set -euo pipefail

TARGET_NAME="${1:-JustConnect}"
DISPLAY_NAME="${2:-JustConnect}"
BUILD_DIR="${3:-build}"
ARCH="${4:-x86_64}"

case "$ARCH" in
    x86_64|aarch64) APPIMAGE_ARCH="$ARCH" ;;
    arm64) APPIMAGE_ARCH="aarch64" ;;
    *) echo "Unsupported AppImage architecture: $ARCH" >&2; exit 1 ;;
esac

python scripts/linuxdeploy_tools.py "$APPIMAGE_ARCH"
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
cp "$BUILD_DIR/icon.png" "AppDir/$TARGET_NAME.png"
ln -sfn "$TARGET_NAME.png" AppDir/.DirIcon

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
# Use the native toolchain's strip so current ELF relocations remain supported.
NO_STRIP=1 ./linuxdeploy --appdir AppDir --plugin qt
python -c 'from scripts.linuxdeploy_tools import strip_elfs; strip_elfs("AppDir")'

cmake --install "$BUILD_DIR" --config Release --component CoreRuntime --prefix "$PWD/AppDir"
NO_STRIP=1 ./linuxdeploy --appdir AppDir --output appimage
