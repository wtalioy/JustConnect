#!/bin/bash
# macOS deployment script
# Usage: ./scripts/deploy-macos.sh "JustConnect" "build" "amd64" "false"

set -euo pipefail

TARGET_NAME="${1:-JustConnect}"
BUILD_DIR="${2:-build}"
ARCH="${3:-arm64}"
NIGHTLY="${4:-false}"
APP_PATH="$TARGET_NAME.app"

# Copy app bundle
cp -R "$BUILD_DIR/$TARGET_NAME.app" .

# Download and extract core
CORE_ARCH="${ARCH}"
if [ "$ARCH" = "x86_64" ]; then
    CORE_ARCH="amd64"
fi

CORE_RELEASE_PATH="latest/download"
if [ "$NIGHTLY" = "true" ]; then
    CORE_RELEASE_PATH="download/nightly"
fi

curl -LO "https://github.com/Mythologyli/zju-connect/releases/$CORE_RELEASE_PATH/zju-connect-darwin-$CORE_ARCH.zip"
unzip -o "zju-connect-darwin-$CORE_ARCH.zip"
rm "zju-connect-darwin-$CORE_ARCH.zip"

# Copy core into app bundle
cp zju-connect "$APP_PATH/Contents/MacOS/"
"$APP_PATH/Contents/MacOS/zju-connect" -version

# Run macdeployqt
macdeployqt "$APP_PATH"

# Reduce bundle size by stripping unused slices from universal Mach-O binaries.
thinned_count=0
before_size=0
after_size=0
while IFS= read -r -d '' binary; do
    file_output="$(file "$binary")"
    if [[ "$file_output" != *"Mach-O universal binary"* ]]; then
        continue
    fi

    lipo_info="$(lipo -info "$binary" 2>/dev/null || true)"
        if [[ "$lipo_info" != *"$ARCH"* ]]; then
            echo "Skipping universal binary without $ARCH slice: $binary" >&2
            continue
        fi

        original_mode="$(stat -f%Lp "$binary")"
        thin_output="$(mktemp)"
        lipo "$binary" -thin "$ARCH" -output "$thin_output"
        chmod "$original_mode" "$thin_output"
        mv "$thin_output" "$binary"

done < <(find "$APP_PATH" -type f -print0)

# macdeployqt has a bug that it doesn't copy the Qt translations to the bundle
# so we need to copy them manually
QT_TRANSLATIONS=$(qmake -query QT_INSTALL_TRANSLATIONS)
mkdir -p "$APP_PATH/Contents/translations"
if [ -d "$QT_TRANSLATIONS" ]; then
    cp -R "$QT_TRANSLATIONS"/qtbase_*.qm "$APP_PATH/Contents/translations"
fi
