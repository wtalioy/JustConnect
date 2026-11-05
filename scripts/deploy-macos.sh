#!/bin/bash
# macOS deployment script
# Usage: ./scripts/deploy-macos.sh "JustConnect" "build" "arm64"

set -euo pipefail

TARGET_NAME="${1:-JustConnect}"
BUILD_DIR="${2:-build}"
ARCH="${3:-arm64}"
APP_PATH="$TARGET_NAME.app"

# Copy app bundle
cp -R "$BUILD_DIR/$TARGET_NAME.app" .

cmake --install "$BUILD_DIR" --config Release --component CoreRuntime --prefix "$PWD"

# Run macdeployqt
MAC_HELPER="$(python3 -c 'import json; print(json.load(open("resource/network-helper-macos.json"))["executable"])')"
macdeployqt "$APP_PATH" "-executable=$APP_PATH/Contents/MacOS/JustConnectProxyRecovery" \
    "-executable=$APP_PATH/Contents/MacOS/$MAC_HELPER"

# Reduce bundle size by stripping unused slices from universal Mach-O binaries.
while IFS= read -r -d '' binary; do
    file_output="$(file "$binary")"
    if [[ "$file_output" != *"Mach-O universal binary"* ]]; then
        continue
    fi

    lipo_info="$(lipo -info "$binary" 2>/dev/null || true)"
        if [[ "$lipo_info" != *"$ARCH"* ]]; then
            echo "Missing $ARCH slice: $binary" >&2
            exit 1
        fi

        original_mode="$(stat -f%Lp "$binary")"
        thin_output="$(mktemp)"
        lipo "$binary" -thin "$ARCH" -output "$thin_output"
        chmod "$original_mode" "$thin_output"
        mv "$thin_output" "$binary"

done < <(find "$APP_PATH" -type f -print0)
