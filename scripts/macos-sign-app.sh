#!/bin/bash
# Usage: ./scripts/macos-sign-app.sh "<app_path>"

set -euo pipefail

APP_PATH="${1:-}"
QTWEBENGINE_PATH="$APP_PATH/Contents/Frameworks/QtWebEngineCore.framework/Helpers/QtWebEngineProcess.app"

if [[ -z "${CODESIGN_IDENTITY:-}" ]]; then
  echo "CODESIGN_IDENTITY is required"
  exit 1
fi

if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "App not found: $APP_PATH"
  exit 1
fi
codesign --verbose --force --options runtime --sign "$CODESIGN_IDENTITY" --entitlements "$QTWEBENGINE_PATH/Contents/Resources/QtWebEngineProcess.entitlements" "$QTWEBENGINE_PATH/Contents/MacOS/QtWebEngineProcess"
read -r MAC_HELPER MAC_HELPER_ID < <(python3 -c 'import json,plistlib; c=json.load(open("resource/network-helper-macos.json")); p=plistlib.load(open("resource/Info.plist","rb")); print(c["executable"],p["CFBundleIdentifier"]+c["service_suffix"])')
codesign --verbose --force --options runtime --identifier "$MAC_HELPER_ID" --sign "$CODESIGN_IDENTITY" "$APP_PATH/Contents/MacOS/$MAC_HELPER"
codesign --verbose --force --options runtime --deep --preserve-metadata=entitlements,identifier --sign "$CODESIGN_IDENTITY" "$APP_PATH"
