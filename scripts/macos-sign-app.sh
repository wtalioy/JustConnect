#!/bin/bash
# Usage: ./scripts/macos-sign-app.sh "<app_path>"

set -euo pipefail

APP_PATH="${1:-}"
QTWEBENGINE_PATH="$APP_PATH/Contents/Frameworks/QtWebEngineCore.framework/Helpers/QtWebEngineProcess.app"

if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "App not found: $APP_PATH"
  exit 1
fi
signing_args=()
if [[ -z "${CODESIGN_IDENTITY:-}" || "$CODESIGN_IDENTITY" == '-' ]]; then
  signing_directory=$(mktemp -d)
  keychain="$signing_directory/local.keychain-db"
  cleanup() {
    local status=$?
    if [[ -f "$keychain" ]]; then security delete-keychain "$keychain" || status=1; fi
    rm -rf -- "$signing_directory"
    exit "$status"
  }
  trap cleanup EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  password=$(uuidgen)
  cat > "$signing_directory/identity.cnf" <<'EOF'
[req]
distinguished_name=dn
x509_extensions=extensions
prompt=no
[dn]
CN=JustConnect local build
[extensions]
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature
extendedKeyUsage=codeSigning
EOF
  # A per-build leaf binds the app/helper; it is not a public publisher identity or trust anchor.
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -config "$signing_directory/identity.cnf" \
    -keyout "$signing_directory/identity.key" -out "$signing_directory/identity.pem"
  openssl pkcs12 -export -inkey "$signing_directory/identity.key" -in "$signing_directory/identity.pem" \
    -out "$signing_directory/identity.p12" -passout "pass:$password"
  security create-keychain -p "$password" "$keychain"
  security unlock-keychain -p "$password" "$keychain"
  security import "$signing_directory/identity.p12" -k "$keychain" -P "$password" -T /usr/bin/codesign
  security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" > /dev/null
  CODESIGN_IDENTITY=$(openssl x509 -in "$signing_directory/identity.pem" -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
  signing_args=(--keychain "$keychain")
fi
codesign --verbose --force --options runtime "${signing_args[@]}" --sign "$CODESIGN_IDENTITY" --entitlements "$QTWEBENGINE_PATH/Contents/Resources/QtWebEngineProcess.entitlements" "$QTWEBENGINE_PATH/Contents/MacOS/QtWebEngineProcess"
read -r MAC_HELPER MAC_HELPER_ID < <(python3 -c 'import json,plistlib; c=json.load(open("resource/network-helper-macos.json")); p=plistlib.load(open("resource/Info.plist","rb")); print(c["executable"],p["CFBundleIdentifier"]+c["service_suffix"])')
codesign --verbose --force --options runtime "${signing_args[@]}" --identifier "$MAC_HELPER_ID" --sign "$CODESIGN_IDENTITY" "$APP_PATH/Contents/MacOS/$MAC_HELPER"
codesign --verbose --force --options runtime "${signing_args[@]}" --deep --preserve-metadata=entitlements,identifier --sign "$CODESIGN_IDENTITY" "$APP_PATH"
