#!/bin/bash
# Usage: ./scripts/macos-sign-app.sh "<app_path>"

set -euo pipefail

APP_PATH="${1:-}"

if [[ -z "$APP_PATH" || ! -d "$APP_PATH" ]]; then
  echo "App not found: $APP_PATH"
  exit 1
fi
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
p12_password=''
if [[ -n "${JC_MAC_SIGNING_P12:-}" ]]; then
  printf '%s' "$JC_MAC_SIGNING_P12" | python3 -c 'import base64,sys; sys.stdout.buffer.write(base64.b64decode(sys.stdin.buffer.read(),validate=True))' > "$signing_directory/identity.p12"
  unset JC_MAC_SIGNING_P12
else
  p12_password=$password
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
  # Disposable identity for local builds and tests that do not use the packaging workflow.
  /usr/bin/openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -config "$signing_directory/identity.cnf" \
    -keyout "$signing_directory/identity.key" -out "$signing_directory/identity.pem"
  /usr/bin/openssl pkcs12 -export -inkey "$signing_directory/identity.key" -in "$signing_directory/identity.pem" \
    -out "$signing_directory/identity.p12" -passout "pass:$p12_password"
fi
local_identity=$(/usr/bin/openssl pkcs12 -in "$signing_directory/identity.p12" -clcerts -nokeys -passin "pass:$p12_password" \
  | /usr/bin/openssl x509 -noout -fingerprint -sha1 | cut -d= -f2 | tr -d ':')
[[ "$local_identity" =~ ^[0-9A-Fa-f]{40}$ ]]
security create-keychain -p "$password" "$keychain"
security unlock-keychain -p "$password" "$keychain"
security import "$signing_directory/identity.p12" -k "$keychain" -P "$p12_password" -T /usr/bin/codesign
security set-key-partition-list -S apple-tool:,apple:,codesign: -s -k "$password" "$keychain" > /dev/null
# codesign also resolves identities through the user's search list.
python3 - "$keychain" <<'PY'
import shlex, subprocess, sys
current = shlex.split(subprocess.check_output(['security', 'list-keychains', '-d', 'user'], text=True))
subprocess.run(['security', 'list-keychains', '-d', 'user', '-s', *current, sys.argv[1]], check=True)
PY
read -r MAC_HELPER MAC_HELPER_ID < <(python3 -c 'import json,plistlib; c=json.load(open("resource/network-helper-macos.json")); p=plistlib.load(open("resource/Info.plist","rb")); print(c["executable"],p["CFBundleIdentifier"]+c["service_suffix"])')
codesign --verbose --force --options runtime,library --keychain "$keychain" --identifier "$MAC_HELPER_ID" --sign "$local_identity" "$APP_PATH/Contents/MacOS/$MAC_HELPER"
codesign --verbose --force --options runtime,library --keychain "$keychain" --deep --preserve-metadata=entitlements,identifier --sign "$local_identity" "$APP_PATH"
