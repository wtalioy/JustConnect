#!/bin/bash
set -euo pipefail

cmake -S tests/coreabi -B build/coreabi -DCMAKE_BUILD_TYPE=Release
cmake --build build/coreabi --config Release --parallel 3 --target macos_networkhelper_client_test macos_tundns_test macos_tunroutes_test
sudo env GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_OS="$RUNNER_OS" build/coreabi/macos_tundns_test --isolated 2>&1 | tee build/coreabi/macos-tun-dns.log
sudo env GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_OS="$RUNNER_OS" build/coreabi/macos_tunroutes_test --isolated 2>&1 | tee build/coreabi/macos-tun-routes.log
read -r helper_id helper_executable < <(python -c 'import json,plistlib; c=json.load(open("resource/network-helper-macos.json")); p=plistlib.load(open("resource/Info.plist","rb")); print(p["CFBundleIdentifier"]+c["service_suffix"],c["executable"])')
sudo env PYTHONDONTWRITEBYTECODE=1 GITHUB_ACTIONS="$GITHUB_ACTIONS" RUNNER_OS="$RUNNER_OS" \
    "$(command -v python)" tests/platform/networkhelper_macos.py --uid "$(id -u)" \
    --helper "build/coreabi/$helper_executable" --client build/coreabi/macos_networkhelper_client_test \
    --plist "build/coreabi/$helper_id.plist" --deploy-tool "$(command -v macdeployqt)" \
    --revision "$GITHUB_SHA" --dns-probe build/coreabi/macos_tundns_test \
    --output build/coreabi/macos-helper 2>&1 | tee build/coreabi/macos-helper.log
