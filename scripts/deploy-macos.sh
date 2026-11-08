#!/bin/bash
set -euo pipefail

target="${1:?Specify the application name}"
build="${2:?Specify the build directory}"
qt_prefix="${3:?Specify the static Qt prefix}"
app="$target.app"

ditto "$build/$app" "$app"
cmake --install "$build" --config Release --component CoreRuntime --prefix "$PWD"

licenses="$app/Contents/Resources/licenses/Qt"
ditto "$qt_prefix/justconnect-licenses" "$licenses"
cp scripts/build-macos-qt.sh "$licenses/"
