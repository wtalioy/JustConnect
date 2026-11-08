#!/bin/bash
set -euo pipefail

prefix="${1:?Specify the Qt installation prefix}"
architecture="${2:?Specify arm64 or x86_64}"
version=6.12.0
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT
cd "$work"

download_module() {
  local archive="$1-everywhere-src-$version.tar.xz"
  curl --fail --location --retry 2 --silent --show-error --output "$archive" \
    "https://download.qt.io/official_releases/qt/${version%.*}/$version/submodules/$archive"
  printf '%s  %s\n' "$2" "$archive" | shasum -a 256 --check
  tar -xf "$archive"
}

download_module qtbase a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307
download_module qtsvg e4ab39534ec97987b1b9b60ef7f4d3253d5912a69f8c713a01753174a4029331

mkdir base svg
cd base
"$work/qtbase-everywhere-src-$version/configure" \
  -prefix "$prefix" -release -static -opensource -confirm-license \
  -nomake examples -nomake tests -no-feature-dbus -no-feature-openssl \
  -qt-zlib -qt-libpng -qt-libjpeg -qt-freetype -qt-pcre -qt-harfbuzz \
  -- -DCMAKE_OSX_ARCHITECTURES="$architecture" -DCMAKE_OSX_DEPLOYMENT_TARGET=14.4
cmake --build . --parallel "$(sysctl -n hw.logicalcpu)"
cmake --install .

mkdir -p "$prefix/justconnect-licenses"
for module in qtbase qtsvg; do
  cp -R "$work/$module-everywhere-src-$version/LICENSES" "$prefix/justconnect-licenses/$module"
done

cd "$work/svg"
"$prefix/bin/qt-configure-module" "$work/qtsvg-everywhere-src-$version" \
  -- -DCMAKE_BUILD_TYPE=Release
cmake --build . --parallel "$(sysctl -n hw.logicalcpu)"
cmake --install .
