#!/bin/bash
# Build the Debian package against Debian 13 (trixie) system libraries.
#
# The package declares system Qt/WebKitGTK as dependencies, so it must be
# built against those libraries instead of the portable Qt SDK. This script
# runs inside a debian:13 container with the repository mounted at $PWD;
# scripts/package-deb.sh keeps staging the payload and the declared
# dependency floors match the libraries installed here.
#
# Usage (from the repository root, on the host):
#   docker run --rm -v "$PWD":/justconnect -w /justconnect debian:13 \
#     bash scripts/build-debian-package.sh [version] [output.deb] [release-date]
set -euo pipefail

version="${1:-}"
output="${2:-justconnect.deb}"
release_date="${3:-}"

apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl git cmake ninja-build g++ dpkg-dev patchelf \
    qt6-base-dev qt6-svg-dev qt6-tools-dev qt6-l10n-tools qt6-translations-l10n \
    libgl1-mesa-dev libegl-dev libxkbcommon-dev libfontconfig1-dev \
    libwebkit2gtk-4.1-dev libssl-dev libx11-dev

# The core and the network helper pin their Go toolchain version in go.mod.
go_version="$(awk '/^go /{print $2; exit}' corelib/go.mod)"
curl -fsSL "https://go.dev/dl/go${go_version}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz
export PATH="/usr/local/go/bin:$PATH" GOTOOLCHAIN=local GOWORK=off CGO_ENABLED=1

# The container runs as root while the checkout belongs to the runner user.
git config --global --add safe.directory "$PWD"
revision="$(git rev-parse --short=7 HEAD)"
if [[ -z "$version" ]]; then
    version="0.0.0~git$revision"
    version_args=(-DNIGHTLY_BUILD=ON "-DGIT_HASH=$revision")
else
    version="${version#v}"
    version_args=(-DNIGHTLY_BUILD=OFF "-DREL_VER=$version" "-DREL_DATE=$release_date")
fi

cmake -S . -B build-deb -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=OFF "${version_args[@]}"
cmake --build build-deb --config Release --parallel "${CMAKE_BUILD_PARALLEL_LEVEL:-3}"
./scripts/package-deb.sh build-deb "$output" "$version"
rm -rf build-deb
