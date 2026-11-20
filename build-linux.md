# Building on Linux

## Install build dependencies

Use a C++17 compiler, CMake 3.20 or later, Qt 6.8 or later, and the exact Go version in [corelib/go.mod](corelib/go.mod). The sign-in browser requires WebKitGTK 4.1 and X11 development packages. OpenSSL development headers enable support for custom gateway CAs.

On Debian 13, install the Go toolchain separately and use APT for the remaining dependencies.

```sh
sudo apt install build-essential cmake git ninja-build pkg-config \
  qt6-base-dev qt6-svg-dev qt6-tools-dev qt6-l10n-tools qt6-translations-l10n \
  libgl1-mesa-dev libegl-dev libxkbcommon-dev libfontconfig1-dev \
  libwebkit2gtk-4.1-dev libx11-dev libssl-dev xvfb xauth
```

If your distribution ships an older Qt, install a Qt SDK with Widgets, SVG, and Linguist Tools. Pass its installation directory to CMake with `-DCMAKE_PREFIX_PATH`.

## Build and test

From the repository root, with the pinned Go toolchain on `PATH`:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
cmake --build build --parallel 3
xvfb-run -a ctest --test-dir build --output-on-failure
```

Run `./build/JustConnect` to try the build in **Local proxy only** mode. Automatic routing needs the helper installed in a root-owned system directory. The Debian package below sets that up, including the polkit policy. See the [Linux runtime requirements](README.md#linux-requirements) for both modes.

## Build a Debian package

On an x64 host with Docker, run the [build script used by CI](scripts/build-debian-package.sh) in a Debian 13 container. The script installs its own build dependencies.

```sh
docker run --rm -v "$PWD":/justconnect -w /justconnect debian:13 \
  bash scripts/build-debian-package.sh "" justconnect.deb
sudo apt install ./justconnect.deb
```
