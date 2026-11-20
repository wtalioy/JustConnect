# Building on Linux

Build and test JustConnect on Debian 13 x64, then optionally turn the same build into a `.deb`. Run the commands from the repository root.

## Install build dependencies

Install the exact Go version in [corelib/go.mod](corelib/go.mod) and put it on `PATH`. Use APT for the remaining dependencies.

```sh
sudo apt update
sudo apt install build-essential cmake git ninja-build pkg-config python3 \
  qt6-base-dev qt6-svg-dev qt6-tools-dev qt6-l10n-tools qt6-translations-l10n \
  libgl1-mesa-dev libegl-dev libxkbcommon-dev libfontconfig1-dev \
  libwebkit2gtk-4.1-dev libx11-dev libssl-dev xvfb xauth
```

For other distributions, use the equivalent packages and Qt 6.8 or later. If you install the Qt SDK separately, pass its directory to CMake with `-DCMAKE_PREFIX_PATH`. The `.deb` below is built against Debian 13 system libraries.

## Build and test

Set the install prefix to `/usr` so the compiled-in helper path matches the Debian package layout.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_TESTING=ON
cmake --build build --parallel 3
xvfb-run -a ctest --test-dir build --output-on-failure
```

Run `./build/JustConnect` to try **Local proxy only**. The package in the next step installs the network helper and polkit policy for **Automatic routing**. See the [Linux runtime requirements](README.md#linux-requirements).

## Package and install

On Debian 13 x64, package the `build` directory from the previous step.

```sh
./scripts/package-deb.sh build justconnect.deb "0.0.0~git$(git rev-parse --short=7 HEAD)"
sudo apt install ./justconnect.deb
```
