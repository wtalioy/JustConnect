# Building JustConnect on Linux

Linux supports both routing modes. **Automatic routing** creates a TUN device
through a privileged helper (`justconnect-network-helper`): once per
application start, polkit (`pkexec`) asks for the administrator password, and
the helper installs campus routes plus split DNS for the lifetime of the
session. Split DNS needs an active systemd-resolved; hosts that resolve names
another way are reported before connecting and automatic mode stays
unavailable. **Local proxy only** needs no privileges. See [runtime notes](#runtime-notes) for desktop and keyring requirements.

## Prerequisites

| Tool | Version | Notes |
| --- | --- | --- |
| GCC / Clang + binutils | any recent | C++17, cgo compiler |
| CMake | 3.20+ | Ninja recommended |
| Qt | 6.8+ | `Core` `Concurrent` `Gui` `Widgets` `Network` `Svg` plus `LinguistTools`; CI and the reference SDK use 6.12.0 |
| WebKitGTK 4.1 | any | the Linux sign-in browser; `pkg-config` must resolve `webkit2gtk-4.1` and `x11` |
| OpenSSL dev | any | optional — without it the sign-in browser cannot trust custom campus CAs and fails closed |
| Go | **exactly** the version pinned in `corelib/go.mod` | the build sets `GOTOOLCHAIN=local` and rejects other versions |
| Python 3 | 3.9+ | packaging/verification helpers |
| patchelf | any | only needed for the portable tarball |
| dpkg-dev | any | only needed for the Debian package (`dpkg-deb`) |

On Ubuntu 24.04, install Qt 6.8 or later from the Qt SDK. The portable build targets Ubuntu 24.04. The Debian package uses Debian 13 system libraries.

### Distribution packages

```sh
sudo apt-get install -y build-essential cmake ninja-build python3 pkg-config \
  libgl1-mesa-dev libegl-dev libxkbcommon-dev libfontconfig1-dev \
  libx11-dev libssl-dev libwebkit2gtk-4.1-dev
```

The sign-in browser links WebKitGTK and drives X11 embedding directly
(`libwebkit2gtk-4.1-dev`, `libx11-dev`); `libssl-dev` enables the custom
campus-CA anchor check. The QtWebEngine-era package list (`libnss3-dev`,
`libxcomposite-dev`, `libatspi2.0-dev`, …) is no longer needed to build — the
application does not link `WebEngineWidgets`.

### Qt SDK

Use [aqtinstall](https://github.com/miurahr/aqtinstall) or the Qt online
installer. The SDK needs the default widget archives — the application links
`Core Concurrent Gui Widgets Network Svg` plus `LinguistTools`, and
`qtdeclarative` is only needed because the SDK's `lrelease` binary links
QtQml (the application itself does not):

```sh
python3 -m pip install aqtinstall
aqt install-qt linux desktop 6.12.0 linux_gcc_64 -O ~/Qt
```

> aqt's architecture name is `linux_gcc_64` (new-style naming); the SDK still
> unpacks into `~/Qt/6.12.0/gcc_64`.

### Go

Install the exact Go version from `corelib/go.mod` (currently **1.27.2**),
e.g. from <https://go.dev/dl/>. `GOTOOLCHAIN=local` is enforced by the build,
so a newer Go installed locally will be rejected.

## Configure, build, test

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON \
  -DCMAKE_PREFIX_PATH="$HOME/Qt/6.12.0/gcc_64"
cmake --build build
```

Run the test suite in an X11 session or with Xvfb for the WebKitGTK sign-in browser checks.

```sh
xvfb-run -a ctest --test-dir build --output-on-failure
```

## Install

A system install places the binary, the system-proxy recovery worker, the
desktop entry and the icon into the usual GNU directories:

```sh
sudo cmake --install build --prefix /usr/local
```

`JustConnectProxyRecovery` restores gsettings proxy state after crashes; it
needs no extra privileges on Linux.

### Privileged network helper (automatic routing)

`cmake --install` also places the privileged helper into
`<prefix>/libexec/justconnect-network-helper` (mode 0755, owned by root when
run under sudo) and the polkit action into
`<prefix>/share/polkit-1/actions/org.justconnect.network-helper.policy`.
polkit only reads actions from the directories it was built with, so make sure
the policy ends up in one of them (on most distributions
`/usr/share/polkit-1/actions`):

```sh
sudo cmake --install build --prefix /usr/local
sudo install -D -o root -g root -m 0644 \
    /usr/local/share/polkit-1/actions/org.justconnect.network-helper.policy \
    /usr/share/polkit-1/actions/
```

`pkexec` refuses to execute programs it does not own, so the helper must stay
root-owned and not group- or world-writable, and only the installed copy at
the annotated system path is ever elevated. The application checks this up
front: when no usable helper is found, automatic routing is reported as
unavailable with a diagnostic that names the system path and the installer
(the same steps appear on the server settings page) instead of failing after
the password prompt.

## Package (Debian)

Build with Debian 13 system libraries. The same script runs in CI for both
previews and releases.

```sh
docker run --rm -v "$PWD":/justconnect -w /justconnect debian:13 \
  bash scripts/build-debian-package.sh "" justconnect.deb
```

Install with `sudo apt install ./justconnect.deb`. APT installs the runtime
libraries, including Qt and WebKitGTK. The package installs the root-owned
helper and its polkit action. CI verifies the package in a fresh Debian 13
container before uploading it.

## Package (portable tarball)

The shipped Linux artifact is a portable, self-contained tree with bundled
Qt libraries and plugins. Sign-in additionally needs the system
`libwebkit2gtk-4.1` runtime (standard on desktop distributions):

```sh
./scripts/deploy-linux.sh JustConnect build "$HOME/Qt/6.12.0/gcc_64"
tar --sort=name --owner=0 --group=0 --numeric-owner -czf justconnect-linux-x64.tar.gz JustConnect
```

Users extract the tarball and run `bin/JustConnect`. **Automatic routing**
additionally needs the helper installed into a root-owned system directory:
`pkexec` refuses user-owned files, and the application only elevates the
installed copy at the annotated system path — a helper inside the extracted
tree is never launched. The package ships a `setup-network-helper.sh` script
at its root that performs the install:

```sh
sudo ./setup-network-helper.sh   # helper to /usr/local/libexec plus the polkit action
```

The install is one-time and survives re-extraction; rerun it after replacing
the package to pick up a newer helper. The script is equivalent to:

```sh
sudo install -D -o root -g root -m 0755 \
    JustConnect/libexec/justconnect-network-helper /usr/local/libexec/justconnect-network-helper
sudo install -D -o root -g root -m 0644 \
    JustConnect/share/polkit-1/actions/org.justconnect.network-helper.policy \
    /usr/share/polkit-1/actions/
```

The policy annotation names the helper path recorded at build time; when it
does not match where `pkexec` actually runs the helper from, polkit falls back
to its default `auth_admin` prompt with a generic message — authorization
still works, only the prompt text is less specific.

The deploy script fails rather than ships an unresolvable package (every ELF
is checked with `ldd`); `scripts/verify-package.py` is what CI runs against
the final archive — it exercises the offline core self-test, the recovery
worker, the sign-in browser probe and the privileged network helper inside
the extracted tree.

## Runtime notes

- **System proxy** integration drives gsettings/dconf (`org.gnome.system.proxy`).
  It applies when a compatible desktop session is present; without one, the
  backend reports unsupported and local proxy keeps working.
- **Credential storage** uses a Secret Service keyring through libsecret.
  Without a usable keyring, saved sign-ins stay in the running app's memory.
- **DNS for automatic routing** installs per-link split DNS on an active
  systemd-resolved only; there is no plain `resolv.conf` fallback.
- **Autostart** writes an XDG autostart entry under `$XDG_CONFIG_HOME`.
- **SSO sign-in browser** embeds WebKitGTK through X11, so Wayland sessions
  run it via XWayland. It needs `libwebkit2gtk-4.1` at runtime — the Debian
  package declares it, and desktop distributions ship it.
- Wayland sessions run through XWayland (the packaged Qt build ships the xcb
  platform plugin).
