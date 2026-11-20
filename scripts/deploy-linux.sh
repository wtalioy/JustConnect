#!/bin/bash
# Assemble the portable Linux application tree.
#
# Layout produced (and validated by scripts/verify-package.py):
#   JustConnect/
#     bin/JustConnect bin/JustConnectProxyRecovery bin/qt.conf
#     lib/                 bundled Qt libraries (RUNPATH $ORIGIN)
#     plugins/<category>/  Qt plugins (RUNPATH $ORIGIN/../../lib)
#     libexec/             privileged network helper
#     core-toolchain.txt source-revision.txt licenses/
#
# The sign-in browser is WebKitGTK, a system dependency; nothing bundles a
# browser runtime.
set -euo pipefail

target="${1:?Specify the application name}"
build="${2:?Specify the build directory}"
qt_prefix="${3:?Specify the Qt prefix}"
qt_prefix="${qt_prefix%/}"

for tool in patchelf readelf; do
    command -v "$tool" >/dev/null || { echo "$tool is required to deploy Linux packages" >&2; exit 1; }
done

package="$PWD/$target"
rm -rf "$package"
mkdir -p "$package"

cmake --install "$build" --config Release --component CoreRuntime --prefix "$package"

mkdir -p "$package/lib"

declare -A bundled_libs=()

list_needed() {
    # readelf: " 0x... (NEEDED) Shared library: [libQt6Core.so.6]"; LC_ALL=C pins the field layout.
    LC_ALL=C readelf --dynamic "$1" | awk '$2 == "(NEEDED)" { gsub(/[\[\]]/, "", $5); print $5 }'
}

copy_qt_library() {
    local library="$1"
    local name="${library##*/}"
    if [[ -n "${bundled_libs[$name]:-}" ]]; then
        return 0
    fi
    bundled_libs[$name]=1
    cp -L "$library" "$package/lib/$name"
    local needed
    while IFS= read -r needed; do
        if [[ -f "$qt_prefix/lib/$needed" ]]; then
            copy_qt_library "$qt_prefix/lib/$needed"
        fi
    done < <(list_needed "$library")
}

# Bundle every direct dependency of an object that ships with the Qt SDK;
# anything else is assumed to be a system library.
bundle_object() {
    local needed
    while IFS= read -r needed; do
        if [[ -f "$qt_prefix/lib/$needed" ]]; then
            copy_qt_library "$qt_prefix/lib/$needed"
        fi
    done < <(list_needed "$1")
}

bundle_object "$package/bin/$target"
bundle_object "$package/bin/JustConnectProxyRecovery"

qt_plugins=(
    platforms/libqxcb.so
    platforms/libqwayland.so
    platforms/libqoffscreen.so
    platforminputcontexts/libcomposeplatforminputcontextplugin.so
    platforminputcontexts/libibusplatforminputcontextplugin.so
    imageformats/libqgif.so
    imageformats/libqico.so
    imageformats/libqjpeg.so
    imageformats/libqsvg.so
    imageformats/libqtiff.so
    imageformats/libqwbmp.so
    imageformats/libqwebp.so
    iconengines/libqsvgicon.so
    xcbglintegrations/libqxcb-egl-integration.so
    xcbglintegrations/libqxcb-glx-integration.so
    platformthemes/libqgtk3.so
    platformthemes/libqxdgdesktopportal.so
    tls/libqcertonlybackend.so
    tls/libqopensslbackend.so
)
# Native Wayland sessions need the shell/decoration/graphics client integrations together.
qt_plugin_directories=(wayland-shell-integration wayland-decoration-client wayland-graphics-integration-client)
for plugin in "${qt_plugins[@]}"; do
    if [[ -f "$qt_prefix/plugins/$plugin" ]]; then
        mkdir -p "$package/plugins/${plugin%/*}"
        cp -L "$qt_prefix/plugins/$plugin" "$package/plugins/$plugin"
        bundle_object "$package/plugins/$plugin"
    fi
done
for directory in "${qt_plugin_directories[@]}"; do
    for object in "$qt_prefix/plugins/$directory/"*.so; do
        if [[ -f "$object" ]]; then
            mkdir -p "$package/plugins/$directory"
            cp -L "$object" "$package/plugins/$directory/"
            bundle_object "$package/plugins/$directory/${object##*/}"
        fi
    done
done

# qt.conf next to the executables redirects every Qt search path into the package.
cat > "$package/bin/qt.conf" <<'EOF'
[Paths]
Prefix = ..
Plugins = plugins
LibExecs = libexec
Data = .
Translations = translations
EOF

# Release payloads carry no debug sections: the Go core's DWARF dominates the
# installed size otherwise. --strip-debug keeps dynamic symbols (and the Go
# runtime's pclntab), so the payload still launches and passes the audit.
if command -v strip >/dev/null; then
    while IFS= read -r -d '' object; do
        [ "$(head -c 4 "$object")" = $'\x7fELF' ] && strip --strip-debug "$object"
    done < <(find "$package/bin" "$package/libexec" "$package/lib" "$package/plugins" -type f -print0)
fi

patchelf --set-rpath '$ORIGIN/../lib' \
    "$package/bin/$target" "$package/bin/JustConnectProxyRecovery"
find "$package/lib" "$package/plugins" -name '*.so*' -type f -print0 | while IFS= read -r -d '' object; do
    if [[ "$object" == "$package/lib/"* ]]; then
        patchelf --set-rpath '$ORIGIN' "$object"
    else
        patchelf --set-rpath '$ORIGIN/../../lib' "$object"
    fi
done

# Fail the deployment rather than ship an unresolvable package.
status=0
while IFS= read -r -d '' object; do
    unresolved="$(env -u LD_LIBRARY_PATH LC_ALL=C ldd "$object" | grep 'not found' || true)"
    if [[ -n "$unresolved" ]]; then
        echo "Unresolved dependencies in $object:" >&2
        echo "$unresolved" >&2
        status=1
    fi
done < <(find "$package/bin" "$package/libexec" -maxdepth 1 -type f -executable -print0;
         find "$package/lib" "$package/plugins" -name '*.so*' -type f -print0)
exit "$status"
