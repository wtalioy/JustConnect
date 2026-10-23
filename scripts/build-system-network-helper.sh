#!/bin/bash
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
output=${1:?Usage: build-system-network-helper.sh BUILD_DIRECTORY}
# The GUI SDK must not affect qmake's reported prefix, CMake discovery or shlibdeps.
unset CMAKE_PREFIX_PATH CMAKE_MODULE_PATH QT_ROOT_DIR QTDIR QT_HOST_PATH QT_PLUGIN_PATH QMAKEPATH QMAKEFEATURES
unset PKG_CONFIG_PATH PKG_CONFIG_LIBDIR
unset Qt6_ROOT Qt6_DIR Qt6Core_DIR Qt6CoreTools_DIR LD_LIBRARY_PATH LD_PRELOAD
export LC_ALL=C.UTF-8
qt_libraries=$(/usr/bin/qmake6 -query QT_INSTALL_LIBS)

cmake -S "$repo/infrastructure/platform/linux/helper" -B "$output" -DCMAKE_BUILD_TYPE=Release \
    "-DCMAKE_PREFIX_PATH=$qt_libraries/cmake" \
    "-DQt6_DIR=$qt_libraries/cmake/Qt6" "-DQt6Core_DIR=$qt_libraries/cmake/Qt6Core" \
    "-DQt6CoreTools_DIR=$qt_libraries/cmake/Qt6CoreTools"
cmake --build "$output" --parallel 3
ctest --test-dir "$output" --output-on-failure
cpack --config "$output/CPackConfig.cmake" -B "$output"
