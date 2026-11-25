include_guard(GLOBAL)

# Builds the static privileged Linux network helper and installs it together
# with the polkit action that authorizes it. The helper path baked into the
# client and the polkit annotation must match the installed layout
# <prefix>/libexec/justconnect-network-helper, so the destination stays a flat
# libexec/ (a multiarch-suffix LIBEXECDIR would break the baked annotation).
function(justconnect_linux_network_helper)
    if(NOT DEFINED REVISION OR NOT DEFINED SOURCE_STATE)
        include("${REPO}/cmake/SourceRevision.cmake")
    endif()
    include(GNUInstallDirs)
    set(JUSTCONNECT_HELPER_PATH "${CMAKE_INSTALL_PREFIX}/libexec/justconnect-network-helper")
    # Sources include the nested relative path, so generate the header where
    # that lookup succeeds from the build root include directory.
    configure_file("${REPO}/infrastructure/networkhelper/linux/networkhelperpaths.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/infrastructure/networkhelper/linux/networkhelperpaths.h" @ONLY)
    configure_file("${REPO}/resource/network-helper-linux.policy.in"
        "${CMAKE_CURRENT_BINARY_DIR}/org.justconnect.network-helper.policy" @ONLY)
    file(GLOB LINUX_HELPER_SOURCES CONFIGURE_DEPENDS "${REPO}/infrastructure/networkhelper/linux/helper/*.go")
    list(FILTER LINUX_HELPER_SOURCES EXCLUDE REGEX "_test\\.go$")
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/justconnect-network-helper"
        COMMAND "${CMAKE_COMMAND}" -E env "CGO_ENABLED=0" "GOTOOLCHAIN=local" "GOWORK=off"
            "${GO_EXECUTABLE}" build -mod=readonly -trimpath -buildvcs=false
            "-ldflags=-s -w -X main.revision=${REVISION} -X main.sourceState=${SOURCE_STATE}"
            -o "${CMAKE_CURRENT_BINARY_DIR}/justconnect-network-helper" .
        WORKING_DIRECTORY "${REPO}/infrastructure/networkhelper/linux/helper"
        DEPENDS ${LINUX_HELPER_SOURCES}
            "${REPO}/infrastructure/networkhelper/linux/helper/go.mod"
            "${REPO}/infrastructure/networkhelper/linux/helper/go.sum"
        VERBATIM)
    add_custom_target(JustConnectNetworkHelper
        DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/justconnect-network-helper")
    install(PROGRAMS "${CMAKE_CURRENT_BINARY_DIR}/justconnect-network-helper"
        DESTINATION libexec COMPONENT CoreRuntime)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/org.justconnect.network-helper.policy"
        DESTINATION "${CMAKE_INSTALL_DATADIR}/polkit-1/actions" COMPONENT CoreRuntime)
    # Portable packages ship a root-runnable script at the package root that
    # fixes the helper's ownership after extraction (pkexec refuses user-owned
    # helpers, and extraction recreates libexec/ with the extractor's owner).
    install(PROGRAMS "${REPO}/scripts/setup-network-helper.sh"
        DESTINATION "." COMPONENT CoreRuntime)
endfunction()
