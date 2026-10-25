include_guard(GLOBAL)

function(justconnect_mac_helper_layout)
    file(READ "${REPO}/resource/Info.plist" APP_INFO)
    string(REGEX MATCH "<key>CFBundleIdentifier</key>[ \t\r\n]*<string>([^<]+)</string>" ID_MATCH "${APP_INFO}")
    set(JC_MAC_APP_ID "${CMAKE_MATCH_1}")
    file(READ "${REPO}/resource/network-helper-macos.json" LAYOUT)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
        "${REPO}/resource/Info.plist" "${REPO}/resource/network-helper-macos.json")
    string(JSON JC_MAC_HELPER_PROTOCOL GET "${LAYOUT}" protocol)
    string(JSON JC_MAC_HELPER_STORAGE GET "${LAYOUT}" storage_version)
    string(JSON HELPER_SUFFIX GET "${LAYOUT}" service_suffix)
    string(JSON JC_MAC_HELPER_EXECUTABLE GET "${LAYOUT}" executable)
    string(JSON JC_MAC_HELPER_STATE GET "${LAYOUT}" state_directory)
    string(JSON JC_MAC_HELPER_RIGHT GET "${LAYOUT}" authorization_right)
    set(JC_MAC_HELPER_ID "${JC_MAC_APP_ID}${HELPER_SUFFIX}")
    if(NOT JC_MAC_APP_ID MATCHES "^[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)+$"
        OR NOT JC_MAC_HELPER_ID MATCHES "^[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)+$"
        OR NOT JC_MAC_HELPER_EXECUTABLE MATCHES "^[A-Za-z0-9_-]+$"
        OR NOT JC_MAC_HELPER_STATE MATCHES "^/var/db/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$"
        OR NOT JC_MAC_HELPER_RIGHT MATCHES "^[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)+$")
        message(FATAL_ERROR "Invalid fixed macOS network helper layout")
    endif()
    configure_file("${REPO}/infrastructure/networkhelper/macos/networkhelperpaths.h.in" macosnetworkhelperpaths.h @ONLY)
    configure_file("${REPO}/resource/network-helper-macos.plist.in" "${JC_MAC_HELPER_ID}.plist" @ONLY)
    set(JC_MAC_HELPER_PLIST "${JC_MAC_HELPER_ID}.plist" PARENT_SCOPE)
    set(JC_MAC_HELPER_EXECUTABLE "${JC_MAC_HELPER_EXECUTABLE}" PARENT_SCOPE)
endfunction()

function(justconnect_mac_network_helper)
    justconnect_mac_helper_layout()
    add_library(justconnect_macos_network_helper STATIC
        "${REPO}/infrastructure/networkhelper/macos/networkhelperprotocol.cpp"
        "${REPO}/infrastructure/networkhelper/macos/networkhelperstate.cpp"
        "${REPO}/infrastructure/networkhelper/macos/helperauthorization.cpp"
        "${REPO}/infrastructure/networkhelper/macos/helperidentity.cpp"
        "${REPO}/infrastructure/networkhelper/macos/helpertransport.cpp"
        "${REPO}/infrastructure/tundevice/macos/tundevice.cpp"
        "${REPO}/infrastructure/routing/macos/routesnapshot.cpp"
        "${REPO}/infrastructure/routing/macos/tunroutes.cpp"
        "${REPO}/infrastructure/dns/macos/tundns.cpp"
        "${REPO}/infrastructure/tundevice/tundevice.cpp"
        "${REPO}/infrastructure/networkjournal/networkjournal.cpp"
        "${REPO}/infrastructure/process/command.cpp")
    target_include_directories(justconnect_macos_network_helper PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    target_compile_options(justconnect_macos_network_helper PRIVATE -fblocks)
    target_link_libraries(justconnect_macos_network_helper PUBLIC Qt6::Core "-framework Security" "-framework CoreFoundation" "-framework SystemConfiguration")
    add_executable(JustConnectNetworkHelper "${REPO}/infrastructure/networkhelper/macos/networkhelpermain.cpp")
    target_link_libraries(JustConnectNetworkHelper PRIVATE justconnect_macos_network_helper)
    target_compile_options(JustConnectNetworkHelper PRIVATE -fblocks)
    target_compile_definitions(JustConnectNetworkHelper PRIVATE JC_HELPER_REVISION="${REVISION}" JC_HELPER_SOURCE_STATE="${SOURCE_STATE}")
    set_target_properties(justconnect_macos_network_helper JustConnectNetworkHelper PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
    set_target_properties(JustConnectNetworkHelper PROPERTIES OUTPUT_NAME "${JC_MAC_HELPER_EXECUTABLE}" INSTALL_RPATH "@executable_path/../Frameworks")
    install(TARGETS JustConnectNetworkHelper RUNTIME DESTINATION JustConnect.app/Contents/MacOS COMPONENT CoreRuntime)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${JC_MAC_HELPER_PLIST}"
        DESTINATION JustConnect.app/Contents/Library/LaunchDaemons COMPONENT CoreRuntime)
endfunction()
