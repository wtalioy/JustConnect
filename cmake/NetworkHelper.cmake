function(justconnect_linux_network_helper)
    # Both development probes and the distribution package compile this one implementation.
    add_library(justconnect_network_helper STATIC
        "${REPO}/infrastructure/platform/linux/networkhelper.cpp"
        "${REPO}/infrastructure/platform/linux/trustedexecutable.cpp"
        "${REPO}/infrastructure/platform/linux/sourcejournal.cpp"
        "${REPO}/infrastructure/platform/linux/ownedroutetable.cpp"
        "${REPO}/infrastructure/platform/linux/tunroutes.cpp"
        "${REPO}/infrastructure/platform/linux/tundns.cpp"
        "${REPO}/infrastructure/platform/linux/tundevice.cpp"
        "${REPO}/infrastructure/platform/tundevice.cpp"
        "${REPO}/infrastructure/platform/platformcommand.cpp")
    target_include_directories(justconnect_network_helper PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(justconnect_network_helper PUBLIC Qt6::Core Qt6::DBus)
    add_executable(JustConnectNetworkHelper "${REPO}/infrastructure/platform/linux/networkhelpermain.cpp")
    target_link_libraries(JustConnectNetworkHelper PRIVATE justconnect_network_helper)
    target_compile_definitions(JustConnectNetworkHelper PRIVATE
        JC_HELPER_REVISION="${REVISION}" JC_HELPER_SOURCE_STATE="${SOURCE_STATE}")
    set_target_properties(justconnect_network_helper JustConnectNetworkHelper PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
    # The installed helper loads distribution libraries; no SDK/AppImage search path survives installation.
    set_target_properties(JustConnectNetworkHelper PROPERTIES INSTALL_RPATH "")
    file(READ "${REPO}/resource/network-helper.json" HELPER_LAYOUT)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${REPO}/resource/network-helper.json")
    string(JSON JC_NETWORK_HELPER_PROTOCOL GET "${HELPER_LAYOUT}" protocol)
    string(JSON JC_NETWORK_HELPER_STORAGE_VERSION GET "${HELPER_LAYOUT}" storage_version)
    if(NOT JC_NETWORK_HELPER_PROTOCOL MATCHES "^[1-9][0-9]*$"
        OR NOT JC_NETWORK_HELPER_STORAGE_VERSION MATCHES "^[1-9][0-9]*$")
        message(FATAL_ERROR "Invalid Linux helper protocol or storage version")
    endif()
    string(JSON JC_NETWORK_HELPER_PATH GET "${HELPER_LAYOUT}" executable)
    string(JSON JC_NETWORK_HELPER_ACTION GET "${HELPER_LAYOUT}" action)
    string(JSON JC_NETWORK_HELPER_AUTHORIZATION GET "${HELPER_LAYOUT}" authorization_program)
    string(JSON JC_NETWORK_HELPER_STATE GET "${HELPER_LAYOUT}" state_directory)
    string(JSON JC_NETWORK_HELPER_RECOVERY_UNIT GET "${HELPER_LAYOUT}" recovery_unit)
    string(JSON JC_NETWORK_HELPER_SYSTEMCTL GET "${HELPER_LAYOUT}" systemctl_program)
    if(NOT JC_NETWORK_HELPER_PATH MATCHES "^/usr/libexec/[A-Za-z0-9._-]+$"
        OR NOT JC_NETWORK_HELPER_AUTHORIZATION MATCHES "^/usr/bin/[A-Za-z0-9._-]+$"
        OR NOT JC_NETWORK_HELPER_SYSTEMCTL MATCHES "^/usr/bin/[A-Za-z0-9._-]+$"
        OR NOT JC_NETWORK_HELPER_RECOVERY_UNIT MATCHES "^[A-Za-z0-9_-]+$")
        message(FATAL_ERROR "Invalid fixed Linux helper program or recovery unit")
    endif()
    if(NOT JC_NETWORK_HELPER_STATE MATCHES "^/var/lib/[A-Za-z0-9_-]+/[A-Za-z0-9_-]+$"
        OR NOT JC_NETWORK_HELPER_ACTION MATCHES "^[A-Za-z0-9_-]+([.][A-Za-z0-9_-]+)+$")
        message(FATAL_ERROR "Invalid fixed Linux helper layout")
    endif()
    get_filename_component(HELPER_FILENAME "${JC_NETWORK_HELPER_PATH}" NAME)
    string(REGEX REPLACE "^/var/lib/" "" JC_NETWORK_HELPER_STATE_RELATIVE "${JC_NETWORK_HELPER_STATE}")
    get_filename_component(JC_NETWORK_HELPER_STATE_PARENT "${JC_NETWORK_HELPER_STATE_RELATIVE}" DIRECTORY)
    set_target_properties(JustConnectNetworkHelper PROPERTIES OUTPUT_NAME "${HELPER_FILENAME}")
    configure_file("${REPO}/infrastructure/platform/linux/networkhelperpaths.h.in" networkhelperpaths.h @ONLY)
    configure_file("${REPO}/resource/network-helper.policy.in" "${JC_NETWORK_HELPER_ACTION}.policy" @ONLY)
    foreach(KIND service timer)
        configure_file("${REPO}/resource/network-helper-recovery.${KIND}.in" "${JC_NETWORK_HELPER_RECOVERY_UNIT}.${KIND}" @ONLY)
        install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${JC_NETWORK_HELPER_RECOVERY_UNIT}.${KIND}"
            DESTINATION lib/systemd/system COMPONENT LinuxNetworkHelper)
    endforeach()
    install(TARGETS JustConnectNetworkHelper RUNTIME DESTINATION libexec COMPONENT LinuxNetworkHelper)
    install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${JC_NETWORK_HELPER_ACTION}.policy"
        DESTINATION share/polkit-1/actions COMPONENT LinuxNetworkHelper)
endfunction()

function(justconnect_linux_network_helper_tests)
    add_executable(linux_networkhelper_test "${REPO}/tests/platform/networkhelper_linux_test.cpp")
    target_link_libraries(linux_networkhelper_test PRIVATE justconnect_network_helper)
    add_dependencies(linux_networkhelper_test JustConnectNetworkHelper)
    set_target_properties(linux_networkhelper_test PROPERTIES AUTOMOC OFF AUTOUIC OFF AUTORCC OFF)
    add_test(NAME linux_networkhelper_test COMMAND linux_networkhelper_test)
    set_tests_properties(linux_networkhelper_test PROPERTIES TIMEOUT 10)
endfunction()
