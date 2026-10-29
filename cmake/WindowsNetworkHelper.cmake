function(justconnect_windows_helper_layout)
    set(CONTRACT "${REPO}/resource/network-helper-windows.json")
    file(READ "${CONTRACT}" LAYOUT)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CONTRACT}")
    string(JSON WINDOWS_STATE_REGISTRY GET "${LAYOUT}" state_registry)
    string(REPLACE "\\" "\\\\" WINDOWS_STATE_REGISTRY "${WINDOWS_STATE_REGISTRY}")
    string(JSON WINDOWS_MAX_RECORD_BYTES GET "${LAYOUT}" max_record_bytes)
    foreach(FIELD IN ITEMS executable driver_library driver_license install_directory service ownership_mutex control_pipe_prefix packet_pipe_prefix)
        string(TOUPPER "${FIELD}" VARIABLE)
        string(JSON WINDOWS_${VARIABLE} GET "${LAYOUT}" "${FIELD}")
        string(REPLACE "\\" "\\\\" WINDOWS_${VARIABLE} "${WINDOWS_${VARIABLE}}")
    endforeach()
    string(JSON WINDOWS_STORAGE_VERSION GET "${LAYOUT}" storage_version)
    foreach(FIELD IN ITEMS protocol control_timeout_ms max_message_bytes)
        string(TOUPPER "${FIELD}" VARIABLE)
        string(JSON WINDOWS_${VARIABLE} GET "${LAYOUT}" "${FIELD}")
    endforeach()
    configure_file("${REPO}/infrastructure/networkhelper/windows/networkcontract.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/windowsnetworkcontract.h" @ONLY)
    set(WINDOWS_EXECUTABLE "${WINDOWS_EXECUTABLE}" PARENT_SCOPE)
endfunction()

function(justconnect_windows_network_helper TARGET)
    if(NOT DEFINED REVISION)
        include("${REPO}/cmake/SourceRevision.cmake")
    endif()
    justconnect_windows_helper_layout()
    include("${REPO}/cmake/WindowsDevice.cmake")
    justconnect_windows_device(${TARGET}_device)
    add_library(${TARGET}_support STATIC
        "${REPO}/infrastructure/process/windows/identity.cpp"
        "${REPO}/infrastructure/networkhelper/windows/installation.cpp"
        "${REPO}/infrastructure/networkhelper/windows/recovery.cpp"
        "${REPO}/infrastructure/networkhelper/windows/service.cpp"
        "${REPO}/infrastructure/networkhelper/windows/control.cpp"
        "${REPO}/infrastructure/networkhelper/windows/controlwire.cpp"
        "${REPO}/infrastructure/networkhelper/windows/session.cpp"
        "${REPO}/infrastructure/networkhelper/windows/packetrelay.cpp"
        "${REPO}/infrastructure/packetpipe/windows/stream.cpp"
        "${REPO}/infrastructure/tundevice/windows/recovery.cpp"
        "${REPO}/infrastructure/dns/windows/nrpt.cpp"
        "${REPO}/infrastructure/dns/windows/dnsreader.cpp"
        "${REPO}/infrastructure/networkjournal/windows/registry.cpp")
    target_include_directories(${TARGET}_support PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    # Current Windows SDK projections use the standard coroutine headers.
    target_compile_features(${TARGET}_support PUBLIC cxx_std_20)
    target_compile_definitions(${TARGET}_support PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00 PRIVATE JC_DNS_READER_LIBRARY)
    target_link_libraries(${TARGET}_support PUBLIC ${TARGET}_device advapi32 ole32 windowsapp ws2_32 ntdll bcrypt shell32 uuid setupapi cfgmgr32 iphlpapi)
    target_link_options(${TARGET}_support INTERFACE /DEPENDENTLOADFLAG:0x800 /DEBUG:FULL /OPT:REF /OPT:ICF "/PDBALTPATH:%_PDB%")
    add_executable(${TARGET} "${REPO}/infrastructure/networkhelper/windows/main.cpp")
    get_filename_component(OUTPUT_NAME "${WINDOWS_EXECUTABLE}" NAME_WE)
    set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")
    target_link_libraries(${TARGET} PRIVATE ${TARGET}_support)
    target_compile_definitions(${TARGET} PRIVATE JC_HELPER_REVISION="${REVISION}" JC_HELPER_SOURCE_STATE="${SOURCE_STATE}")
endfunction()

function(justconnect_windows_network_client TARGET)
    justconnect_windows_helper_layout()
    find_package(Qt6 REQUIRED COMPONENTS Core Concurrent Network)
    add_library(${TARGET} STATIC
        "${REPO}/infrastructure/networkhelper/windows/networkhelperclient.cpp"
        "${REPO}/infrastructure/networkhelper/windows/networkhelperclient.h"
        "${REPO}/infrastructure/networkhelper/windows/networkhelperpreparation.cpp"
        "${REPO}/infrastructure/networkhelper/windows/networkownership.cpp"
        "${REPO}/infrastructure/networkhelper/windows/controlwire.cpp"
        "${REPO}/infrastructure/packetpipe/windows/stream.cpp"
        "${REPO}/infrastructure/process/windows/identity.cpp")
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>DLL")
    target_compile_features(${TARGET} PUBLIC cxx_std_20)
    target_compile_definitions(${TARGET} PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
    target_include_directories(${TARGET} PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    target_link_libraries(${TARGET} PUBLIC Qt6::Core Qt6::Concurrent PRIVATE Qt6::Network advapi32 ole32)
endfunction()
