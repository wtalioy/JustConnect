function(justconnect_windows_network_helper TARGET)
    set(CONTRACT "${REPO}/resource/network-helper-windows.json")
    file(READ "${CONTRACT}" LAYOUT)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CONTRACT}")
    string(JSON WINDOWS_STATE_REGISTRY GET "${LAYOUT}" state_registry)
    string(REPLACE "\\" "\\\\" WINDOWS_STATE_REGISTRY "${WINDOWS_STATE_REGISTRY}")
    string(JSON WINDOWS_MAX_RECORD_BYTES GET "${LAYOUT}" max_record_bytes)
    foreach(FIELD IN ITEMS executable driver_library driver_license install_directory service ownership_mutex)
        string(TOUPPER "${FIELD}" VARIABLE)
        string(JSON WINDOWS_${VARIABLE} GET "${LAYOUT}" "${FIELD}")
        string(REPLACE "\\" "\\\\" WINDOWS_${VARIABLE} "${WINDOWS_${VARIABLE}}")
    endforeach()
    string(JSON WINDOWS_STORAGE_VERSION GET "${LAYOUT}" storage_version)
    configure_file("${REPO}/infrastructure/networkhelper/windows/networkcontract.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/windowsnetworkcontract.h" @ONLY)
    add_library(${TARGET}_support STATIC
        "${REPO}/infrastructure/process/windows/identity.cpp"
        "${REPO}/infrastructure/networkhelper/windows/publisher.cpp"
        "${REPO}/infrastructure/networkhelper/windows/installation.cpp"
        "${REPO}/infrastructure/networkhelper/windows/recovery.cpp"
        "${REPO}/infrastructure/networkhelper/windows/service.cpp"
        "${REPO}/infrastructure/tundevice/windows/recovery.cpp"
        "${REPO}/infrastructure/dns/windows/nrpt.cpp"
        "${REPO}/infrastructure/networkjournal/windows/registry.cpp")
    target_include_directories(${TARGET}_support PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    # Current Windows SDK projections use the standard coroutine headers.
    target_compile_features(${TARGET}_support PUBLIC cxx_std_20)
    target_compile_definitions(${TARGET}_support PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
    target_link_libraries(${TARGET}_support PUBLIC advapi32 wintrust crypt32 ole32 windowsapp ws2_32 ntdll bcrypt shell32 uuid setupapi)
    target_link_options(${TARGET}_support INTERFACE /DEPENDENTLOADFLAG:0x800 /DEBUG:FULL /OPT:REF /OPT:ICF "/PDBALTPATH:%_PDB%")
    add_executable(${TARGET} "${REPO}/infrastructure/networkhelper/windows/main.cpp")
    get_filename_component(OUTPUT_NAME "${WINDOWS_EXECUTABLE}" NAME_WE)
    set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")
    target_link_libraries(${TARGET} PRIVATE ${TARGET}_support)
endfunction()
