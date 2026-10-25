function(justconnect_windows_helper_support TARGET)
    set(CONTRACT "${REPO}/corelib/internal/networkhelper/windows/contract.json")
    file(READ "${CONTRACT}" LAYOUT)
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${CONTRACT}")
    string(JSON WINDOWS_STATE_REGISTRY GET "${LAYOUT}" state_registry)
    string(REPLACE "\\" "\\\\" WINDOWS_STATE_REGISTRY "${WINDOWS_STATE_REGISTRY}")
    string(JSON WINDOWS_MAX_RECORD_BYTES GET "${LAYOUT}" max_record_bytes)
    foreach(FIELD IN ITEMS executable driver_library driver_license install_directory)
        string(TOUPPER "${FIELD}" VARIABLE)
        string(JSON WINDOWS_${VARIABLE} GET "${LAYOUT}" "${FIELD}")
    endforeach()
    configure_file("${REPO}/infrastructure/networkhelper/windows/networkcontract.h.in"
        "${CMAKE_CURRENT_BINARY_DIR}/windowsnetworkcontract.h" @ONLY)
    add_library(${TARGET} STATIC
        "${REPO}/infrastructure/process/windows/identity.cpp"
        "${REPO}/infrastructure/networkhelper/windows/publisher.cpp"
        "${REPO}/infrastructure/networkhelper/windows/installation.cpp"
        "${REPO}/infrastructure/dns/windows/nrpt.cpp"
        "${REPO}/infrastructure/networkjournal/windows/registry.cpp")
    target_include_directories(${TARGET} PUBLIC "${REPO}" "${CMAKE_CURRENT_BINARY_DIR}")
    # Current Windows SDK projections use the standard coroutine headers.
    target_compile_features(${TARGET} PUBLIC cxx_std_20)
    target_compile_definitions(${TARGET} PUBLIC NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
    target_link_libraries(${TARGET} PUBLIC advapi32 wintrust crypt32 ole32 windowsapp ws2_32 ntdll bcrypt shell32 uuid)
    target_link_options(${TARGET} INTERFACE /DEPENDENTLOADFLAG:0x800 /DEBUG:FULL /OPT:REF /OPT:ICF "/PDBALTPATH:%_PDB%")
endfunction()
