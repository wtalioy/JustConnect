include_guard(GLOBAL)

function(justconnect_network_access TARGET PLATFORM)
    if(WIN32)
        set(NETWORK_ACCESS_SOURCES "${REPO}/infrastructure/networkaccess/windows/networkaccess.cpp")
    elseif(APPLE)
        set(NETWORK_ACCESS_SOURCES
            "${REPO}/infrastructure/networkhelper/macos/networkhelperpreparation.cpp"
            "${REPO}/infrastructure/networkaccess/macos/networkaccess.cpp")
    elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        set(NETWORK_ACCESS_SOURCES
            "${REPO}/infrastructure/networkhelper/linux/networkhelperpreparation.cpp"
            "${REPO}/infrastructure/networkaccess/linux/networkaccess.cpp"
            "${REPO}/infrastructure/networkhelper/linux/networkownership.cpp")
    else()
        message(FATAL_ERROR "Unsupported network access platform: ${CMAKE_SYSTEM_NAME}")
    endif()
    add_library(${TARGET} STATIC ${NETWORK_ACCESS_SOURCES})
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON)
    target_link_libraries(${TARGET} PUBLIC justconnect_application ${PLATFORM})
endfunction()
