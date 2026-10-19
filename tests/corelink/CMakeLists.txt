cmake_minimum_required(VERSION 3.19)
project(CoreLinkProbe LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
find_package(Qt6 6.5 REQUIRED COMPONENTS WebEngineWidgets)
find_program(GO_EXECUTABLE go REQUIRED)

set(PROBE_MODE c-archive CACHE STRING "Go build mode for S1-06")
if(PROBE_MODE STREQUAL "c-archive")
    set(PROBE_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/probe.a")
elseif(PROBE_MODE STREQUAL "c-shared" AND WIN32)
    set(PROBE_LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/probe.dll")
else()
    message(FATAL_ERROR "Use c-archive, or c-shared for the Windows fallback")
endif()

add_custom_command(OUTPUT "${PROBE_LIBRARY}"
    COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOTOOLCHAIN=local GOWORK=off
        GOEXPERIMENT=cgocheck2 "${GO_EXECUTABLE}" build -mod=readonly -trimpath
        -buildvcs=false "-buildmode=${PROBE_MODE}" -o "${PROBE_LIBRARY}" .
    WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
    DEPENDS main.go go.mod
    VERBATIM
)
add_custom_target(probe_library DEPENDS "${PROBE_LIBRARY}")
add_executable(corelink_test host/main.cpp)
add_dependencies(corelink_test probe_library)
target_link_libraries(corelink_test PRIVATE Qt6::WebEngineWidgets)
if(PROBE_MODE STREQUAL "c-archive")
    target_link_libraries(corelink_test PRIVATE "${PROBE_LIBRARY}")
    if(WIN32)
        target_link_libraries(corelink_test PRIVATE ws2_32 ntdll winmm)
    elseif(APPLE)
        target_link_libraries(corelink_test PRIVATE "-framework CoreFoundation" "-framework Security" resolv)
    else()
        find_package(Threads REQUIRED)
        target_link_libraries(corelink_test PRIVATE Threads::Threads ${CMAKE_DL_LIBS} m resolv)
    endif()
else()
    target_compile_definitions(corelink_test PRIVATE PROBE_SHARED)
    add_custom_command(TARGET corelink_test POST_BUILD COMMAND "${CMAKE_COMMAND}" -E
        copy_if_different "${PROBE_LIBRARY}" "$<TARGET_FILE_DIR:corelink_test>/probe.dll")
endif()

include(CTest)
add_test(NAME corelink_test COMMAND corelink_test)
set_tests_properties(corelink_test PROPERTIES TIMEOUT 60
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")
