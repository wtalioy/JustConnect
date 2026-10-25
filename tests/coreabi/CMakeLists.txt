cmake_minimum_required(VERSION 3.20)
project(CoreABIContract LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
find_package(Qt6 6.10 REQUIRED COMPONENTS WebEngineWidgets Concurrent)
include("${CMAKE_CURRENT_SOURCE_DIR}/../../cmake/CoreLibrary.cmake")
include(CTest)
foreach(KIND coreabi coreabi_fixture)
    set(TAGS)
    if(KIND STREQUAL "coreabi_fixture")
        set(TAGS -tags=jc_abi_test)
    endif()
    justconnect_core_library(${KIND} ${TAGS})
    justconnect_core_engine(${KIND}_engine ${KIND} coreabi_platform)
    set(HOST "${KIND}_test")
    add_executable(${HOST} main.cpp header_smoke.c)
    target_include_directories(${HOST} PRIVATE "${CORE}/abi")
    target_link_libraries(${HOST} PRIVATE Qt6::WebEngineWidgets ${KIND})
    if(KIND STREQUAL "coreabi_fixture")
        target_compile_definitions(${HOST} PRIVATE ABI_FIXTURE)
    endif()
    if(WIN32)
        target_compile_definitions(${HOST} PRIVATE ABI_SHARED ABI_LIBRARY_NAME="${KIND}.dll")
    endif()
    justconnect_core_runtime(${HOST} ${KIND})
    set(ADAPTER "${KIND}_adapter_test")
    add_executable(${ADAPTER} ../embeddedcoreengine_test.cpp)
    set_target_properties(${ADAPTER} PROPERTIES AUTOMOC ON)
    target_include_directories(${ADAPTER} PRIVATE "${REPO}")
    target_link_libraries(${ADAPTER} PRIVATE Qt6::Core ${KIND}_engine)
    justconnect_core_runtime(${ADAPTER} ${KIND})
    if(KIND STREQUAL "coreabi_fixture")
        target_compile_definitions(${ADAPTER} PRIVATE ABI_FIXTURE)
    endif()
    add_test(NAME ${ADAPTER} COMMAND ${ADAPTER})
    set_tests_properties(${ADAPTER} PROPERTIES TIMEOUT 60)
    add_test(NAME ${HOST} COMMAND ${HOST})
    set_tests_properties(${HOST} PROPERTIES TIMEOUT 60
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")
endforeach()

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(coreabi_tun_adapter_test tun_adapter.cpp
        "${REPO}/application/connectionsession.cpp" "${REPO}/application/networkpolicysession.cpp"
        "${REPO}/core/connectionsessionstate.cpp")
    set_target_properties(coreabi_tun_adapter_test PROPERTIES AUTOMOC ON)
    target_include_directories(coreabi_tun_adapter_test PRIVATE "${REPO}")
    target_link_libraries(coreabi_tun_adapter_test PRIVATE coreabi_engine Qt6::Network)
    justconnect_core_runtime(coreabi_tun_adapter_test coreabi)
    add_executable(linux_networkaccess_test ../platform/networkaccess_linux_test.cpp
        "${REPO}/application/connectionsession.cpp" "${REPO}/application/networkpolicysession.cpp"
        "${REPO}/core/connectionsessionstate.cpp")
    set_target_properties(linux_networkaccess_test PROPERTIES AUTOMOC ON)
    target_link_libraries(linux_networkaccess_test PRIVATE coreabi_engine)
    add_test(NAME linux_networkaccess_test COMMAND linux_networkaccess_test)
    set_tests_properties(linux_networkaccess_test PROPERTIES TIMEOUT 15)
endif()

if(APPLE)
    add_executable(coreabi_macos_tun_adapter_test tun_macos_adapter.cpp
        "${REPO}/application/connectionsession.cpp" "${REPO}/application/networkpolicysession.cpp"
        "${REPO}/application/applicationshutdown.cpp" "${REPO}/application/systemproxysession.cpp"
        "${REPO}/core/connectionsessionstate.cpp")
    set_target_properties(coreabi_macos_tun_adapter_test PROPERTIES AUTOMOC ON INSTALL_RPATH "@executable_path/../Frameworks")
    target_include_directories(coreabi_macos_tun_adapter_test PRIVATE "${REPO}")
    target_link_libraries(coreabi_macos_tun_adapter_test PRIVATE coreabi_engine Qt6::Network)
    justconnect_core_runtime(coreabi_macos_tun_adapter_test coreabi)
endif()

add_test(NAME coreabi_protocol_test
    COMMAND "${CMAKE_COMMAND}" -E env "JC_NATIVE_PROTOCOL_HOST=$<TARGET_FILE:coreabi_test>"
        GOTOOLCHAIN=local GOWORK=off GOENV=off CGO_ENABLED=1 GOEXPERIMENT=cgocheck2
        "${GO_EXECUTABLE}" test -mod=readonly -count=1 -timeout 60s -run "^TestNativeProtocolHost$" -v ./internal/bridge)
set_tests_properties(coreabi_protocol_test PROPERTIES TIMEOUT 90 WORKING_DIRECTORY "${CORE}"
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")

add_test(NAME coreabi_performance_test
    COMMAND "${CMAKE_COMMAND}" -E env "JC_NATIVE_PROTOCOL_HOST=$<TARGET_FILE:coreabi_test>"
        "JC_NATIVE_BASELINE_OUTPUT=${CMAKE_CURRENT_BINARY_DIR}/performance.json"
        GOTOOLCHAIN=local GOWORK=off GOENV=off CGO_ENABLED=1 GOEXPERIMENT=cgocheck2
        "${GO_EXECUTABLE}" test -mod=readonly -count=1 -timeout 120s -run "^TestNativePerformanceHost$" -v ./internal/bridge)
set_tests_properties(coreabi_performance_test PROPERTIES TIMEOUT 150 WORKING_DIRECTORY "${CORE}"
    ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")

include("${REPO}/tests/CoreEngineTests.cmake")

include("${REPO}/cmake/Platform.cmake")
justconnect_platform(coreabi_platform)
justconnect_core_ui_tests(coreabi_ui_test coreabi_engine coreabi coreabi_platform)
justconnect_platform_tests(coreabi_platform_test coreabi_platform)
justconnect_network_policy_tests()
justconnect_credential_tests(coreabi_credentialstore_test coreabi_platform)
justconnect_autostart_tests(coreabi_autostart_test coreabi_platform)
