cmake_minimum_required(VERSION 3.20)
project(JustConnectWindowsDevice LANGUAGES CXX)
if(NOT WIN32)
    message(FATAL_ERROR "The device fixture is Windows-only")
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
get_filename_component(REPO "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
include("${REPO}/cmake/WindowsDevice.cmake")
justconnect_windows_device(windows_device)
add_executable(windows_device_broker broker.cpp)
target_link_libraries(windows_device_broker PRIVATE windows_device advapi32 setupapi uuid)

# Restrict static dependencies before main; this fixture runs with administrator rights.
target_link_options(windows_device_broker PRIVATE /DEPENDENTLOADFLAG:0x800)

add_executable(windows_process_identity_test process_identity.cpp
    "${REPO}/infrastructure/process/windows/identity.cpp")
target_include_directories(windows_process_identity_test PRIVATE "${REPO}")
target_compile_features(windows_process_identity_test PRIVATE cxx_std_17)
target_compile_definitions(windows_process_identity_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
target_link_libraries(windows_process_identity_test PRIVATE advapi32)
target_link_options(windows_process_identity_test PRIVATE /DEPENDENTLOADFLAG:0x800)

add_executable(windows_publisher_test publisher.cpp
    "${REPO}/infrastructure/networkhelper/windows/publisher.cpp")
target_include_directories(windows_publisher_test PRIVATE "${REPO}")
target_compile_features(windows_publisher_test PRIVATE cxx_std_17)
target_compile_definitions(windows_publisher_test PRIVATE NOMINMAX WIN32_LEAN_AND_MEAN _WIN32_WINNT=0x0A00)
target_link_libraries(windows_publisher_test PRIVATE wintrust crypt32)
target_link_options(windows_publisher_test PRIVATE /DEPENDENTLOADFLAG:0x800)
