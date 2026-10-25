cmake_minimum_required(VERSION 3.20)
project(JustConnectWindowsDevice LANGUAGES CXX)
if(NOT WIN32)
    message(FATAL_ERROR "The device fixture is Windows-only")
endif()
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
get_filename_component(REPO "${CMAKE_CURRENT_SOURCE_DIR}/../../.." ABSOLUTE)
include("${REPO}/cmake/WindowsDevice.cmake")
include("${REPO}/cmake/WindowsNetworkHelper.cmake")
justconnect_windows_device(windows_device)
justconnect_windows_helper_support(windows_helper_support)
add_library(windows_packet_relay STATIC
    "${REPO}/infrastructure/packetpipe/windows/stream.cpp"
    "${REPO}/infrastructure/networkhelper/windows/packetrelay.cpp")
target_link_libraries(windows_packet_relay PUBLIC windows_device windows_helper_support)
add_library(windows_fixture_support STATIC ordinarytoken.cpp)
target_link_libraries(windows_fixture_support PUBLIC windows_helper_support)
add_executable(windows_device_broker broker.cpp)
target_link_libraries(windows_device_broker PRIVATE windows_device windows_fixture_support windows_packet_relay setupapi uuid)

# Restrict static dependencies before main; this fixture runs with administrator rights.
target_link_options(windows_device_broker PRIVATE /DEPENDENTLOADFLAG:0x800)

foreach(CASE IN ITEMS process_identity publisher registry_journal packet_frame nrpt)
    add_executable(windows_${CASE}_test ${CASE}.cpp)
    target_link_libraries(windows_${CASE}_test PRIVATE windows_helper_support windows_fixture_support windows_packet_relay)
    target_link_options(windows_${CASE}_test PRIVATE /DEPENDENTLOADFLAG:0x800)
endforeach()
