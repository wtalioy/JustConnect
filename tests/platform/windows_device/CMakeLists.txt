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
