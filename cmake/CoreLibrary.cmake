include_guard(GLOBAL)
find_package(Threads REQUIRED)
find_program(GO_EXECUTABLE go REQUIRED)
find_package(Python3 REQUIRED COMPONENTS Interpreter)
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(CORE "${REPO}/corelib")
if(WIN32)
    set(ABI_MODE c-shared)
else()
    set(ABI_MODE c-archive)
endif()
file(STRINGS "${CORE}/go.mod" GO_VERSION_LINE REGEX "^go ")
string(REPLACE "go " "go" REQUIRED_GO "${GO_VERSION_LINE}")
execute_process(COMMAND "${CMAKE_COMMAND}" -E env GOTOOLCHAIN=local "${GO_EXECUTABLE}" version
    OUTPUT_VARIABLE GO_VERSION OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
if(NOT GO_VERSION MATCHES " ${REQUIRED_GO} ")
    message(FATAL_ERROR "Required ${REQUIRED_GO}; found ${GO_VERSION}")
endif()
execute_process(COMMAND "${Python3_EXECUTABLE}" "${REPO}/scripts/generate-core-abi.py"
    COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${GO_EXECUTABLE}" env GOOS GOARCH CC
    OUTPUT_VARIABLE GO_ENV OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
message(STATUS "Core toolchain: ${GO_VERSION}; ${GO_ENV}; C=${CMAKE_C_COMPILER_ID} ${CMAKE_C_COMPILER_VERSION}; CXX=${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
execute_process(COMMAND "${GO_EXECUTABLE}" env CC OUTPUT_VARIABLE CGO_CC OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
separate_arguments(CGO_CC NATIVE_COMMAND "${CGO_CC}")
execute_process(COMMAND ${CGO_CC} --version OUTPUT_VARIABLE CGO_CC_VERSION COMMAND_ERROR_IS_FATAL ANY)
file(WRITE "${CMAKE_BINARY_DIR}/core-toolchain.txt"
    "${GO_VERSION}\n${GO_ENV}\n${CGO_CC_VERSION}\nABI=${ABI_MODE}\nCGO_ENABLED=1\nGOEXPERIMENT=cgocheck2\nC=${CMAKE_C_COMPILER} ${CMAKE_C_COMPILER_VERSION}\nCXX=${CMAKE_CXX_COMPILER} ${CMAKE_CXX_COMPILER_VERSION}\n")
file(GLOB_RECURSE ABI_SOURCES CONFIGURE_DEPENDS "${CORE}/*.go" "${CORE}/abi/*")
list(FILTER ABI_SOURCES EXCLUDE REGEX "_test\\.go$")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CORE}/go.mod" "${CORE}/go.sum" "${REPO}/scripts/generate-core-abi.py" ${ABI_SOURCES})
include("${REPO}/cmake/SourceRevision.cmake")
if(APPLE)
    # Qt 6.12's documented deployment floor also governs cgo and Info.plist.
    if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
        set(CMAKE_OSX_DEPLOYMENT_TARGET "14.4" CACHE STRING "Minimum macOS version" FORCE)
    endif()
    set(CGO_PLATFORM_ENV "CGO_CFLAGS=$ENV{CGO_CFLAGS} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}"
        "CGO_LDFLAGS=$ENV{CGO_LDFLAGS} -mmacosx-version-min=${CMAKE_OSX_DEPLOYMENT_TARGET}")
endif()

function(justconnect_core_library KIND)
    set(TAGS ${ARGN})
    if(WIN32)
        set(LIBRARY_NAME "${KIND}.dll")
    else()
        set(LIBRARY_NAME "${KIND}.a")
    endif()
    set(CORE_OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/$<CONFIG>")
    set(LIBRARY "${CORE_OUTPUT}/${LIBRARY_NAME}")
    file(GENERATE OUTPUT "${CORE_OUTPUT}/${KIND}-options.txt"
        CONTENT "${REVISION}\n${SOURCE_STATE}\n${TAGS}\n${ABI_MODE}\n${GO_EXECUTABLE}\n$<CONFIG>\n$ENV{CC}\n$ENV{CGO_CFLAGS}\n$ENV{CGO_LDFLAGS}\n${CMAKE_OSX_DEPLOYMENT_TARGET}\n")
    add_custom_command(OUTPUT "${LIBRARY}" "${CORE_OUTPUT}/${KIND}.h"
        COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOTOOLCHAIN=local GOWORK=off GOENV=off
            GOEXPERIMENT=cgocheck2 ${CGO_PLATFORM_ENV} "${GO_EXECUTABLE}" build -mod=readonly -trimpath -buildvcs=false ${TAGS}
            "-ldflags=$<$<CONFIG:Release>:-w> -X main.revision=${REVISION} -X main.sourceState=${SOURCE_STATE}"
            "-buildmode=${ABI_MODE}" -o "${LIBRARY}" ./abi
        WORKING_DIRECTORY "${CORE}"
        DEPENDS ${ABI_SOURCES} "${CORE}/go.mod" "${CORE}/go.sum" "${CORE_OUTPUT}/${KIND}-options.txt" "${CMAKE_BINARY_DIR}/CMakeCache.txt"
        VERBATIM)
    add_custom_target(${KIND}_build DEPENDS "${LIBRARY}" "${CORE_OUTPUT}/${KIND}.h")
    add_library(${KIND} INTERFACE)
    add_dependencies(${KIND} ${KIND}_build)
    target_include_directories(${KIND} INTERFACE "${CORE}/abi")
    if(WIN32)
        target_compile_definitions(${KIND} INTERFACE JC_SHARED_LIBRARY="${LIBRARY_NAME}")
        set_property(TARGET ${KIND} PROPERTY JC_RUNTIME_LIBRARY "${LIBRARY}")
    else()
        target_link_libraries(${KIND} INTERFACE "${LIBRARY}" Threads::Threads)
        if(APPLE)
            target_link_libraries(${KIND} INTERFACE "-framework CoreFoundation" "-framework Security" resolv)
        else()
            target_link_libraries(${KIND} INTERFACE ${CMAKE_DL_LIBS} m resolv)
        endif()
    endif()
endfunction()

function(justconnect_core_engine TARGET LIBRARY PLATFORM)
    add_library(${TARGET} STATIC "${REPO}/application/coreengine.h"
        "${REPO}/application/authmethodsquery.cpp"
        "${REPO}/application/networkprotection.cpp"
        "${REPO}/infrastructure/coreengine/embeddedcoreengine.cpp")
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON)
    target_include_directories(${TARGET} PUBLIC "${REPO}")
    target_link_libraries(${TARGET} PUBLIC Qt6::Core Qt6::Network ${LIBRARY} ${PLATFORM})
endfunction()

function(justconnect_core_runtime HOST KIND)
    if(WIN32)
        get_target_property(LIBRARY ${KIND} JC_RUNTIME_LIBRARY)
        add_custom_target(${HOST}_runtime
            COMMAND "${CMAKE_COMMAND}" -E make_directory "$<TARGET_FILE_DIR:${HOST}>"
            COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${LIBRARY}" "$<TARGET_FILE_DIR:${HOST}>"
            DEPENDS ${KIND} VERBATIM)
        add_dependencies(${HOST} ${HOST}_runtime)
    endif()
endfunction()
