include_guard(GLOBAL)
find_package(Threads REQUIRED)
find_package(Git REQUIRED)
find_program(GO_EXECUTABLE go REQUIRED)
get_filename_component(REPO "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)
set(CORE "${REPO}/corelib")
if(WIN32)
    set(ABI_MODE c-shared)
else()
    set(ABI_MODE c-archive)
endif()
execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse HEAD
    WORKING_DIRECTORY "${REPO}" OUTPUT_VARIABLE REVISION OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${GIT_EXECUTABLE}" status --porcelain
    WORKING_DIRECTORY "${REPO}" OUTPUT_VARIABLE DIRTY COMMAND_ERROR_IS_FATAL ANY)
set(SOURCE_STATE clean)
if(DIRTY)
    set(SOURCE_STATE dirty)
endif()
file(GLOB_RECURSE ABI_SOURCES CONFIGURE_DEPENDS "${CORE}/*.go" "${CORE}/abi/*")
list(FILTER ABI_SOURCES EXCLUDE REGEX "_test\\.go$")
execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --git-path HEAD WORKING_DIRECTORY "${REPO}"
    OUTPUT_VARIABLE GIT_HEAD OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
execute_process(COMMAND "${GIT_EXECUTABLE}" symbolic-ref -q HEAD WORKING_DIRECTORY "${REPO}"
    OUTPUT_VARIABLE GIT_REF OUTPUT_STRIP_TRAILING_WHITESPACE)
get_filename_component(GIT_HEAD "${GIT_HEAD}" ABSOLUTE BASE_DIR "${REPO}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${ABI_SOURCES} "${GIT_HEAD}")
if(GIT_REF)
    execute_process(COMMAND "${GIT_EXECUTABLE}" rev-parse --git-path "${GIT_REF}" WORKING_DIRECTORY "${REPO}"
        OUTPUT_VARIABLE GIT_REF_PATH OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
    get_filename_component(GIT_REF_PATH "${GIT_REF_PATH}" ABSOLUTE BASE_DIR "${REPO}")
    set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${GIT_REF_PATH}")
endif()

function(justconnect_core_library KIND)
    set(TAGS ${ARGN})
    if(WIN32)
        set(LIBRARY_NAME "${KIND}.dll")
    else()
        set(LIBRARY_NAME "${KIND}.a")
    endif()
    set(LIBRARY "${CMAKE_CURRENT_BINARY_DIR}/${LIBRARY_NAME}")
    add_custom_command(OUTPUT "${LIBRARY}"
        COMMAND "${CMAKE_COMMAND}" -E env CGO_ENABLED=1 GOTOOLCHAIN=local GOWORK=off GOENV=off
            GOEXPERIMENT=cgocheck2 "${GO_EXECUTABLE}" build -mod=readonly -trimpath -buildvcs=false ${TAGS}
            "-ldflags=-X main.revision=${REVISION} -X main.sourceState=${SOURCE_STATE}"
            "-buildmode=${ABI_MODE}" -o "${LIBRARY}" ./abi
        WORKING_DIRECTORY "${CORE}"
        DEPENDS ${ABI_SOURCES} "${CORE}/go.mod" "${CORE}/go.sum" "${CMAKE_CURRENT_BINARY_DIR}/CMakeCache.txt"
        VERBATIM)
    add_custom_target(${KIND}_build DEPENDS "${LIBRARY}")
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
