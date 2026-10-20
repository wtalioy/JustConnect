cmake_minimum_required(VERSION 3.19)
project(JustConnect)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

option(NIGHTLY_BUILD    "Set if built nightly.")

if(NIGHTLY_BUILD)
    set(PROJ_VER "${GIT_HASH}-nightly")
elseif(DEFINED REL_VER)
    set(PROJ_VER "${REL_VER}")
else()
    set(PROJ_VER "dev")
endif()

add_compile_definitions(PROJ_VER="${PROJ_VER}")
message("PROJ_VER=${PROJ_VER}")

find_package(Qt6 6.5 COMPONENTS
    Core
    Concurrent
    Gui
    Widgets
    Network
    Svg
    WebEngineWidgets
    REQUIRED
)

include(cmake/CoreLibrary.cmake)
justconnect_core_library(justconnect_core)
justconnect_core_engine(justconnect_engine justconnect_core)
include(cmake/Platform.cmake)
justconnect_platform(justconnect_platform)
if(WIN32)
    install(FILES "$<TARGET_PROPERTY:justconnect_core,JC_RUNTIME_LIBRARY>" DESTINATION . COMPONENT CoreRuntime)
endif()
if(APPLE)
    set(CORE_DATA_DESTINATION "${PROJECT_NAME}.app/Contents/Resources")
elseif(WIN32)
    set(CORE_DATA_DESTINATION ".")
else()
    set(CORE_DATA_DESTINATION "usr/share/${PROJECT_NAME}")
endif()
install(FILES "${CMAKE_BINARY_DIR}/core-toolchain.txt" "${CMAKE_BINARY_DIR}/source-revision.txt"
    DESTINATION "${CORE_DATA_DESTINATION}" COMPONENT CoreRuntime)
install(FILES "${CORE}/UPSTREAM.md" "${CORE}/LICENSE.zju-connect" "${REPO}/LICENSE"
    DESTINATION "${CORE_DATA_DESTINATION}/licenses" COMPONENT CoreRuntime)
install(FILES "${CORE}/internal/ping/LICENSE"
    DESTINATION "${CORE_DATA_DESTINATION}/licenses" RENAME LICENSE.ping COMPONENT CoreRuntime)

set(SOURCE_FILES
    main.cpp
    presentation/main/mainwindow.cpp
    presentation/main/mainwindowcoordinator.cpp
    presentation/coordinators/authdialogcoordinator.cpp
    presentation/coordinators/connectionuicontroller.cpp
    application/applicationlogger.cpp
    application/commandlineoptions.cpp
    application/connectionsession.cpp
    application/profileservice.cpp
    application/settingsmigrator.cpp
    application/systemproxysession.cpp
    application/defaultsettings.cpp
    core/connectionsessionstate.cpp
    infrastructure/logging/applicationlogfile.cpp
    infrastructure/platform/autostart.cpp
    infrastructure/settings/settingsprofileloader.cpp
    infrastructure/storage/applicationpaths.cpp
    infrastructure/update/updatechecker.cpp
    presentation/presentationhelpers.cpp
    presentation/dialogs/extrasettingwindow/extrasettingwindow.cpp
    presentation/dialogs/settingwindow/settingwindow.cpp
    presentation/dialogs/loginwindow/loginwindow.cpp
    presentation/dialogs/ssologinwebview/ssologinwebview.cpp
    presentation/dialogs/authinfowindow/authinfowindow.cpp
    presentation/dialogs/configurationguidedialog/configurationguidedialog.cpp
    presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp
    presentation/dialogs/graphcaptchawindow/captchacanvas.cpp
    infrastructure/settings/profilemanager.cpp
    resource.qrc
)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

if (WIN32)
    message("Building for Windows")

    add_executable(${PROJECT_NAME} WIN32
        ${SOURCE_FILES}
    )

    set(PLATFORM_LIBS shell32)
elseif(APPLE)
    message("Building for MacOS")
    
    add_executable(${PROJECT_NAME} MACOSX_BUNDLE
        ${SOURCE_FILES}
    )

    set_target_properties(${PROJECT_NAME}
        PROPERTIES MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/resource/Info.plist")
else()
    add_executable(${PROJECT_NAME}
        ${SOURCE_FILES}
    )

    install(
        TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin
    )
endif()

set(QAPPLICATION_CLASS QApplication CACHE STRING "Inheritance class for SingleApplication")

add_subdirectory(singleapplication)

target_link_libraries(${PROJECT_NAME}
        Qt::Core
        Qt::Concurrent
        Qt::Gui
        Qt::Widgets
        Qt::Network
        Qt::Svg
        Qt::WebEngineWidgets
        justconnect_engine
        justconnect_platform
        SingleApplication::SingleApplication
        ${PLATFORM_LIBS}
)

justconnect_core_runtime(${PROJECT_NAME} justconnect_core)

include(CTest)

if(BUILD_TESTING)
    justconnect_platform_tests(platformbackend_test justconnect_platform)
    add_test(NAME core_self_test COMMAND ${PROJECT_NAME} --core-self-test)
    set_tests_properties(core_self_test PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "\"ok\":true")
    include(tests/CoreEngineTests.cmake)
    justconnect_core_ui_tests(coreengineui_test justconnect_engine justconnect_core)
    add_executable(webengine_test tests/webengine_test.cpp)
    target_link_libraries(webengine_test Qt::WebEngineWidgets)
    add_test(NAME webengine_test COMMAND webengine_test)
    set_tests_properties(webengine_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu"
        TIMEOUT 20
    )

    add_executable(applicationlogger_test
        tests/applicationlogger_test.cpp
        application/applicationlogger.cpp
    )
    target_include_directories(applicationlogger_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(applicationlogger_test Qt::Core)
    add_test(NAME applicationlogger_test COMMAND applicationlogger_test)

    add_executable(applicationlogfile_test
        tests/applicationlogfile_test.cpp
        infrastructure/logging/applicationlogfile.cpp
    )
    target_include_directories(applicationlogfile_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(applicationlogfile_test Qt::Core)
    add_test(NAME applicationlogfile_test COMMAND applicationlogfile_test)

    add_executable(settingsprofileloader_test
        tests/settingsprofileloader_test.cpp
        infrastructure/settings/settingsprofileloader.cpp
    )
    target_include_directories(settingsprofileloader_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(settingsprofileloader_test Qt::Core)
    add_test(NAME settingsprofileloader_test COMMAND settingsprofileloader_test)

    add_executable(connectionsessionstate_test
        tests/connectionsessionstate_test.cpp
        core/connectionsessionstate.cpp
    )
    target_include_directories(connectionsessionstate_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(connectionsessionstate_test Qt::Core)
    add_test(NAME connectionsessionstate_test COMMAND connectionsessionstate_test)

    add_executable(connectionsession_test
        application/coreengine.h
        tests/connectionsession_test.cpp
        application/connectionsession.cpp
        core/connectionsessionstate.cpp
    )
    target_include_directories(connectionsession_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(connectionsession_test Qt::Core)
    add_test(NAME connectionsession_test COMMAND connectionsession_test)

    add_executable(systemproxysession_test
        tests/systemproxysession_test.cpp
        application/systemproxysession.cpp
    )
    target_include_directories(systemproxysession_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(systemproxysession_test Qt::Core Qt::Concurrent)
    add_test(NAME systemproxysession_test COMMAND systemproxysession_test)

    add_executable(updatechecker_test
        tests/updatechecker_test.cpp
        infrastructure/update/updatechecker.cpp
    )
    target_include_directories(updatechecker_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(updatechecker_test justconnect_engine Qt::Core Qt::Gui Qt::Widgets Qt::Network)
    justconnect_core_runtime(updatechecker_test justconnect_core)
    add_test(NAME updatechecker_test COMMAND updatechecker_test)

    add_executable(settingsmigrator_test
        tests/settingsmigrator_test.cpp
        application/settingsmigrator.cpp
        application/defaultsettings.cpp
    )
    target_include_directories(settingsmigrator_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(settingsmigrator_test Qt::Core)
    add_test(NAME settingsmigrator_test COMMAND settingsmigrator_test)

    add_executable(profileservice_test
        tests/profileservice_test.cpp
        application/profileservice.cpp
    )
    target_include_directories(profileservice_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profileservice_test Qt::Core)
    add_test(NAME profileservice_test COMMAND profileservice_test)

    add_executable(profilemanager_test
        tests/profilemanager_test.cpp
        infrastructure/settings/profilemanager.cpp
    )
    target_include_directories(profilemanager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profilemanager_test Qt::Core)
    add_test(NAME profilemanager_test COMMAND profilemanager_test)

    add_executable(configurationguidedialog_test
        tests/configurationguidedialog_test.cpp
        presentation/dialogs/configurationguidedialog/configurationguidedialog.cpp
        presentation/dialogs/authinfowindow/authinfowindow.cpp
    )
    target_include_directories(configurationguidedialog_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(configurationguidedialog_test
        justconnect_engine
        Qt::Core
        Qt::Gui
        Qt::Widgets
    )
    justconnect_core_runtime(configurationguidedialog_test justconnect_core)
    add_test(NAME configurationguidedialog_test COMMAND configurationguidedialog_test)
    set_tests_properties(configurationguidedialog_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )

    add_executable(graphcaptchawindow_test
        tests/graphcaptchawindow_test.cpp
        presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp
        presentation/dialogs/graphcaptchawindow/captchacanvas.cpp
    )
    target_include_directories(graphcaptchawindow_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(graphcaptchawindow_test Qt::Core Qt::Gui Qt::Widgets)
    add_test(NAME graphcaptchawindow_test COMMAND graphcaptchawindow_test)
    set_tests_properties(graphcaptchawindow_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
    )
endif()
