cmake_minimum_required(VERSION 3.20)
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

find_package(Qt6 6.10 COMPONENTS
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
justconnect_core_engine(justconnect_engine justconnect_core justconnect_platform)
include(cmake/SystemIntegration.cmake)
justconnect_system_integration(justconnect_platform)
if(WIN32)
    install(FILES "$<TARGET_GENEX_EVAL:justconnect_core,$<TARGET_PROPERTY:justconnect_core,JC_RUNTIME_LIBRARY>>" DESTINATION . COMPONENT CoreRuntime)
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
    infrastructure/process/terminationrequests.cpp
    presentation/main/mainwindow.cpp
    presentation/main/mainwindowcoordinator.cpp
    presentation/coordinators/authdialogcoordinator.cpp
    presentation/coordinators/authenticationcachecoordinator.cpp
    presentation/coordinators/connectionuicontroller.cpp
    application/applicationlogger.cpp
    application/commandlineoptions.cpp
    application/applicationshutdown.cpp
    application/connectionsession.cpp
    application/profileservice.cpp
    application/profileconfiguration.cpp
    application/profilecredentials.cpp
    application/settingsmigrator.cpp
    application/systemproxysession.cpp
    application/networkpolicysession.cpp
    presentation/dialogs/networkpolicywindow.cpp
    application/defaultsettings.cpp
    core/connectionsessionstate.cpp
    infrastructure/logging/applicationlogfile.cpp
    infrastructure/settings/credentialaccess.cpp
    infrastructure/storage/applicationpaths.cpp
    infrastructure/update/updatechecker.cpp
    presentation/presentationhelpers.cpp
    presentation/widgets/serversettingswidget.cpp
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
add_dependencies(${PROJECT_NAME} JustConnectProxyRecovery)
if(APPLE)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:JustConnectProxyRecovery>" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/")
endif()

include(CTest)

if(BUILD_TESTING)
    add_executable(singleapplication_test tests/singleapplication_test.cpp)
    target_link_libraries(singleapplication_test PRIVATE SingleApplication::SingleApplication)
    add_test(NAME singleapplication_test COMMAND singleapplication_test)
    set_tests_properties(singleapplication_test PROPERTIES TIMEOUT 20 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(serversettingswidget_test tests/serversettingswidget_test.cpp
        presentation/widgets/serversettingswidget.cpp application/profileservice.cpp
        application/defaultsettings.cpp application/settingsmigrator.cpp application/profileconfiguration.cpp)
    target_link_libraries(serversettingswidget_test PRIVATE Qt6::Widgets)
    add_test(NAME serversettingswidget_test COMMAND serversettingswidget_test)
    set_tests_properties(serversettingswidget_test PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
    justconnect_system_integration_tests(platformbackend_test justconnect_platform)
    justconnect_credential_tests(credentialstore_test justconnect_platform)
    justconnect_autostart_tests(autostart_test justconnect_platform)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(settingwindow_test tests/settingwindow_test.cpp
            presentation/widgets/serversettingswidget.cpp
            presentation/dialogs/settingwindow/settingwindow.cpp
            presentation/dialogs/authinfowindow/authinfowindow.cpp
            presentation/presentationhelpers.cpp
            application/defaultsettings.cpp application/settingsmigrator.cpp application/profileconfiguration.cpp infrastructure/settings/profilemanager.cpp
            infrastructure/storage/applicationpaths.cpp infrastructure/settings/credentialaccess.cpp
            application/profilecredentials.cpp application/profileservice.cpp)
        target_link_libraries(settingwindow_test PRIVATE justconnect_engine justconnect_platform Qt6::WebEngineWidgets Qt6::Concurrent)
        add_test(NAME settingwindow_test COMMAND settingwindow_test)
        set_tests_properties(settingwindow_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    endif()
    add_test(NAME core_self_test COMMAND ${PROJECT_NAME} --core-self-test)
    set_tests_properties(core_self_test PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "\"ok\":true")
    include(tests/CoreEngineTests.cmake)
    justconnect_core_ui_tests(coreengineui_test justconnect_engine justconnect_core justconnect_platform)
    set(MAINWINDOW_TEST_SOURCES ${SOURCE_FILES})
    list(REMOVE_ITEM MAINWINDOW_TEST_SOURCES main.cpp)
    add_executable(mainwindow_test tests/mainwindow_test.cpp ${MAINWINDOW_TEST_SOURCES})
    add_dependencies(mainwindow_test JustConnectProxyRecovery)
    target_link_libraries(mainwindow_test PRIVATE justconnect_engine justconnect_platform
        Qt6::WebEngineWidgets Qt6::Concurrent Qt6::Svg SingleApplication::SingleApplication ${PLATFORM_LIBS})
    justconnect_core_runtime(mainwindow_test justconnect_core)
    add_test(NAME mainwindow_test COMMAND mainwindow_test)
    add_test(NAME mainwindow_active_preferences_test COMMAND mainwindow_test --active-preferences)
    add_test(NAME mainwindow_close_exit_test COMMAND mainwindow_test --close-exits)
    add_test(NAME mainwindow_preferences_failure_test COMMAND mainwindow_test --preferences-failure)
    add_test(NAME mainwindow_termination_test COMMAND mainwindow_test --termination)
    add_test(NAME mainwindow_system_session_test COMMAND mainwindow_test --system-session)
    if(UNIX)
        add_test(NAME mainwindow_external_signal_test COMMAND mainwindow_test --external-signal)
        add_test(NAME mainwindow_interrupt_test COMMAND mainwindow_test --interrupt)
        add_test(NAME mainwindow_hangup_test COMMAND mainwindow_test --hangup)
        set_tests_properties(mainwindow_interrupt_test mainwindow_hangup_test mainwindow_external_signal_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    endif()
    set_tests_properties(mainwindow_test mainwindow_active_preferences_test mainwindow_close_exit_test mainwindow_preferences_failure_test mainwindow_termination_test mainwindow_system_session_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
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

    add_executable(credentialaccess_test tests/credentialaccess_test.cpp infrastructure/settings/credentialaccess.cpp
        application/profileconfiguration.cpp application/profilecredentials.cpp
        application/profileservice.cpp application/defaultsettings.cpp application/settingsmigrator.cpp)
    target_link_libraries(credentialaccess_test PRIVATE Qt6::Core Qt6::Concurrent)
    add_test(NAME credentialaccess_test COMMAND credentialaccess_test)
    set_tests_properties(credentialaccess_test PROPERTIES TIMEOUT 20)

    add_executable(profilecredentials_test tests/profilecredentials_test.cpp application/profilecredentials.cpp)
    target_link_libraries(profilecredentials_test PRIVATE Qt6::Core)
    add_test(NAME profilecredentials_test COMMAND profilecredentials_test)

    add_executable(settingsprofileloader_test
        tests/settingsprofileloader_test.cpp
        application/profileconfiguration.cpp application/defaultsettings.cpp
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

    justconnect_network_policy_tests()

    add_executable(connectionsession_test
        application/coreengine.h
        tests/connectionsession_test.cpp
        application/connectionsession.cpp
        core/connectionsessionstate.cpp
    )
    target_include_directories(connectionsession_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(connectionsession_test Qt::Core)
    add_test(NAME connectionsession_test COMMAND connectionsession_test)

    add_executable(applicationshutdown_test tests/applicationshutdown_test.cpp
        application/applicationshutdown.cpp application/connectionsession.cpp
        core/connectionsessionstate.cpp application/systemproxysession.cpp application/coreengine.h)
    target_link_libraries(applicationshutdown_test PRIVATE Qt6::Core Qt6::Concurrent)
    add_test(NAME applicationshutdown_test COMMAND applicationshutdown_test)
    set_tests_properties(applicationshutdown_test PROPERTIES TIMEOUT 15)

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
        application/profileservice.cpp application/defaultsettings.cpp application/settingsmigrator.cpp
    )
    target_include_directories(profileservice_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profileservice_test Qt::Core)
    add_test(NAME profileservice_test COMMAND profileservice_test)

    add_executable(profilemanager_test
        tests/profilemanager_test.cpp
        infrastructure/settings/profilemanager.cpp
        application/settingsmigrator.cpp application/defaultsettings.cpp
    )
    target_include_directories(profilemanager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profilemanager_test Qt::Core)
    add_test(NAME profilemanager_test COMMAND profilemanager_test)

    add_executable(configurationguidedialog_test
        tests/configurationguidedialog_test.cpp
        infrastructure/settings/credentialaccess.cpp application/profilecredentials.cpp application/profileservice.cpp
        presentation/presentationhelpers.cpp
        presentation/widgets/serversettingswidget.cpp
        application/settingsmigrator.cpp application/defaultsettings.cpp application/profileconfiguration.cpp
        presentation/dialogs/configurationguidedialog/configurationguidedialog.cpp
        presentation/dialogs/authinfowindow/authinfowindow.cpp
    )
    target_include_directories(configurationguidedialog_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(configurationguidedialog_test
        justconnect_engine
        Qt6::Concurrent
        Qt::Core
        Qt::Gui
        Qt::Widgets
    )
    justconnect_core_runtime(configurationguidedialog_test justconnect_core)
    add_test(NAME configurationguidedialog_test COMMAND configurationguidedialog_test)
    set_tests_properties(configurationguidedialog_test PROPERTIES
        TIMEOUT 30
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
