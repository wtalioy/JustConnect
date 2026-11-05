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
include(cmake/Application.cmake)
justconnect_core_library(justconnect_core)
justconnect_core_engine(justconnect_engine justconnect_core justconnect_platform)
include(cmake/SystemIntegration.cmake)
justconnect_system_integration(justconnect_platform)
include(cmake/NetworkAccess.cmake)
justconnect_network_access(justconnect_network_access justconnect_platform)
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

add_library(justconnect_desktop OBJECT
    infrastructure/process/terminationrequests.cpp
    presentation/i18n/applicationlanguage.cpp
    presentation/dialogs/applicationpreferences/applicationpreferencesdialog.cpp
    presentation/appearance/applicationappearance.cpp
    presentation/main/mainwindow.cpp
    presentation/main/mainwindowcoordinator.cpp
    presentation/coordinators/authdialogcoordinator.cpp
    presentation/coordinators/authenticationcachecoordinator.cpp
    presentation/coordinators/connectiondiagnostics.cpp
    presentation/coordinators/connectionuicontroller.cpp
    presentation/coordinators/controllerselectioncoordinator.cpp
    presentation/dialogs/networkpolicywindow.cpp
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

find_package(Qt6 REQUIRED COMPONENTS LinguistTools)
set(justconnect_desktop_catalog "${CMAKE_CURRENT_SOURCE_DIR}/resource/translations/justconnect_zh_CN.ts")
qt_add_translations(justconnect_desktop
    TS_FILES "${justconnect_desktop_catalog}"
    RESOURCE_PREFIX "/i18n")

if(WIN32)
    target_sources(justconnect_desktop PRIVATE presentation/appearance/windows/backdrop.cpp)
    target_link_libraries(justconnect_desktop PUBLIC dwmapi)
elseif(APPLE)
    target_sources(justconnect_desktop PRIVATE presentation/appearance/macos/backdrop.mm)
    target_link_libraries(justconnect_desktop PUBLIC "-framework AppKit")
endif()

if (WIN32)
    message("Building for Windows")

    add_executable(${PROJECT_NAME} WIN32
        main.cpp)

    set(PLATFORM_LIBS shell32)
elseif(APPLE)
    message("Building for MacOS")

    add_executable(${PROJECT_NAME} MACOSX_BUNDLE
        main.cpp)

    set_target_properties(${PROJECT_NAME}
        PROPERTIES MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/resource/Info.plist")
else()
    add_executable(${PROJECT_NAME}
        main.cpp)

    install(
        TARGETS ${PROJECT_NAME}
        RUNTIME DESTINATION bin)
endif()

set(QAPPLICATION_CLASS QApplication CACHE STRING "Inheritance class for SingleApplication")

add_subdirectory(singleapplication)

target_link_libraries(justconnect_desktop
        PUBLIC
        Qt::Core
        Qt::Concurrent
        Qt::Gui
        Qt::Widgets
        Qt::Network
        Qt::Svg
        Qt::WebEngineWidgets
        justconnect_engine
        justconnect_network_access
        justconnect_platform
        SingleApplication::SingleApplication
        ${PLATFORM_LIBS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE justconnect_desktop)
justconnect_core_runtime(${PROJECT_NAME} justconnect_core)
add_dependencies(${PROJECT_NAME} JustConnectProxyRecovery)
if(APPLE)
    add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
        COMMAND "${CMAKE_COMMAND}" -E copy_if_different "$<TARGET_FILE:JustConnectProxyRecovery>" "$<TARGET_FILE_DIR:${PROJECT_NAME}>/")
endif()

include(CTest)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
    add_executable(JustConnectIconRenderer scripts/render-icon.cpp)
    target_link_libraries(JustConnectIconRenderer PRIVATE Qt6::Svg Qt6::Gui)
    add_custom_command(OUTPUT "${CMAKE_CURRENT_BINARY_DIR}/icon.png"
        COMMAND JustConnectIconRenderer "${CMAKE_CURRENT_SOURCE_DIR}/resource/icon.svg" "${CMAKE_CURRENT_BINARY_DIR}/icon.png"
        DEPENDS JustConnectIconRenderer "${CMAKE_CURRENT_SOURCE_DIR}/resource/icon.svg"
        VERBATIM)
    add_custom_target(linux_package_icon ALL DEPENDS "${CMAKE_CURRENT_BINARY_DIR}/icon.png")
    add_dependencies(${PROJECT_NAME} linux_package_icon)
endif()

if(BUILD_TESTING)
    add_executable(singleapplication_test tests/singleapplication_test.cpp)
    target_link_libraries(singleapplication_test PRIVATE SingleApplication::SingleApplication)
    add_test(NAME singleapplication_test COMMAND singleapplication_test)
    set_tests_properties(singleapplication_test PROPERTIES TIMEOUT 20 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(serversettingswidget_test tests/serversettingswidget_test.cpp
        presentation/widgets/serversettingswidget.cpp)
    target_link_libraries(serversettingswidget_test PRIVATE Qt6::Widgets justconnect_application)
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
            presentation/coordinators/controllerselectioncoordinator.cpp
            presentation/presentationhelpers.cpp
            infrastructure/settings/profilemanager.cpp
            infrastructure/storage/applicationpaths.cpp infrastructure/settings/credentialaccess.cpp)
        target_link_libraries(settingwindow_test PRIVATE justconnect_engine justconnect_platform Qt6::WebEngineWidgets Qt6::Concurrent justconnect_application)
        add_test(NAME settingwindow_test COMMAND settingwindow_test)
        set_tests_properties(settingwindow_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    endif()
    add_test(NAME core_self_test COMMAND ${PROJECT_NAME} --core-self-test)
    set_tests_properties(core_self_test PROPERTIES TIMEOUT 30 PASS_REGULAR_EXPRESSION "\"ok\":true")
    include(tests/CoreEngineTests.cmake)
    justconnect_core_ui_tests(coreengineui_test justconnect_engine justconnect_core justconnect_platform)
    get_filename_component(justconnect_catalog_name "${justconnect_desktop_catalog}" NAME_WE)
    add_test(NAME networkpolicywindow_language_test COMMAND networkpolicywindow_test --catalog "${CMAKE_CURRENT_BINARY_DIR}/${justconnect_catalog_name}.qm")
    set_tests_properties(networkpolicywindow_language_test PROPERTIES TIMEOUT 15 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(connectiondiagnostics_test tests/connectiondiagnostics_test.cpp presentation/coordinators/connectiondiagnostics.cpp)
    target_link_libraries(connectiondiagnostics_test PRIVATE justconnect_application)
    add_test(NAME connectiondiagnostics_test COMMAND connectiondiagnostics_test)
    set_tests_properties(connectiondiagnostics_test PROPERTIES TIMEOUT 15)
    add_executable(mainwindow_test tests/mainwindow_test.cpp)
    add_dependencies(mainwindow_test JustConnectProxyRecovery)
    target_link_libraries(mainwindow_test PRIVATE justconnect_desktop)
    justconnect_core_runtime(mainwindow_test justconnect_core)
    add_test(NAME mainwindow_test COMMAND mainwindow_test)
    add_test(NAME mainwindow_auth_language_test COMMAND mainwindow_test --auth-language)
    set_tests_properties(mainwindow_auth_language_test PROPERTIES TIMEOUT 60 ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")
    add_test(NAME mainwindow_chinese_startup_test COMMAND mainwindow_test --chinese-startup)
    add_test(NAME mainwindow_invalid_language_test COMMAND mainwindow_test --invalid-language)
    add_test(NAME mainwindow_active_preferences_test COMMAND mainwindow_test --active-preferences)
    add_test(NAME mainwindow_profile_language_test COMMAND mainwindow_test --profile-language)
    set_tests_properties(mainwindow_profile_language_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
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
    set_tests_properties(mainwindow_test mainwindow_chinese_startup_test mainwindow_invalid_language_test mainwindow_active_preferences_test mainwindow_close_exit_test mainwindow_preferences_failure_test mainwindow_termination_test mainwindow_system_session_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_executable(webengine_test tests/webengine_test.cpp)
    target_link_libraries(webengine_test Qt::WebEngineWidgets)
    add_test(NAME webengine_test COMMAND webengine_test)
    set_tests_properties(webengine_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu"
        TIMEOUT 20)

    add_executable(applicationlogger_test
        tests/applicationlogger_test.cpp)
    target_include_directories(applicationlogger_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(applicationlogger_test Qt::Core justconnect_application)
    add_test(NAME applicationlogger_test COMMAND applicationlogger_test)

    add_executable(applicationlogfile_test
        tests/applicationlogfile_test.cpp
        infrastructure/logging/applicationlogfile.cpp)
    target_include_directories(applicationlogfile_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(applicationlogfile_test Qt::Core)
    add_test(NAME applicationlogfile_test COMMAND applicationlogfile_test)

    add_executable(credentialaccess_test tests/credentialaccess_test.cpp infrastructure/settings/credentialaccess.cpp)
    target_link_libraries(credentialaccess_test PRIVATE Qt6::Core Qt6::Concurrent justconnect_application)
    add_test(NAME credentialaccess_test COMMAND credentialaccess_test)
    set_tests_properties(credentialaccess_test PROPERTIES TIMEOUT 20)

    add_executable(profilecredentials_test tests/profilecredentials_test.cpp)
    target_link_libraries(profilecredentials_test PRIVATE Qt6::Core justconnect_application)
    add_test(NAME profilecredentials_test COMMAND profilecredentials_test)

    add_executable(settingsprofileloader_test
        tests/settingsprofileloader_test.cpp)
    target_include_directories(settingsprofileloader_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(settingsprofileloader_test Qt::Core justconnect_application)
    add_test(NAME settingsprofileloader_test COMMAND settingsprofileloader_test)

    add_executable(connectionsessionstate_test
        tests/connectionsessionstate_test.cpp)
    target_include_directories(connectionsessionstate_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(connectionsessionstate_test Qt::Core justconnect_application)
    add_test(NAME connectionsessionstate_test COMMAND connectionsessionstate_test)

    justconnect_network_policy_tests()

    add_executable(connectionsession_test
        tests/connectionsession_test.cpp)
    target_include_directories(connectionsession_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(connectionsession_test Qt::Core justconnect_application)
    add_test(NAME connectionsession_test COMMAND connectionsession_test)

    add_executable(applicationshutdown_test tests/applicationshutdown_test.cpp)
    target_link_libraries(applicationshutdown_test PRIVATE Qt6::Core Qt6::Concurrent justconnect_application)
    add_test(NAME applicationshutdown_test COMMAND applicationshutdown_test)
    set_tests_properties(applicationshutdown_test PROPERTIES TIMEOUT 15)

    add_executable(systemproxysession_test
        tests/systemproxysession_test.cpp)
    target_include_directories(systemproxysession_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(systemproxysession_test Qt::Core Qt::Concurrent justconnect_application)
    add_test(NAME systemproxysession_test COMMAND systemproxysession_test)

    add_executable(updatechecker_test
        tests/updatechecker_test.cpp
        infrastructure/update/updatechecker.cpp)
    target_include_directories(updatechecker_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(updatechecker_test justconnect_engine Qt::Core Qt::Gui Qt::Widgets Qt::Network)
    justconnect_core_runtime(updatechecker_test justconnect_core)
    add_test(NAME updatechecker_test COMMAND updatechecker_test)

    add_executable(settingsmigrator_test
        tests/settingsmigrator_test.cpp)
    target_include_directories(settingsmigrator_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(settingsmigrator_test Qt::Core justconnect_application)
    add_test(NAME settingsmigrator_test COMMAND settingsmigrator_test)

    add_executable(profileservice_test
        tests/profileservice_test.cpp)
    target_include_directories(profileservice_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profileservice_test Qt::Core justconnect_application)
    add_test(NAME profileservice_test COMMAND profileservice_test)

    add_executable(profilemanager_test
        tests/profilemanager_test.cpp
        infrastructure/settings/profilemanager.cpp)
    target_include_directories(profilemanager_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(profilemanager_test Qt::Core justconnect_application)
    add_test(NAME profilemanager_test COMMAND profilemanager_test)

    add_executable(configurationguidedialog_test
        tests/configurationguidedialog_test.cpp
        infrastructure/settings/credentialaccess.cpp
        presentation/presentationhelpers.cpp
        presentation/widgets/serversettingswidget.cpp
        presentation/dialogs/configurationguidedialog/configurationguidedialog.cpp
        presentation/dialogs/authinfowindow/authinfowindow.cpp
        presentation/coordinators/controllerselectioncoordinator.cpp
        infrastructure/settings/profilemanager.cpp)
    target_include_directories(configurationguidedialog_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(configurationguidedialog_test
        justconnect_engine
        Qt6::Concurrent
        Qt::Core
        Qt::Gui
        Qt::Widgets
        justconnect_application)
    justconnect_core_runtime(configurationguidedialog_test justconnect_core)
    add_test(NAME configurationguidedialog_test COMMAND configurationguidedialog_test)
    set_tests_properties(configurationguidedialog_test PROPERTIES
        TIMEOUT 30
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")

    add_executable(graphcaptchawindow_test
        tests/graphcaptchawindow_test.cpp
        presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp
        presentation/dialogs/graphcaptchawindow/captchacanvas.cpp)
    target_include_directories(graphcaptchawindow_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(graphcaptchawindow_test Qt::Core Qt::Gui Qt::Widgets)
    add_test(NAME graphcaptchawindow_test COMMAND graphcaptchawindow_test)
    set_tests_properties(graphcaptchawindow_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
