cmake_minimum_required(VERSION 3.20)
project(JustConnect)

if(NOT WIN32 AND NOT APPLE)
    message(FATAL_ERROR "JustConnect supports only Windows and macOS")
endif()

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
    REQUIRED
)

include(cmake/CoreLibrary.cmake)
include(cmake/Application.cmake)
include(cmake/SignInBrowser.cmake)
justconnect_signin_browser(justconnect_signin_browser)
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
else()
    set(CORE_DATA_DESTINATION ".")
endif()
install(FILES "${CMAKE_BINARY_DIR}/core-toolchain.txt" "${CMAKE_BINARY_DIR}/source-revision.txt"
    DESTINATION "${CORE_DATA_DESTINATION}" COMPONENT CoreRuntime)
install(FILES "${CORE}/UPSTREAM.md" "${CORE}/LICENSE.zju-connect" "${REPO}/LICENSE" "${REPO}/resource/LICENSE.lucide"
    DESTINATION "${CORE_DATA_DESTINATION}/licenses" COMPONENT CoreRuntime)
install(FILES "${CORE}/internal/ping/LICENSE"
    DESTINATION "${CORE_DATA_DESTINATION}/licenses" RENAME LICENSE.ping COMPONENT CoreRuntime)

include(cmake/UiResources.cmake)
add_library(justconnect_desktop OBJECT
    infrastructure/process/applicationinstancelock.cpp
    infrastructure/process/terminationrequests.cpp
    presentation/i18n/applicationlanguage.cpp
    presentation/widgets/applicationpreferenceswidget.cpp
    presentation/appearance/applicationappearance.cpp
    presentation/main/mainwindow.cpp
    presentation/main/mainwindow.ui
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
    presentation/dialogs/settingwindow/settingwindow.ui
    presentation/dialogs/loginwindow/loginwindow.cpp
    presentation/dialogs/loginwindow/loginwindow.ui
    presentation/dialogs/ssologinwebview/ssologinwebview.cpp
    presentation/dialogs/ssologinwebview/ssologinwebview.ui
    presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp
    presentation/dialogs/graphcaptchawindow/graphcaptchawindow.ui
    presentation/dialogs/graphcaptchawindow/captchacanvas.cpp
    infrastructure/settings/profilemanager.cpp
)
target_sources(justconnect_desktop INTERFACE "$<TARGET_OBJECTS:justconnect_ui_resources>")

find_package(Qt6 REQUIRED COMPONENTS LinguistTools)
set(justconnect_desktop_catalog "${CMAKE_CURRENT_SOURCE_DIR}/resource/translations/justconnect_zh_CN.ts")
qt_add_translations(justconnect_desktop
    TS_FILES "${justconnect_desktop_catalog}"
    RESOURCE_PREFIX "/i18n"
    MERGE_QT_TRANSLATIONS
    QT_TRANSLATION_CATALOGS qtbase)

if(WIN32)
    message("Building for Windows")

    enable_language(RC)
    configure_file(resource/app-icon.rc.in app-icon.rc @ONLY)
    add_executable(${PROJECT_NAME} WIN32
        main.cpp
        "${CMAKE_CURRENT_BINARY_DIR}/app-icon.rc")

    set(PLATFORM_LIBS shell32)
else()
    message("Building for MacOS")

    set_source_files_properties(resource/JustConnect.icns PROPERTIES MACOSX_PACKAGE_LOCATION Resources)
    add_executable(${PROJECT_NAME} MACOSX_BUNDLE
        main.cpp
        resource/JustConnect.icns)

    set_target_properties(${PROJECT_NAME}
        PROPERTIES MACOSX_BUNDLE_INFO_PLIST "${CMAKE_CURRENT_SOURCE_DIR}/resource/Info.plist")
endif()

target_link_libraries(justconnect_desktop
        PUBLIC
        Qt::Core
        Qt::Concurrent
        Qt::Gui
        Qt::Widgets
        Qt::Network
        Qt::Svg
        justconnect_signin_browser
        justconnect_engine
        justconnect_network_access
        justconnect_platform
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


if(BUILD_TESTING)
    add_executable(appearance_test tests/appearance_test.cpp presentation/appearance/applicationappearance.cpp)
    target_link_libraries(appearance_test PRIVATE Qt6::Widgets justconnect_ui_resources)
    target_include_directories(appearance_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    add_test(NAME appearance_test COMMAND appearance_test)
    add_test(NAME appearance_scaled_test COMMAND appearance_test)
    set_tests_properties(appearance_scaled_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA};QT_SCALE_FACTOR=2")
    set_tests_properties(appearance_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA}")
    add_executable(applicationinstancelock_test tests/applicationinstancelock_test.cpp
        infrastructure/process/applicationinstancelock.cpp)
    target_include_directories(applicationinstancelock_test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
    target_link_libraries(applicationinstancelock_test PRIVATE Qt6::Core)
    add_test(NAME applicationinstancelock_test COMMAND applicationinstancelock_test)
    set_tests_properties(applicationinstancelock_test PROPERTIES TIMEOUT 40)
    add_executable(serversettingswidget_test tests/serversettingswidget_test.cpp
        presentation/presentationhelpers.cpp
        presentation/widgets/serversettingswidget.cpp)
    target_link_libraries(serversettingswidget_test PRIVATE Qt6::Widgets justconnect_application justconnect_ui_resources)
    add_test(NAME serversettingswidget_test COMMAND serversettingswidget_test)
    set_tests_properties(serversettingswidget_test PROPERTIES ENVIRONMENT "QT_QPA_PLATFORM=offscreen" TIMEOUT 30)
    justconnect_system_integration_tests(platformbackend_test justconnect_platform)
    justconnect_credential_tests(credentialstore_test justconnect_platform)
    justconnect_autostart_tests(autostart_test justconnect_platform)
    add_executable(settingwindow_test tests/settingwindow_test.cpp)
    target_link_libraries(settingwindow_test PRIVATE justconnect_desktop)
    justconnect_core_runtime(settingwindow_test justconnect_core)
    add_test(NAME settingwindow_test COMMAND settingwindow_test)
    set_tests_properties(settingwindow_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
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
    add_test(NAME mainwindow_native_test COMMAND mainwindow_test --native-home)
    set_tests_properties(mainwindow_native_test PROPERTIES TIMEOUT 45 ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA};QT_SCALE_FACTOR=1.5")
    add_test(NAME mainwindow_auth_language_test COMMAND mainwindow_test --auth-language)
    set_tests_properties(mainwindow_auth_language_test PROPERTIES TIMEOUT 60 ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA};QT_SCALE_FACTOR=2")
    add_test(NAME mainwindow_chinese_startup_test COMMAND mainwindow_test --chinese-startup)
    add_test(NAME mainwindow_invalid_language_test COMMAND mainwindow_test --invalid-language)
    add_test(NAME mainwindow_active_preferences_test COMMAND mainwindow_test --active-preferences)
    add_test(NAME mainwindow_profile_language_test COMMAND mainwindow_test --profile-language)
    set_tests_properties(mainwindow_profile_language_test PROPERTIES TIMEOUT 30 ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA};QT_SCALE_FACTOR=1.5")
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
    file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/ui-report")
    set_property(TEST mainwindow_native_test mainwindow_profile_language_test mainwindow_auth_language_test
        APPEND PROPERTY ENVIRONMENT "JC_UI_REPORT_DIR=${CMAKE_CURRENT_BINARY_DIR}/ui-report")
    # The package verifier runs this probe against the installed runtime.
    add_executable(signinbrowser_test tests/signinbrowser_test.cpp)
    target_link_libraries(signinbrowser_test PRIVATE justconnect_signin_browser)

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

    add_executable(graphcaptchawindow_test
        tests/graphcaptchawindow_test.cpp
        presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp
        presentation/dialogs/graphcaptchawindow/captchacanvas.cpp)
    target_include_directories(graphcaptchawindow_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(graphcaptchawindow_test Qt::Core Qt::Gui Qt::Widgets justconnect_ui_resources)
    add_test(NAME graphcaptchawindow_test COMMAND graphcaptchawindow_test)
    set_tests_properties(graphcaptchawindow_test PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()
