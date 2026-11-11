include("${CMAKE_CURRENT_LIST_DIR}/../cmake/UiResources.cmake")

function(justconnect_core_ui_tests TARGET ENGINE LIBRARY PLATFORM)
    add_executable(coexistencenetworkaccess_test "${REPO}/tests/coexistencenetworkaccess_test.cpp")
    set_target_properties(coexistencenetworkaccess_test PROPERTIES AUTOMOC ON)
    target_link_libraries(coexistencenetworkaccess_test PRIVATE ${ENGINE} Qt6::Concurrent justconnect_application)
    justconnect_core_runtime(coexistencenetworkaccess_test ${LIBRARY})
    add_test(NAME coexistencenetworkaccess_test COMMAND coexistencenetworkaccess_test)
    set_tests_properties(coexistencenetworkaccess_test PROPERTIES TIMEOUT 30)
    add_executable(${TARGET}
        "${REPO}/tests/coreengineui_test.cpp"
        "${REPO}/presentation/dialogs/networkpolicywindow.cpp"
        "${REPO}/infrastructure/settings/credentialaccess.cpp"
        "${REPO}/presentation/coordinators/authdialogcoordinator.cpp"
        "${REPO}/presentation/coordinators/authenticationcachecoordinator.cpp"
        "${REPO}/presentation/coordinators/connectionuicontroller.cpp"
        "${REPO}/presentation/coordinators/controllerselectioncoordinator.cpp"
        "${REPO}/infrastructure/settings/savedconnectionstore.cpp"
        "${REPO}/presentation/dialogs/settingwindow/settingwindow.cpp"
        "${REPO}/presentation/widgets/serversettingswidget.cpp"
        "${REPO}/presentation/widgets/applicationpreferenceswidget.cpp"
        "${REPO}/presentation/i18n/applicationlanguage.cpp"
        "${REPO}/infrastructure/storage/applicationpaths.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/captchacanvas.cpp"
        "${REPO}/presentation/dialogs/ssologinwebview/ssologinwebview.cpp"
        "${REPO}/presentation/dialogs/loginwindow/loginwindow.cpp"
        "${REPO}/presentation/presentationhelpers.cpp")
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON AUTOUIC ON)
    target_link_libraries(${TARGET} PRIVATE ${ENGINE} ${PLATFORM} justconnect_signin_browser Qt6::Concurrent justconnect_ui_resources)
    justconnect_core_runtime(${TARGET} ${LIBRARY})
    add_test(NAME ${TARGET} COMMAND ${TARGET})
    set_tests_properties(${TARGET} PROPERTIES TIMEOUT 60 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
    add_test(NAME ${TARGET}_browser COMMAND ${TARGET} --browser)
    set_tests_properties(${TARGET}_browser PROPERTIES TIMEOUT 60
        ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA};QT_LOGGING_RULES=justconnect.signin.debug=true")
    add_test(NAME ${TARGET}_protocol
        COMMAND "${CMAKE_COMMAND}" -E env "JC_NATIVE_PROTOCOL_HOST=$<TARGET_FILE:${TARGET}>"
            GOTOOLCHAIN=local GOWORK=off GOENV=off CGO_ENABLED=1 GOEXPERIMENT=cgocheck2
            "${GO_EXECUTABLE}" test -mod=readonly -count=1 -timeout 60s -run "^TestNativeProtocolHost$" -v ./internal/bridge)
    set_tests_properties(${TARGET}_protocol PROPERTIES TIMEOUT 90 WORKING_DIRECTORY "${CORE}"
        ENVIRONMENT "QT_QPA_PLATFORM=${JC_BROWSER_QPA}")
endfunction()

function(justconnect_network_policy_tests)
    add_executable(windows_networkownership_test "${REPO}/tests/platform/networkownership_windows_test.cpp"
        "${REPO}/infrastructure/networkhelper/windows/networkownership.cpp")
    target_include_directories(windows_networkownership_test PRIVATE "${REPO}")
    target_link_libraries(windows_networkownership_test PRIVATE Qt6::Core Qt6::Network)
    add_test(NAME windows_networkownership_test COMMAND windows_networkownership_test)
    add_executable(networkprotection_test "${REPO}/tests/networkprotection_test.cpp"
        "${REPO}/infrastructure/networkhelper/windows/networkhelperpreparation.cpp")
    target_include_directories(networkprotection_test PRIVATE "${REPO}")
    target_link_libraries(networkprotection_test PRIVATE Qt6::Core Qt6::Network justconnect_application)
    add_test(NAME networkprotection_test COMMAND networkprotection_test)
    add_executable(networkpolicysession_test "${REPO}/tests/networkpolicysession_test.cpp")
    set_target_properties(networkpolicysession_test PROPERTIES AUTOMOC ON)
    target_include_directories(networkpolicysession_test PRIVATE "${REPO}")
    target_link_libraries(networkpolicysession_test PRIVATE Qt6::Core Qt6::Network Qt6::Concurrent justconnect_application)
    add_test(NAME networkpolicysession_test COMMAND networkpolicysession_test)
    set_tests_properties(networkpolicysession_test PROPERTIES TIMEOUT 15)
    add_executable(networkpolicywindow_test "${REPO}/tests/networkpolicywindow_test.cpp"
        "${REPO}/presentation/presentationhelpers.cpp"
        "${REPO}/presentation/dialogs/networkpolicywindow.cpp")
    set_target_properties(networkpolicywindow_test PROPERTIES AUTOMOC ON)
    target_include_directories(networkpolicywindow_test PRIVATE "${REPO}")
    target_link_libraries(networkpolicywindow_test PRIVATE Qt6::Widgets Qt6::Network Qt6::Concurrent justconnect_application justconnect_ui_resources)
    add_test(NAME networkpolicywindow_test COMMAND networkpolicywindow_test)
    set_tests_properties(networkpolicywindow_test PROPERTIES TIMEOUT 15 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endfunction()
