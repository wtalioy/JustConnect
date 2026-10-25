add_test(NAME coreabi_workflow_test COMMAND "${Python3_EXECUTABLE}" "${REPO}/tests/coreabi_workflow_test.py")
set_tests_properties(coreabi_workflow_test PROPERTIES TIMEOUT 10)
add_test(NAME windows_helper_sdk_test COMMAND "${Python3_EXECUTABLE}" "${REPO}/tests/windows_helper_sdk_test.py")
set_tests_properties(windows_helper_sdk_test PROPERTIES TIMEOUT 10)

function(justconnect_core_ui_tests TARGET ENGINE LIBRARY PLATFORM)
    add_executable(${TARGET}
        "${REPO}/tests/coreengineui_test.cpp"
        "${REPO}/application/applicationshutdown.cpp"
        "${REPO}/application/connectionsession.cpp"
        "${REPO}/application/networkpolicysession.cpp"
        "${REPO}/presentation/dialogs/networkpolicywindow.cpp"
        "${REPO}/application/applicationlogger.cpp"
        "${REPO}/application/systemproxysession.cpp"
        "${REPO}/application/profilecredentials.cpp"
        "${REPO}/application/profileservice.cpp"
        "${REPO}/application/defaultsettings.cpp"
        "${REPO}/application/settingsmigrator.cpp"
        "${REPO}/infrastructure/settings/credentialaccess.cpp"
        "${REPO}/application/profileconfiguration.cpp"
        "${REPO}/core/connectionsessionstate.cpp"
        "${REPO}/presentation/coordinators/authdialogcoordinator.cpp"
        "${REPO}/presentation/coordinators/authenticationcachecoordinator.cpp"
        "${REPO}/presentation/coordinators/connectionuicontroller.cpp"
        "${REPO}/presentation/dialogs/authinfowindow/authinfowindow.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/captchacanvas.cpp"
        "${REPO}/presentation/dialogs/ssologinwebview/ssologinwebview.cpp"
        "${REPO}/presentation/dialogs/loginwindow/loginwindow.cpp"
        "${REPO}/presentation/presentationhelpers.cpp")
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON AUTOUIC ON)
    target_link_libraries(${TARGET} PRIVATE ${ENGINE} ${PLATFORM} Qt6::WebEngineWidgets Qt6::Concurrent)
    justconnect_core_runtime(${TARGET} ${LIBRARY})
    add_test(NAME ${TARGET} COMMAND ${TARGET})
    set_tests_properties(${TARGET} PROPERTIES TIMEOUT 60
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")
    add_test(NAME ${TARGET}_protocol
        COMMAND "${CMAKE_COMMAND}" -E env "JC_NATIVE_PROTOCOL_HOST=$<TARGET_FILE:${TARGET}>"
            GOTOOLCHAIN=local GOWORK=off GOENV=off CGO_ENABLED=1 GOEXPERIMENT=cgocheck2
            "${GO_EXECUTABLE}" test -mod=readonly -count=1 -timeout 60s -run "^TestNativeProtocolHost$" -v ./internal/bridge)
    set_tests_properties(${TARGET}_protocol PROPERTIES TIMEOUT 90 WORKING_DIRECTORY "${CORE}"
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen;QTWEBENGINE_CHROMIUM_FLAGS=--disable-gpu")
endfunction()

function(justconnect_network_policy_tests)
    if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_executable(linux_networkownership_test "${REPO}/tests/platform/networkownership_linux_test.cpp"
            "${REPO}/infrastructure/platform/linux/networkownership.cpp")
        target_include_directories(linux_networkownership_test PRIVATE "${REPO}")
        target_link_libraries(linux_networkownership_test PRIVATE justconnect_network_helper Qt6::Network)
        add_test(NAME linux_networkownership_test COMMAND linux_networkownership_test)
        add_executable(linux_networkhelperpreparation_test "${REPO}/tests/platform/networkhelperpreparation_linux_test.cpp"
            "${REPO}/infrastructure/platform/linux/networkhelperpreparation.cpp" "${REPO}/application/networkprotection.cpp")
        target_include_directories(linux_networkhelperpreparation_test PRIVATE "${REPO}")
        target_link_libraries(linux_networkhelperpreparation_test PRIVATE justconnect_network_helper Qt6::Network)
        add_test(NAME linux_networkhelperpreparation_test COMMAND linux_networkhelperpreparation_test)
    endif()
    add_executable(networkprotection_test "${REPO}/tests/networkprotection_test.cpp" "${REPO}/application/networkprotection.cpp")
    target_include_directories(networkprotection_test PRIVATE "${REPO}")
    target_link_libraries(networkprotection_test PRIVATE Qt6::Core Qt6::Network)
    add_test(NAME networkprotection_test COMMAND networkprotection_test)
    add_executable(networkpolicysession_test "${REPO}/tests/networkpolicysession_test.cpp"
        "${REPO}/application/networkpolicysession.cpp" "${REPO}/application/networkprotection.cpp" "${REPO}/application/coreengine.h")
    set_target_properties(networkpolicysession_test PROPERTIES AUTOMOC ON)
    target_include_directories(networkpolicysession_test PRIVATE "${REPO}")
    target_link_libraries(networkpolicysession_test PRIVATE Qt6::Core Qt6::Network Qt6::Concurrent)
    add_test(NAME networkpolicysession_test COMMAND networkpolicysession_test)
    set_tests_properties(networkpolicysession_test PROPERTIES TIMEOUT 15)
    add_executable(networkpolicywindow_test "${REPO}/tests/networkpolicywindow_test.cpp"
        "${REPO}/presentation/dialogs/networkpolicywindow.cpp" "${REPO}/application/networkpolicysession.cpp"
        "${REPO}/application/networkprotection.cpp" "${REPO}/application/coreengine.h")
    set_target_properties(networkpolicywindow_test PROPERTIES AUTOMOC ON)
    target_include_directories(networkpolicywindow_test PRIVATE "${REPO}")
    target_link_libraries(networkpolicywindow_test PRIVATE Qt6::Widgets Qt6::Network Qt6::Concurrent)
    add_test(NAME networkpolicywindow_test COMMAND networkpolicywindow_test)
    set_tests_properties(networkpolicywindow_test PROPERTIES TIMEOUT 15 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endfunction()
