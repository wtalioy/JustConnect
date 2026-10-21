function(justconnect_core_ui_tests TARGET ENGINE LIBRARY)
    add_executable(${TARGET}
        "${REPO}/tests/coreengineui_test.cpp"
        "${REPO}/application/connectionsession.cpp"
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
        "${REPO}/presentation/coordinators/connectionuicontroller.cpp"
        "${REPO}/presentation/dialogs/authinfowindow/authinfowindow.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/graphcaptchawindow.cpp"
        "${REPO}/presentation/dialogs/graphcaptchawindow/captchacanvas.cpp"
        "${REPO}/presentation/dialogs/ssologinwebview/ssologinwebview.cpp"
        "${REPO}/presentation/dialogs/loginwindow/loginwindow.cpp"
        "${REPO}/presentation/presentationhelpers.cpp")
    set_target_properties(${TARGET} PROPERTIES AUTOMOC ON AUTOUIC ON)
    target_link_libraries(${TARGET} PRIVATE ${ENGINE} Qt6::WebEngineWidgets Qt6::Concurrent)
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
