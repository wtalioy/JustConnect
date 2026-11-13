include_guard(GLOBAL)

function(justconnect_add_connection_ui TARGET)
    target_sources(${TARGET} PRIVATE
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
endfunction()
