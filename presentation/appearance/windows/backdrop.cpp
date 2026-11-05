#include "../applicationappearance.h"
#include <QWidget>
#include <QGuiApplication>
#include <qt_windows.h>
#include <dwmapi.h>

bool ApplicationAppearance::enableNativeBackdrop(QWidget *window) {
    if (QGuiApplication::platformName()!="windows") return false;
    window->setAttribute(Qt::WA_TranslucentBackground);
    const auto handle=reinterpret_cast<HWND>(window->winId());
    const BOOL dark=FALSE;
    DwmSetWindowAttribute(handle,DWMWA_USE_IMMERSIVE_DARK_MODE,&dark,sizeof(dark));
    const DWM_SYSTEMBACKDROP_TYPE material=DWMSBT_TRANSIENTWINDOW;
    if (FAILED(DwmSetWindowAttribute(handle,DWMWA_SYSTEMBACKDROP_TYPE,&material,sizeof(material)))) {
        window->setAttribute(Qt::WA_TranslucentBackground,false);
        return false;
    }
    const MARGINS margins{-1,-1,-1,-1};
    if (SUCCEEDED(DwmExtendFrameIntoClientArea(handle,&margins))) return true;
    const DWM_SYSTEMBACKDROP_TYPE none=DWMSBT_NONE;
    DwmSetWindowAttribute(handle,DWMWA_SYSTEMBACKDROP_TYPE,&none,sizeof(none));
    window->setAttribute(Qt::WA_TranslucentBackground,false);
    return false;
}
