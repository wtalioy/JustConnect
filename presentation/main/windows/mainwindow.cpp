#include "presentation/main/mainwindow.h"

#include <QGuiApplication>
#include <qt_windows.h>
#include <commctrl.h>

#pragma comment(linker, "\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

bool MainWindow::showNativeUpdateInformation(const QString &title,const QString &description)
{
    if (QGuiApplication::platformName()!=QStringLiteral("windows")) return false;
    const auto caption = title.toStdWString();
    const auto content = description.toStdWString();
    TASKDIALOGCONFIG dialog{};
    dialog.cbSize = sizeof(dialog);
    dialog.hwndParent = reinterpret_cast<HWND>(winId());
    dialog.dwFlags = TDF_ALLOW_DIALOG_CANCELLATION | TDF_POSITION_RELATIVE_TO_WINDOW;
    dialog.dwCommonButtons = TDCBF_OK_BUTTON;
    dialog.pszWindowTitle = caption.c_str();
    dialog.pszMainIcon = TD_INFORMATION_ICON;
    dialog.pszContent = content.c_str();
    return SUCCEEDED(TaskDialogIndirect(&dialog,nullptr,nullptr,nullptr));
}
