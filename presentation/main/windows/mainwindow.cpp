#include "presentation/main/mainwindow.h"

#include <QGuiApplication>
#include <qt_windows.h>

bool MainWindow::showNativeUpdateInformation(const QString &title,const QString &description)
{
    if (QGuiApplication::platformName()!=QStringLiteral("windows")) return false;
    return MessageBoxW(reinterpret_cast<HWND>(winId()),description.toStdWString().c_str(),
        title.toStdWString().c_str(),MB_OK | MB_ICONINFORMATION)!=0;
}
