#include "presentation/main/mainwindow.h"

#import <AppKit/AppKit.h>
#include <QGuiApplication>

void MainWindow::showEvent(QShowEvent *event)
{
    QMainWindow::showEvent(event);
    if (QGuiApplication::platformName() == QStringLiteral("cocoa")) {
        auto *view = reinterpret_cast<NSView *>(winId());
        view.window.titleVisibility = NSWindowTitleHidden;
    }
}
