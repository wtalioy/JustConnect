#include "presentation/main/mainwindow.h"
#include "presentation/presentationhelpers.h"

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

bool MainWindow::showNativeUpdateInformation(const QString &title,const QString &description)
{
    if (QGuiApplication::platformName()!=QStringLiteral("cocoa")) return false;
    if (!isVisible() || isMinimized()) PresentationHelpers::activateWindow(this);
    auto *alert = [[NSAlert alloc] init];
    alert.alertStyle = NSAlertStyleInformational;
    alert.messageText = title.toNSString();
    alert.informativeText = description.toNSString();
    [alert addButtonWithTitle:QCoreApplication::translate("QPlatformTheme","OK").toNSString()];
    // Avoid the sheet dismissal transition for this brief confirmation.
    alert.window.animationBehavior = NSWindowAnimationBehaviorNone;
    while ([alert runModal] == NSModalResponseContinue) {}
    [alert release];
    return true;
}
