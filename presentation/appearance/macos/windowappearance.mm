#import <AppKit/AppKit.h>

#include <QGuiApplication>
#include <QWidget>

namespace ApplicationAppearance {
void hideNativeWindowTitle(QWidget &window)
{
    if (QGuiApplication::platformName() != QStringLiteral("cocoa")) return;
    auto *view = reinterpret_cast<NSView *>(window.winId());
    view.window.titleVisibility = NSWindowTitleHidden;
}
}
