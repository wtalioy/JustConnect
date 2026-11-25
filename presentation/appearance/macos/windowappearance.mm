#import <AppKit/AppKit.h>

#include <QGuiApplication>
#include <QWidget>

namespace ApplicationAppearance {
void blendNativeTitleBar(QWidget &window)
{
    if (QGuiApplication::platformName() != QStringLiteral("cocoa")) return;
    auto *view = reinterpret_cast<NSView *>(window.winId());
    view.window.titleVisibility = NSWindowTitleHidden;
    // Qt 6.12's title-bar flag mask is truncated when Cocoa BOOL is a byte on Intel.
    view.window.titlebarAppearsTransparent = YES;
}
}
