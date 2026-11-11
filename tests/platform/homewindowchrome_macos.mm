#import <AppKit/AppKit.h>
#include <QWidget>
#include <initializer_list>

bool hasUntitledNativeHomeFrame(QWidget &widget)
{
    auto *view = reinterpret_cast<NSView *>(widget.winId());
    NSWindow *window = view.window;
    if (window.titleVisibility != NSWindowTitleHidden || window.title.length == 0
        || !(window.styleMask & NSWindowStyleMaskTitled))
        return false;
    for (auto type : {NSWindowCloseButton, NSWindowMiniaturizeButton, NSWindowZoomButton}) {
        NSButton *button = [window standardWindowButton:type];
        if (!button || button.isHidden)
            return false;
    }
    return true;
}
