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

bool acknowledgeMacUpdateInformation(QWidget &owner)
{
    auto *view = reinterpret_cast<NSView *>(owner.winId());
    NSWindow *sheet = view.window.attachedSheet;
    if (!sheet.isVisible) return false;
    auto *button = sheet.defaultButtonCell.controlView;
    if (![button isKindOfClass:[NSButton class]]) return false;
    [(NSButton *)button performClick:nil];
    return true;
}

bool macUpdateInformationIsOpen(QWidget &owner)
{
    auto *view = reinterpret_cast<NSView *>(owner.winId());
    return view.window.attachedSheet != nil;
}
