#import <AppKit/AppKit.h>
#include <QWidget>
#include <initializer_list>

bool hasBlendedNativeFrame(QWidget &widget, bool isHome)
{
    auto *view = reinterpret_cast<NSView *>(widget.winId());
    NSWindow *window = view.window;
    if (window.titleVisibility != NSWindowTitleHidden || window.title.length == 0
        || !(window.styleMask & NSWindowStyleMaskTitled) || !window.titlebarAppearsTransparent
        || !(window.styleMask & NSWindowStyleMaskFullSizeContentView) || widget.contentsRect().top() <= 0)
        return false;
    NSButton *close = [window standardWindowButton:NSWindowCloseButton];
    if (!close || close.isHidden) return false;
    if (!isHome) return true;
    for (auto type : {NSWindowMiniaturizeButton, NSWindowZoomButton}) {
        NSButton *button = [window standardWindowButton:type];
        if (!button || button.isHidden)
            return false;
    }
    return true;
}

bool acknowledgeMacUpdateInformation()
{
    NSWindow *alert = NSApp.modalWindow;
    if (!alert.isVisible || alert.sheetParent || alert.animationBehavior!=NSWindowAnimationBehaviorNone) return false;
    auto *button = alert.defaultButtonCell.controlView;
    if (![button isKindOfClass:[NSButton class]]) return false;
    [(NSButton *)button performClick:nil];
    return true;
}

bool macUpdateInformationIsOpen()
{
    return NSApp.modalWindow != nil;
}
