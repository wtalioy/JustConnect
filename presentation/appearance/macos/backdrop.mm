#include "../applicationappearance.h"
#include <QWidget>
#import <AppKit/AppKit.h>

bool ApplicationAppearance::enableNativeBackdrop(QWidget *window) {
    window->setAttribute(Qt::WA_TranslucentBackground);
    auto *view=reinterpret_cast<NSView *>(window->winId());
    auto *native=view.window;
    if (!native || !view.superview) {
        window->setAttribute(Qt::WA_TranslucentBackground,false);
        return false;
    }
    native.appearance=[NSAppearance appearanceNamed:NSAppearanceNameAqua];
    native.opaque=NO;
    native.backgroundColor=NSColor.clearColor;
    auto *effect=[[NSVisualEffectView alloc] initWithFrame:view.frame];
    effect.material=NSVisualEffectMaterialSidebar;
    effect.blendingMode=NSVisualEffectBlendingModeBehindWindow;
    effect.state=NSVisualEffectStateFollowsWindowActiveState;
    effect.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    [view.superview addSubview:effect positioned:NSWindowBelow relativeTo:view];
    [effect release];
    return true;
}
