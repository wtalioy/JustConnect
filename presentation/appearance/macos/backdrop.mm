#include "../applicationappearance.h"
#include <QWidget>
#include <QGuiApplication>
#import <AppKit/AppKit.h>

bool ApplicationAppearance::enableNativeBackdrop(QWidget *window) {
    if (QGuiApplication::platformName()!="cocoa") return false;
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
    NSVisualEffectView *effect=nil;
    for (NSView *sibling in view.superview.subviews) {
        if ([sibling.identifier isEqualToString:@"JustConnectBackdrop"] && [sibling isKindOfClass:NSVisualEffectView.class]) {
            effect=(NSVisualEffectView *)sibling;
            break;
        }
    }
    if (!effect) {
        effect=[[[NSVisualEffectView alloc] initWithFrame:view.frame] autorelease];
        effect.identifier=@"JustConnectBackdrop";
        [view.superview addSubview:effect positioned:NSWindowBelow relativeTo:view];
    }
    effect.frame=view.frame;
    effect.material=NSVisualEffectMaterialSidebar;
    effect.blendingMode=NSVisualEffectBlendingModeBehindWindow;
    effect.state=NSVisualEffectStateFollowsWindowActiveState;
    effect.autoresizingMask=NSViewWidthSizable|NSViewHeightSizable;
    return true;
}
