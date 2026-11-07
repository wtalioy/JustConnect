#pragma once

class QWidget;

namespace ApplicationAppearance {
// Only the supplied main window opts into a native backdrop; other windows remain opaque.
void install(QWidget *initialWindow=nullptr);
// Apply to the current native handle; safe to repeat after a window is reopened.
bool enableNativeBackdrop(QWidget *window);
}
