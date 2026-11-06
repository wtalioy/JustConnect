#pragma once

class QWidget;

namespace ApplicationAppearance {
void install();
// Apply to the current native handle; safe to repeat after a window is reopened.
bool enableNativeBackdrop(QWidget *window);
}
