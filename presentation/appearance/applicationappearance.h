#pragma once

class QWidget;

namespace ApplicationAppearance {
void install();
// Called only while a native top-level window is being prepared.
bool enableNativeBackdrop(QWidget *window);
}
