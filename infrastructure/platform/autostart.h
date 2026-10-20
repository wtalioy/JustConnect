#pragma once
#include "application/platformoperationresult.h"
#ifdef Q_OS_MACOS
#include "platformcommand.h"
#endif
namespace AutoStart {
PlatformOperationResult setEnabled(bool enabled);
#ifdef Q_OS_MACOS
PlatformOperationResult setEnabled(bool enabled, const PlatformCommandRunner &runner);
#endif
}
