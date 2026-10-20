#include "infrastructure/platform/autostart.h"
PlatformOperationResult AutoStart::setEnabled(bool) {
    return {PlatformOperationResult::Status::Unsupported, "Autostart is unsupported on this platform"};
}
