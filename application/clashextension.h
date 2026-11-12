#pragma once

#include "core/connectionoptions.h"

namespace ClashExtension {
// One-based line number, or zero when the saved targets can be exported.
int invalidTargetLine(const ConnectionOptions &options);
QString script(const ConnectionOptions &options);
}
