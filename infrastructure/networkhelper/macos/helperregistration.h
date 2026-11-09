#pragma once
#include "application/platformoperationresult.h"
#include <functional>

// Completion runs off the Qt event thread.
void registerMacNetworkHelper(bool refresh, std::function<void(PlatformOperationResult)> completion);
