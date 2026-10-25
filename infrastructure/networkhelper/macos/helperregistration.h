#pragma once
#include "application/platformoperationresult.h"

// May prompt for system approval; call from a worker, never from the Qt event thread.
PlatformOperationResult registerMacNetworkHelper();
