#pragma once

#include "infrastructure/networkjournal/macos/networkjournal.h"
#include "infrastructure/systemproxy/platformsystemproxybackend.h"

class MacPrivilegedProxy
{
public:
    MacPrivilegedProxy();
    PlatformOperationResult open(int bootDirectory);
    PlatformOperationResult restore();
    SystemProxyCheck inspect() { return native.inspect(); }
    PlatformOperationResult apply(const SystemProxyConfig &config);
private:
    MacNetworkJournal journal;
    PlatformSystemProxyBackend native;
    bool clean = false;
};
