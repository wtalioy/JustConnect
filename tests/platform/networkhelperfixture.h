#pragma once
#include "infrastructure/platform/linux/networkhelper.h"

inline LinuxHelperConfiguration helperFixtureConfiguration(const QStringList &prefixes)
{
    LinuxHelperConfiguration configuration;
    configuration.address = "198.18.0.1";
    configuration.peer = "198.18.0.2";
    configuration.mtu = 1400;
    configuration.capturePrefixes = prefixes;
    configuration.originalInterface = "helperorig0";
    configuration.originalSource = "192.0.2.1";
    configuration.originalPrefixes = prefixes;
    return configuration;
}
