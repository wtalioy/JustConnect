#pragma once

#include "networkhelper.h"
#include "application/dnssnapshot.h"
#include "infrastructure/platform/platformcommand.h"

struct LinuxHelperPreparation {
    PlatformOperationResult result;
    LinuxHelperConfiguration configuration;
};
// Read-only, bounded kernel queries; run on a worker while the Qt event loop stays live.
LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &policy,
    const QJsonObject &network, const DnsSnapshot &dns, const QString &localDNS, int mtu, const PlatformCommandRunner &reader = {});
