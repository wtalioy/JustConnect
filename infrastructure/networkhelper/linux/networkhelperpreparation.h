#pragma once

#include "infrastructure/networkhelper/linux/networkhelper.h"
#include "application/dnssnapshot.h"
#include "infrastructure/process/command.h"

struct LinuxHelperPreparation {
    PlatformOperationResult result;
    LinuxHelperConfiguration configuration;
};
// Read-only, bounded kernel queries; run on a worker while the Qt event loop stays live.
LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &policy,
    const QJsonObject &network, const DnsSnapshot &dns, const QString &localDNS, int mtu, const PlatformCommandRunner &reader = {});

PlatformOperationResult verifyLinuxCaptureExit(const LinuxHelperConfiguration &owned, const QStringList &prefixes,
    const PlatformCommandRunner &reader = {});

// Excludes unrelated overlay routes, while detecting changes hidden by our source lookup.
std::optional<QJsonObject> linuxOriginalExitSnapshot(const QJsonObject &network, const LinuxHelperConfiguration &owned);
