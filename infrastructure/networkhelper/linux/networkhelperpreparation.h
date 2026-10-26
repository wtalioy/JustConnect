#pragma once

#include "infrastructure/networkhelper/linux/networkhelper.h"
#include "application/dnssnapshot.h"
#include "infrastructure/dns/linux/resolvedlink.h"
#include "infrastructure/process/command.h"
#include <QJsonArray>

struct LinuxHelperPreparation {
    PlatformOperationResult result;
    LinuxHelperConfiguration configuration;
    QJsonArray originalSources;
};
using LinuxOriginalDNSReader = std::function<LinuxResolved::LinkSnapshot(int, QDeadlineTimer &)>;
// Read-only, bounded kernel queries; run on a worker while the Qt event loop stays live.
LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &policy,
    const QJsonObject &network, const DnsSnapshot &dns, const QString &localDNS, int mtu, const PlatformCommandRunner &reader = {},
    const LinuxOriginalDNSReader &dnsReader = {});

// Complete only the exact native source set with canonical, core-confirmed endpoints.
std::optional<LinuxHelperConfiguration> completeLinuxOriginalDNS(LinuxHelperConfiguration configuration, const QJsonObject &listeners);

PlatformOperationResult verifyLinuxCaptureExit(const LinuxHelperConfiguration &owned, const QStringList &prefixes,
    const PlatformCommandRunner &reader = {});

// Excludes unrelated overlay routes, while detecting changes hidden by our source lookup.
std::optional<QJsonObject> linuxOriginalExitSnapshot(const QJsonObject &network, const LinuxHelperConfiguration &owned);
