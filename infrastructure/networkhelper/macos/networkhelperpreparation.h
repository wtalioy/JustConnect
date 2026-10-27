#pragma once
#include "infrastructure/networkhelper/macos/networkhelper.h"
#include "application/dnssnapshot.h"
#include <functional>

struct MacHelperPreparation {
    PlatformOperationResult result;
    MacHelperConfiguration configuration;
    QJsonArray originalSources;
};
using MacOriginalDnsReader = std::function<DnsSnapshot(const QString &service)>;
MacHelperPreparation prepareMacNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu,const MacOriginalDnsReader &read = {});
std::optional<MacHelperConfiguration> completeMacOriginalDNS(MacHelperConfiguration configuration,const QJsonObject &listeners);
std::optional<QStringList> updatedMacCapturePrefixes(const QJsonObject &resources,const QJsonObject &policy,
    const MacHelperConfiguration &configuration,const QJsonArray &originalSources);
