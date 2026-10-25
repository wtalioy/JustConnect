#pragma once
#include "infrastructure/networkhelper/macos/networkhelper.h"

struct MacHelperPreparation {
    PlatformOperationResult result;
    MacHelperConfiguration configuration;
};
MacHelperPreparation prepareMacNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu);
