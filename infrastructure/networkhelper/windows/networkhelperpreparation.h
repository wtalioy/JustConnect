#pragma once
#include "application/platformoperationresult.h"
#include <QJsonObject>

struct WindowsHelperPreparation {
    PlatformOperationResult result;
    QJsonObject configuration;
};
WindowsHelperPreparation prepareWindowsNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu);
