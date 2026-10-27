#pragma once
#include "application/platformoperationresult.h"
#include <QJsonObject>
#include <QJsonArray>
#include <optional>
#include <QStringList>

struct WindowsHelperPreparation {
    PlatformOperationResult result;
    QJsonObject configuration;
    QJsonArray originalSources;
    QJsonObject originalContext;
};
WindowsHelperPreparation prepareWindowsNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu);
std::optional<QJsonObject> completeWindowsOriginalDNS(QJsonObject configuration,const QJsonObject &listeners);
std::optional<QStringList> updatedWindowsCapturePrefixes(const QJsonObject &resources,const QJsonObject &policy,
    const QJsonObject &configuration,const QJsonArray &originalSources);
