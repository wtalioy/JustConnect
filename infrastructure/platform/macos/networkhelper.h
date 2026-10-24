#pragma once

#include "application/platformoperationresult.h"
#include "macosnetworkhelperpaths.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QUuid>
#include <optional>

inline constexpr int MacHelperPacketBytes = 65536;
inline constexpr int MacHelperOperationTimeoutMs = 30000;
inline constexpr int MacHelperMaxPeers = 64;

struct MacHelperConfiguration {
    QString address, peer;
    int mtu = 0;
    QStringList capturePrefixes;
    QStringList dnsDomains;
};

QJsonObject macHelperRequest(const char *operation, const QUuid &owner, const QUuid &request);
QJsonObject macHelperApplyRequest(const QUuid &owner, const QUuid &request, const MacHelperConfiguration &configuration);
QJsonObject macHelperExtendRequest(const QUuid &owner, const QUuid &request, const QStringList &addresses);
std::optional<QStringList> parseMacHelperExtend(const QJsonObject &packet);
bool validMacHelperRequest(const QJsonObject &packet);
std::optional<MacHelperConfiguration> parseMacHelperApply(const QJsonObject &packet);
QJsonObject macHelperResponse(const QJsonObject &request, const PlatformOperationResult &result, const QJsonObject &device = {});
std::optional<PlatformOperationResult> parseMacHelperResponse(const QJsonObject &packet, const QJsonObject &request);
