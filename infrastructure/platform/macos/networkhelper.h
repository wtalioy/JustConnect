#pragma once

#include "application/platformoperationresult.h"
#include "macosnetworkhelperpaths.h"
#include "infrastructure/platform/networkjournal.h"
#include <QJsonObject>
#include <QJsonArray>
#include <QStringList>
#include <QUuid>
#include <optional>

inline constexpr int MacHelperRequestBytes = 65536;
// A reply includes the bounded native capture record and its DNS/device envelope.
inline constexpr int MacHelperPacketBytes = NetworkJournalMaxBytes + 2*MacHelperRequestBytes;
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
QJsonObject macHelperRoutesRequest(const QUuid &owner, const QUuid &request, const QStringList &prefixes);
std::optional<QStringList> parseMacHelperRoutes(const QJsonObject &packet);
bool validMacHelperRequest(const QJsonObject &packet);
std::optional<MacHelperConfiguration> parseMacHelperApply(const QJsonObject &packet);
QJsonObject macHelperResponse(const QJsonObject &request, const PlatformOperationResult &result, const QJsonObject &device = {});
std::optional<PlatformOperationResult> parseMacHelperResponse(const QJsonObject &packet, const QJsonObject &request);
