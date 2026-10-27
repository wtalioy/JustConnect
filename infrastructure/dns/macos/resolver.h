#pragma once
#include "infrastructure/process/command.h"
#include <QJsonArray>
#include <QJsonObject>
#include <optional>

inline constexpr qsizetype MacDnsSnapshotBytes = 262144;
bool macDnsServersBelongTo(const QJsonArray &effective,const QJsonArray &configured);
bool validMacOriginalDnsContext(const QJsonObject &context);
std::optional<QJsonObject> originalMacDnsResolver(QJsonObject resolver,const QJsonObject &context);
std::optional<QJsonArray> parseMacDnsResolvers(const QString &configuration);
// Zero selects ordinary supplemental DNS; a positive index selects that private interface's scoped resolver.
bool macDnsResolverUsesPeer(const QJsonObject &resolver,const QString &peer,quint32 interfaceIndex = 0);

bool macDnsResolverMatches(const QString &configuration,const QString &peer,const QStringList &domains);
PlatformOperationResult waitForMacDnsResolver(const QString &peer,const QStringList &domains,
                                             PlatformCommandRunner run = {});
