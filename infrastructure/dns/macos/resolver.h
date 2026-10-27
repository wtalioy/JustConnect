#pragma once
#include "infrastructure/process/command.h"
#include <QJsonArray>
#include <QJsonObject>
#include <optional>

inline constexpr qsizetype MacDnsSnapshotBytes = 262144;
std::optional<QJsonArray> parseMacDnsResolvers(const QString &configuration);
// Zero selects ordinary supplemental DNS; a positive index selects that private interface's scoped resolver.
bool macDnsResolverUsesPeer(const QJsonObject &resolver,const QString &peer,quint32 interfaceIndex = 0);

bool macDnsResolverMatches(const QString &configuration,const QString &peer,const QStringList &domains);
PlatformOperationResult waitForMacDnsResolver(const QString &peer,const QStringList &domains,
                                             PlatformCommandRunner run = {});
