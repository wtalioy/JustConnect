#pragma once
#include "infrastructure/process/command.h"

bool macDnsResolverMatches(const QString &configuration,const QString &peer,const QStringList &domains);
PlatformOperationResult waitForMacDnsResolver(const QString &peer,const QStringList &domains,
                                             PlatformCommandRunner run = {});
