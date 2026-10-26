#pragma once
#include "infrastructure/process/command.h"
#include <optional>

std::optional<QStringList> linuxRouteEndpoints(const QStringList &prefixes);
// Verify the actual bound-source lookup before extending owned original/capture routes.
PlatformOperationResult verifyLinuxOriginalExit(const QString &interface, const QString &source, const QString &gateway,
    const QStringList &prefixes, const PlatformCommandRunner &reader = {});
