#pragma once
#include "application/platformoperationresult.h"
#include <QByteArray>
#include <QStringList>
#include <functional>

struct PlatformCommandResult
{
    PlatformOperationResult result;
    QString output;
    QString standardError;
};
using PlatformCommandRunner = std::function<PlatformCommandResult(const QString &, const QStringList &)>;
inline constexpr int PlatformCommandCleanupTimeoutMs = 1000;
PlatformCommandResult runPlatformCommand(const QString &program, const QStringList &arguments, int timeoutMs = 5000,
                                        const QByteArray &input = {});
