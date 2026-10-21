#pragma once
#include "application/platformoperationresult.h"
#include <QDBusConnection>
#include <QJsonObject>

struct LinuxDnsSnapshot
{
    PlatformOperationResult result;
    QJsonObject data;
};

// Blocking, read-only; call on a worker, never on the GUI thread.
LinuxDnsSnapshot readLinuxDnsSnapshot(const QDBusConnection &bus = QDBusConnection::systemBus(),
                                     const QString &resolvConf = QStringLiteral("/etc/resolv.conf"));
