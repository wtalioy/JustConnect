#pragma once
#include "infrastructure/platform/dnssnapshot.h"
#include <QDBusConnection>

// Blocking, read-only; call on a worker, never on the GUI thread.
DnsSnapshot readLinuxDnsSnapshot(const QDBusConnection &bus = QDBusConnection::systemBus(),
                                 const QString &resolvConf = QStringLiteral("/etc/resolv.conf"));
