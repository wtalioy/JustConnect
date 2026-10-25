#pragma once
#include "infrastructure/networkaddress/ipv4.h"
#include "infrastructure/networkjournal/networkjournal.h"

#include <QFileInfo>
#include <QStandardPaths>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QScopeGuard>
#include <QRegularExpression>
#include <QUuid>
#include <sys/stat.h>

inline constexpr qsizetype LinuxRouteSnapshotBytes = 1024*1024;
inline constexpr qsizetype LinuxRouteSnapshotRows = 4096;
inline constexpr qsizetype LinuxRouteRecoveryBytes = NetworkJournalMaxBytes;
inline constexpr int LinuxRouteOperationTimeoutMs = 10000;

inline bool sameLinuxNetworkNamespace(const QByteArray &path)
{
    struct stat here{}, other{};
    return ::stat("/proc/thread-self/ns/net", &here) == 0 && ::stat(path.constData(), &other) == 0
        && here.st_dev == other.st_dev && here.st_ino == other.st_ino;
}

inline QString linuxNetworkNamespace()
{
    struct stat identity{};
    QFile boot("/proc/sys/kernel/random/boot_id");
    if (::stat("/proc/thread-self/ns/net",&identity)!=0 || !boot.open(QIODevice::ReadOnly)) return {};
    const auto id = QString::fromLatin1(boot.read(64)).trimmed();
    if (QUuid(id).isNull() || QUuid(id).toString(QUuid::WithoutBraces)!=id) return {};
    return id+":"+QString::number(identity.st_dev)+":"+QString::number(identity.st_ino);
}

inline quint32 linuxSourceTable(const QUuid &owner)
{
    return 1000000000u + owner.toByteArray(QUuid::Id128).left(8).toUInt(nullptr, 16) % 1000000000u;
}

// Local delivery stays first; bound original traffic bypasses the campus lookup.
inline constexpr int LinuxOriginalRulePriority = 1;
inline constexpr int LinuxCaptureRulePriority = 2;
inline quint32 linuxCaptureTable(const QUuid &owner)
{
    return linuxSourceTable(owner) + 1000000000u;
}

inline quint32 linuxRouteMetric(const QUuid &owner)
{
    return 1u + owner.toByteArray(QUuid::Id128).left(8).toUInt(nullptr,16) % 0xfffffffeu;
}

inline QByteArray linuxTunName(const QUuid &owner)
{
    return QByteArray("jc") + owner.toByteArray(QUuid::Id128).left(IFNAMSIZ-3);
}

inline bool sameLinuxRoute(QJsonObject current, QJsonObject saved)
{
    for (auto *row : {&current,&saved}) {
        if (!(*row)["flags"].isArray()) return false;
        for (const auto &flag : (*row)["flags"].toArray()) if (flag != "linkdown") return false;
        row->remove("flags");
        if ((*row)["type"] == "unicast") row->remove("type");
    }
    return current == saved;
}

inline QString ipv4RoutePrefix(const QJsonObject &row)
{
    const auto value = row["dst"].toString();
    if (value == "default") return "0.0.0.0/0";
    return value.contains('/') ? value : value + "/32";
}

inline bool canonicalLinuxInterfaceName(const QString &name)
{
    return QRegularExpression("^[A-Za-z0-9_.-]{1,15}$").match(name).hasMatch();
}

inline QString trustedIpRouteUtility()
{
    const QFileInfo utility(QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}));
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) return {};
    return utility.canonicalFilePath();
}
