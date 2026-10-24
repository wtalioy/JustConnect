#pragma once

#include <QFileInfo>
#include <QStandardPaths>
#include <QJsonObject>
#include <QJsonArray>
#include <QFile>
#include <QScopeGuard>
#include <QUuid>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/stat.h>

inline constexpr qsizetype LinuxRouteSnapshotBytes = 1024*1024;
inline constexpr qsizetype LinuxRouteSnapshotRows = 4096;
inline constexpr qsizetype LinuxRouteRecoveryBytes = 2*1024*1024;
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

inline bool canonicalIpv4Prefix(const QString &value, int minimum = 2)
{
    const auto parts = value.split('/');
    if (parts.size() != 2) return false;
    bool valid = false;
    const int bits = parts[1].toInt(&valid);
    in_addr address{};
    if (!valid || bits < minimum || bits > 32 || QString::number(bits) != parts[1]
        || ::inet_pton(AF_INET, parts[0].toLatin1().constData(), &address) != 1) return false;
    char canonical[INET_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET, &address, canonical, sizeof(canonical)) || parts[0] != QString::fromLatin1(canonical)) return false;
    const quint32 host = ntohl(address.s_addr), mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
    return (host & mask) == host;
}

inline bool canonicalUnicastIpv4(const QString &value)
{
    if (!canonicalIpv4Prefix(value+"/32")) return false;
    const int first=value.section('.',0,0).toInt();
    return first>0 && first<224 && first!=127;
}

inline bool ipv4PrefixContainsAddress(const QString &prefix, const QString &address)
{
    if (!canonicalIpv4Prefix(prefix) || !canonicalUnicastIpv4(address)) return false;
    const auto parts = prefix.split('/');
    in_addr network{}, host{};
    ::inet_pton(AF_INET, parts[0].toLatin1().constData(), &network);
    ::inet_pton(AF_INET, address.toLatin1().constData(), &host);
    const quint32 mask = 0xffffffffu << (32 - parts[1].toInt());
    return (ntohl(host.s_addr) & mask) == ntohl(network.s_addr);
}

inline bool assignedLinuxTunPair(const QString &name, quint32 index, const QString &source, const QString &peer)
{
    if (!index || ::if_nametoindex(name.toLatin1().constData()) != index
        || !canonicalUnicastIpv4(source) || !canonicalUnicastIpv4(peer) || source == peer) return false;
    in_addr local{}, remote{};
    ::inet_pton(AF_INET, source.toLatin1().constData(), &local);
    ::inet_pton(AF_INET, peer.toLatin1().constData(), &remote);
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (QString::fromLatin1(entry->ifa_name) == name && (entry->ifa_flags & IFF_POINTOPOINT)
            && entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET
            && entry->ifa_dstaddr && entry->ifa_dstaddr->sa_family == AF_INET
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_addr)->sin_addr.s_addr == local.s_addr
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_dstaddr)->sin_addr.s_addr == remote.s_addr) return true;
    }
    return false;
}

inline QString trustedIpRouteUtility()
{
    const QFileInfo utility(QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}));
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) return {};
    return utility.canonicalFilePath();
}
