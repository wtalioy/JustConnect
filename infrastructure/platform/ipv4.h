#pragma once

#include <QString>
#include <QScopeGuard>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

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

inline bool assignedUnixTunPair(const QString &name, quint32 index, const QString &source, const QString &peer)
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
