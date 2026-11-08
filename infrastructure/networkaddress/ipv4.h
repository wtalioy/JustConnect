#pragma once

#include <QString>
#include <QStringView>
#include <QScopeGuard>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <optional>

namespace unixIpv4 {
struct Prefix { quint32 network, mask; };

inline std::optional<quint32> canonicalAddress(QStringView value)
{
    if (value.size() >= INET_ADDRSTRLEN) return {};
    in_addr address{};
    char canonical[INET_ADDRSTRLEN]{};
    if (::inet_pton(AF_INET, value.toLatin1().constData(), &address) != 1
        || !::inet_ntop(AF_INET, &address, canonical, sizeof(canonical))
        || value != QLatin1StringView(canonical)) return {};
    return ntohl(address.s_addr);
}

inline std::optional<Prefix> canonicalPrefix(QStringView value)
{
    const auto slash = value.indexOf(u'/');
    if (slash <= 0) return {};
    const auto length = value.sliced(slash+1);
    bool valid = false;
    const auto bits = length.toInt(&valid);
    if (!valid || bits < 2 || bits > 32 || length != QString::number(bits)) return {};
    const auto network = canonicalAddress(value.first(slash));
    const quint32 mask = 0xffffffffu << (32-bits);
    if (!network || (*network & mask) != *network) return {};
    return Prefix{*network, mask};
}

inline bool unicastRange(quint32 first, quint32 last)
{
    // Captures exclude the unspecified, loopback and non-unicast ranges.
    return first >= 0x01000000u && last < 0xe0000000u && !(first <= 0x7fffffffu && last >= 0x7f000000u);
}

inline std::optional<quint32> unicastAddress(QStringView value)
{
    const auto address = canonicalAddress(value);
    return address && unicastRange(*address, *address) ? address : std::nullopt;
}
}

inline bool canonicalIpv4Prefix(const QString &value)
{
    return unixIpv4::canonicalPrefix(value).has_value();
}

inline bool canonicalUnicastIpv4Prefix(const QString &value)
{
    const auto prefix = unixIpv4::canonicalPrefix(value);
    return prefix && unixIpv4::unicastRange(prefix->network, prefix->network | ~prefix->mask);
}

inline bool canonicalUnicastIpv4(const QString &value)
{
    return unixIpv4::unicastAddress(value).has_value();
}

inline bool ipv4PrefixContainsAddress(const QString &prefix, const QString &address)
{
    const auto range = unixIpv4::canonicalPrefix(prefix);
    if (!range) return false;
    const auto host = unixIpv4::unicastAddress(address);
    return host && (*host & range->mask) == range->network;
}

inline bool assignedUnixTunPair(const QString &name, quint32 index, const QString &source, const QString &peer)
{
    if (!index || ::if_nametoindex(name.toLatin1().constData()) != index) return false;
    const auto sourceAddress = unixIpv4::unicastAddress(source), peerAddress = unixIpv4::unicastAddress(peer);
    if (!sourceAddress || !peerAddress || sourceAddress == peerAddress) return false;
    const auto local = htonl(*sourceAddress), remote = htonl(*peerAddress);
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (QString::fromLatin1(entry->ifa_name) == name && (entry->ifa_flags & IFF_POINTOPOINT)
            && entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET
            && entry->ifa_dstaddr && entry->ifa_dstaddr->sa_family == AF_INET
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_addr)->sin_addr.s_addr == local
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_dstaddr)->sin_addr.s_addr == remote) return true;
    }
    return false;
}
