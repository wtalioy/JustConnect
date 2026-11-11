#pragma once

#include <QHostAddress>

namespace networkModel {
inline constexpr qsizetype MaxModelItems = 4096;

inline bool mapped(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv6Protocol) return false;
    const auto bytes = address.toIPv6Address();
    bool result = bytes[10] == 0xff && bytes[11] == 0xff;
    for (int i = 0; i < 10; ++i) result = result && bytes[i] == 0;
    return result;
}

inline int compare(const QHostAddress &a, const QHostAddress &b)
{
    if (a.protocol() == QAbstractSocket::IPv4Protocol) {
        const auto left = a.toIPv4Address(), right = b.toIPv4Address();
        return left < right ? -1 : left > right ? 1 : 0;
    }
    const auto left = a.toIPv6Address(), right = b.toIPv6Address();
    for (int i = 0; i < 16; ++i) {
        if (left[i] < right[i]) return -1;
        if (left[i] > right[i]) return 1;
    }
    return 0;
}
}
