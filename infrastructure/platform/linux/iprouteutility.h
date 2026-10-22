#pragma once

#include <QFileInfo>
#include <QStandardPaths>
#include <QJsonObject>
#include <arpa/inet.h>

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

inline QString trustedIpRouteUtility()
{
    const QFileInfo utility(QStandardPaths::findExecutable("ip", {"/usr/sbin", "/usr/bin", "/sbin", "/bin"}));
    if (!utility.isExecutable() || utility.ownerId() != 0
        || (utility.permissions() & (QFileDevice::WriteGroup | QFileDevice::WriteOther))) return {};
    return utility.canonicalFilePath();
}
