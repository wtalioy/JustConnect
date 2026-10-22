#include "networkprotection.h"
#include <QHostAddress>
#include <QMap>

namespace {
bool mapped(const QHostAddress &address)
{
    if (address.protocol() != QAbstractSocket::IPv6Protocol) return false;
    const auto bytes = address.toIPv6Address();
    bool result = bytes[10] == 0xff && bytes[11] == 0xff;
    for (int i = 0; i < 10; ++i) result = result && bytes[i] == 0;
    return result;
}

int compare(const QHostAddress &a, const QHostAddress &b)
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

std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network)
{
    if (!network["interfaces"].isArray() || !network["routes"].isArray()) return std::nullopt;
    QMap<QString, QJsonArray> targets;
    auto add = [&](const QString &value, const QJsonObject &source, bool route) {
        const auto subnet = QHostAddress::parseSubnet(value);
        if (subnet.second < 0 || !subnet.first.scopeId().isEmpty()) return false;
        if (mapped(subnet.first)) return false;
        // Default and split-default routes describe exits, never protected destinations.
        if (subnet.second <= 1) return route;
        const QString prefix = subnet.first.toString() + '/' + QString::number(subnet.second);
        targets[prefix].append(source);
        return true;
    };
    add("127.0.0.0/8", {{"kind", "loopback"}}, false);
    add("::1/128", {{"kind", "loopback"}}, false);
    const auto interfaces = network["interfaces"].toArray();
    for (int i = 0; i < interfaces.size(); ++i) {
        if (!interfaces[i].isObject()) return std::nullopt;
        const auto item = interfaces[i].toObject();
        if (!item["addresses"].isArray()) return std::nullopt;
        const auto addresses = item["addresses"].toArray();
        for (int j = 0; j < addresses.size(); ++j) {
            if (!addresses[j].isString() || !add(addresses[j].toString(),
                {{"kind", "interface_address"}, {"interface", i}, {"address", j}}, false)) return std::nullopt;
        }
    }
    const auto routes = network["routes"].toArray();
    for (int i = 0; i < routes.size(); ++i) {
        if (!routes[i].isObject()) return std::nullopt;
        const auto destination = routes[i].toObject().value("destination");
        if (!destination.isString() || !add(destination.toString(), {{"kind", "route"}, {"route", i}}, true))
            return std::nullopt;
    }
    QJsonArray result;
    for (auto it = targets.cbegin(); it != targets.cend(); ++it)
        result.append(QJsonObject{{"prefix", it.key()}, {"sources", it.value()}});
    return result;
}

std::optional<QJsonArray> campusProtectionConflicts(const QJsonArray &targets, const QJsonObject &resources)
{
    if (!resources["ip_resources"].isArray() || !resources["dns_records"].isObject()
        || !resources["campus_dns"].isString()) return std::nullopt;
    QList<std::pair<QHostAddress, int>> subnets;
    for (const auto &target : targets) {
        const auto subnet = QHostAddress::parseSubnet(target.toObject().value("prefix").toString());
        if (subnet.second <= 1 || mapped(subnet.first) || !subnet.first.scopeId().isEmpty()) return std::nullopt;
        subnets.append(subnet);
    }
    QJsonArray conflicts;
    auto add = [&](const QString &first, const QString &last, const QJsonObject &source) {
        const QHostAddress low(first), high(last);
        if (low.isNull() || high.isNull() || low.protocol() != high.protocol() || mapped(low) || mapped(high)
            || !low.scopeId().isEmpty() || !high.scopeId().isEmpty() || compare(low, high) > 0) return false;
        for (int i = 0; i < subnets.size(); ++i) {
            const auto &subnet = subnets[i];
            if (low.protocol() != subnet.first.protocol()) continue;
            if (low.isInSubnet(subnet) || high.isInSubnet(subnet)
                || (compare(subnet.first, low) >= 0 && compare(subnet.first, high) <= 0)) {
                if (conflicts.size() == 4096) return false;
                auto conflict = source;
                conflict["target"] = i;
                conflicts.append(conflict);
            }
        }
        return true;
    };
    const auto ips = resources["ip_resources"].toArray();
    for (int i = 0; i < ips.size(); ++i) {
        const auto resource = ips[i].toObject();
        if (!add(resource["ip_min"].toString(), resource["ip_max"].toString(),
                 {{"kind", "ip_resource"}, {"resource", i}})) return std::nullopt;
    }
    const auto records = resources["dns_records"].toObject();
    for (auto it = records.begin(); it != records.end(); ++it) {
        if (!it.value().isArray()) return std::nullopt;
        const auto addresses = it.value().toArray();
        for (int i = 0; i < addresses.size(); ++i) {
            if (!addresses[i].isString() || !add(addresses[i].toString(), addresses[i].toString(),
                {{"kind", "dns_record"}, {"domain", it.key()}, {"record", i}})) return std::nullopt;
        }
    }
    const auto dns = resources["campus_dns"].toString();
    if (!dns.isEmpty() && !add(dns, dns, {{"kind", "campus_dns"}})) return std::nullopt;
    return conflicts;
}
