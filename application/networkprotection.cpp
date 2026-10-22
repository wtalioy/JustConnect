#include "networkprotection.h"
#include <QHostAddress>
#include <QMap>

std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network)
{
    if (!network["interfaces"].isArray() || !network["routes"].isArray()) return std::nullopt;
    QMap<QString, QJsonArray> targets;
    auto add = [&](const QString &value, const QJsonObject &source, bool route) {
        const auto subnet = QHostAddress::parseSubnet(value);
        if (subnet.second < 0 || !subnet.first.scopeId().isEmpty()) return false;
        if (subnet.first.protocol() == QAbstractSocket::IPv6Protocol) {
            const auto bytes = subnet.first.toIPv6Address();
            bool mapped = bytes[10] == 0xff && bytes[11] == 0xff;
            for (int i = 0; i < 10; ++i) mapped = mapped && bytes[i] == 0;
            if (mapped) return false;
        }
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
