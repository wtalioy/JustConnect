#include "networkprotection.h"
#include <QHostAddress>
#include <QMap>
#include <QRegularExpression>

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

std::optional<QJsonArray> originalDnsNamespaces(const QJsonObject &dns)
{
    QJsonArray result;
    auto add = [&](const QJsonValue &name, const QString &role, const QJsonObject &source) {
        if (!name.isString() || name.toString().contains(QChar::Null) || result.size() == 4096) return false;
        result.append(QJsonObject{{"name", name}, {"role", role}, {"source", source}});
        return true;
    };
    auto list = [&](const QJsonObject &row, const QString &field, const QString &role, QJsonObject source) {
        if (!row.contains(field)) return true;
        if (!row[field].isArray()) return false;
        const auto names = row[field].toArray();
        source["field"] = field;
        for (int i = 0; i < names.size(); ++i) {
            source["item"] = i;
            if (!add(names[i], role, source)) return false;
        }
        return true;
    };
    if (dns.contains("resolv_conf")) {
        if (!dns["resolv_conf"].isObject()) return std::nullopt;
        const auto contents = dns["resolv_conf"].toObject()["contents"];
        if (!contents.isString()) return std::nullopt;
        const auto lines = contents.toString().split('\n');
        QStringList names;
        int sourceLine = -1;
        const QRegularExpression whitespace(QStringLiteral("[ \\t]+"));
        for (int i = 0; i < lines.size(); ++i) {
            const auto &line = lines[i];
            if (!line.startsWith("search ") && !line.startsWith("search\t")
                && !line.startsWith("domain ") && !line.startsWith("domain\t")) continue;
            const auto words = line.split(whitespace, Qt::SkipEmptyParts);
            if (words.size() < 2) continue;
            names = words.mid(1, words[0] == "domain" ? 1 : -1);
            sourceLine = i;
        }
        for (int i = 0; i < names.size(); ++i)
            if (!add(names[i], "search_configuration", {{"provider", "resolv_conf"}, {"line", sourceLine}, {"item", i}})) return std::nullopt;
    }
    if (dns.contains("resolved")) {
        if (!dns["resolved"].isObject()) return std::nullopt;
        const auto resolved = dns["resolved"].toObject();
        if (resolved["status"] == "available") {
            if (!resolved["Domains"].isArray()) return std::nullopt;
            const auto domains = resolved["Domains"].toArray();
            for (int i = 0; i < domains.size(); ++i) {
                const auto row = domains[i].toObject();
                if (!row["route_only"].isBool() || row["interface_index"].toInteger(-1) < 0
                    || !add(row["domain"], row["route_only"].toBool() ? "route" : "search_route",
                            {{"provider", "resolved"}, {"row", i}, {"interface_index", row["interface_index"]}})) return std::nullopt;
            }
        } else if (resolved["status"] != "unavailable") return std::nullopt;
    }
    for (const auto &table : {QStringLiteral("nrpt"), QStringLiteral("clients")}) {
        if (!dns.contains(table)) continue;
        if (!dns[table].isArray()) return std::nullopt;
        const auto rows = dns[table].toArray();
        for (int i = 0; i < rows.size(); ++i) {
            if (!rows[i].isObject()) return std::nullopt;
            const auto row = rows[i].toObject();
            const QJsonObject source{{"provider", table}, {"row", i}};
            if (table == "nrpt") {
                if (!row["Namespace"].isArray() || !list(row, "Namespace", "nrpt", source)) return std::nullopt;
            } else {
                const auto suffix = row["ConnectionSpecificSuffix"];
                if (!suffix.isString() || (!suffix.toString().isEmpty()
                    && !add(suffix, "search", {{"provider", table}, {"row", i}, {"field", "ConnectionSpecificSuffix"}}))
                    || !list(row, "ConnectionSpecificSuffixSearchList", "search", source)) return std::nullopt;
            }
        }
    }
    if (dns.contains("global") && (!dns["global"].isObject()
        || !list(dns["global"].toObject(), "SuffixSearchList", "search", {{"provider", "global"}}))) return std::nullopt;
    if (dns.contains("dynamic_store")) {
        if (!dns["dynamic_store"].isObject()) return std::nullopt;
        const auto store = dns["dynamic_store"].toObject();
        for (auto it = store.begin(); it != store.end(); ++it) {
            if (!it.value().isObject()) return std::nullopt;
            const auto row = it.value().toObject();
            const QJsonObject source{{"provider", "dynamic_store"}, {"key", it.key()}};
            // Store entries are resolver inputs, not the final scoped resolver order.
            if (!list(row, "SupplementalMatchDomains", "match_configuration", source)
                || !list(row, "SearchDomains", "search_configuration", source)) return std::nullopt;
            if (row.contains("DomainName") && !add(row["DomainName"], "domain_configuration",
                {{"provider", "dynamic_store"}, {"key", it.key()}, {"field", "DomainName"}})) return std::nullopt;
        }
    }
    return result;
}
