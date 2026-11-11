#include "networkprotection.h"
#include "networkmodel_p.h"
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <QUrl>
#include <QtEndian>
#include <cstring>
#include <limits>
#include <utility>
#if defined(Q_OS_MACOS)
#include "infrastructure/routing/macos/proxyview.h"
#endif

using namespace networkModel;

std::optional<QJsonObject> originalProxyNetworkView(QJsonObject network)
{
#if defined(Q_OS_MACOS)
    return macOriginalProxyView(std::move(network));
#else
    return network;
#endif
}

std::optional<QJsonArray> originalNetworkProtection(const QJsonObject &network)
{
    if (!network["interfaces"].isArray() || !network["routes"].isArray()) return std::nullopt;
    QMap<QString, QJsonArray> targets;
    auto add = [&](const QString &value, const QJsonObject &source, bool route, bool excluded = false) {
        const auto subnet = QHostAddress::parseSubnet(value);
        if (subnet.second < 0 || !subnet.first.scopeId().isEmpty()) return false;
        if (mapped(subnet.first)) return false;
        // Host caches and routes bound only to disconnected links do not establish reachable networks.
        if (excluded) return true;
        // Default and split-default routes describe exits, never protected destinations.
        if (subnet.second <= 1) return route;
        const QString prefix = subnet.first.toString() + '/' + QString::number(subnet.second);
        targets[prefix].append(source);
        return true;
    };
    add("127.0.0.0/8", {{"kind", "loopback"}}, false);
    add("::1/128", {{"kind", "loopback"}}, false);
    QSet<qint64> interfacesSeen, disconnected;
    qint64 proxyIndex = 0;
#if defined(Q_OS_MACOS)
    proxyIndex = network["proxy_tunnel"].toObject()["interface_index"].toInteger();
#endif
    const auto interfaces = network["interfaces"].toArray();
    // Tailscale's reserved pools: https://tailscale.com/docs/reference/reserved-ip-addresses
    static const auto overlay4 = QHostAddress::parseSubnet(QStringLiteral("100.64.0.0/10"));
    static const auto overlay6 = QHostAddress::parseSubnet(QStringLiteral("fd7a:115c:a1e0::/48"));
    for (int i = 0; i < interfaces.size(); ++i) {
        if (!interfaces[i].isObject()) return std::nullopt;
        const auto item = interfaces[i].toObject();
        if (!item["addresses"].isArray()) return std::nullopt;
        const auto index = item["index"].toInteger(0);
        if (index > 0) {
            if (interfacesSeen.contains(index)) return std::nullopt;
            interfacesSeen.insert(index);
            if (item["up"] == false) disconnected.insert(index);
        }
        const auto addresses = item["addresses"].toArray();
        int overlayAddress4 = -1, overlayAddress6 = -1;
        for (int j = 0; j < addresses.size(); ++j) {
            if (!addresses[j].isString() || !add(addresses[j].toString(),
                {{"kind", "interface_address"}, {"interface", i}, {"address", j}}, false,index > 0 && index == proxyIndex)) return std::nullopt;
            const auto address = QHostAddress::parseSubnet(addresses[j].toString()).first;
            if (address.isInSubnet(overlay4)) overlayAddress4 = j;
            if (address.isInSubnet(overlay6)) overlayAddress6 = j;
        }
        // Both assigned families identify the live overlay without relying on its user-editable name.
        if (index > 0 && index != proxyIndex && item["up"] == true && item["loopback"] == false
            && overlayAddress4 >= 0 && overlayAddress6 >= 0) {
            add(overlay4.first.toString()+'/'+QString::number(overlay4.second),
                {{"kind", "interface_address"}, {"interface", i}, {"address", overlayAddress4}},false);
            add(overlay6.first.toString()+'/'+QString::number(overlay6.second),
                {{"kind", "interface_address"}, {"interface", i}, {"address", overlayAddress6}},false);
        }
    }
    const auto routes = network["routes"].toArray();
    for (int i = 0; i < routes.size(); ++i) {
        if (!routes[i].isObject()) return std::nullopt;
        const auto row = routes[i].toObject();
        const auto destination = row.value("destination");
        bool inactive = disconnected.contains(row["interface_index"].toInteger(0));
        if ((row.contains("cloned") && !row["cloned"].isBool()) || !destination.isString()
            || !add(destination.toString(), {{"kind", "route"}, {"route", i}}, true,row["cloned"].toBool() || inactive))
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
    struct Range {
        QAbstractSocket::NetworkLayerProtocol family;
        Q_IPV6ADDR first, last;
    };
    // Network byte order lets the overlap scan compare bounds without parsing addresses again.
    const auto bytes = [](const QHostAddress &address) {
        if (address.protocol() == QAbstractSocket::IPv6Protocol) return address.toIPv6Address();
        Q_IPV6ADDR value{};
        qToBigEndian(address.toIPv4Address(), value.c);
        return value;
    };
    QList<Range> subnets;
    subnets.reserve(targets.size());
    for (const auto &target : targets) {
        const auto subnet = QHostAddress::parseSubnet(target.toObject().value("prefix").toString());
        if (subnet.second <= 1 || mapped(subnet.first) || !subnet.first.scopeId().isEmpty()) return std::nullopt;
        const auto family = subnet.first.protocol();
        const auto first = bytes(subnet.first);
        auto last = first;
        const auto width = family == QAbstractSocket::IPv4Protocol ? 4 : 16;
        for (int i = subnet.second / 8; i < width; ++i)
            last[i] |= 0xff >> (i == subnet.second / 8 ? subnet.second % 8 : 0);
        subnets.append({family, first, last});
    }
    QJsonArray conflicts;
    auto add = [&](const QString &first, const QString &last, const QJsonObject &source) {
        const QHostAddress low(first), high(last);
        if (low.isNull() || high.isNull() || low.protocol() != high.protocol() || mapped(low) || mapped(high)
            || !low.scopeId().isEmpty() || !high.scopeId().isEmpty() || compare(low, high) > 0) return false;
        const auto family = low.protocol();
        const auto firstBytes = bytes(low), lastBytes = bytes(high);
        for (int i = 0; i < subnets.size(); ++i) {
            const auto &subnet = subnets.at(i);
            if (family == subnet.family && std::memcmp(firstBytes.c, subnet.last.c, sizeof firstBytes.c) <= 0
                && std::memcmp(subnet.first.c, lastBytes.c, sizeof lastBytes.c) <= 0) {
                if (conflicts.size() == MaxModelItems) return false;
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
        if (!name.isString() || name.toString().contains(QChar::Null) || result.size() == MaxModelItems) return false;
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
    if (dns.contains("macos_resolvers")) {
        if (!dns["macos_resolvers"].isArray()) return std::nullopt;
        const auto resolvers = dns["macos_resolvers"].toArray();
        for (int i = 0; i < resolvers.size(); ++i) {
            const auto row = resolvers[i].toObject(); const auto scope = row["scope"].toString();
            const auto index = row["interface_index"].toInteger(-1);
            const auto resolver = row["resolver"].toInteger(-1);
            if (!resolvers[i].isObject() || (scope != "unscoped" && scope != "interface" && scope != "service")
                || !row["resolver"].isDouble() || row["resolver"] != QJsonValue(resolver)
                || resolver <= 0 || resolver > std::numeric_limits<quint32>::max()
                || !row["interface_index"].isDouble() || row["interface_index"] != QJsonValue(index)
                || index < 0 || index > std::numeric_limits<quint32>::max() || !row["search"].isArray()
                || (!row["domain"].isUndefined() && !row["domain"].isString())) return std::nullopt;
            const QJsonObject source{{"provider","macos_resolver"},{"row",i},{"scope",scope},{"interface_index",index}};
            if ((!row["domain"].toString().isEmpty() && !add(row["domain"],"route",source))
                || !list(row,"search","search",source)) return std::nullopt;
        }
    }
    return result;
}

std::optional<QJsonObject> originalDnsProtection(const QJsonObject &dns)
{
    if (dns.contains("dynamic_store") && !dns.contains("macos_resolvers")) return std::nullopt;
    const auto namespaces = originalDnsNamespaces(dns);
    if (!namespaces) return std::nullopt;
    QMap<std::pair<QString, QString>, QJsonArray> rules;
    auto add = [&](const QString &kind, const QString &value, const QJsonObject &source) {
        const auto key = std::make_pair(kind, value);
        if (!rules.contains(key) && rules.size() == MaxModelItems) return false;
        rules[key].append(source);
        return true;
    };
    add("suffix", "localhost", {{"kind", "loopback"}});
    for (int i = 0; i < namespaces->size(); ++i) {
        const auto item = (*namespaces)[i].toObject(), origin = item["source"].toObject();
        const auto role = item["role"].toString(), provider = origin["provider"].toString();
        // Interface/service-only resolvers do not claim ordinary unscoped queries.
        if (provider == "macos_resolver" && origin["scope"] != "unscoped") continue;
        if (provider == "dynamic_store") continue; // These are inputs; the native merged view owns macOS routing/search semantics.
        const bool search = role == "search";
        const QJsonObject source{{"kind", "namespace"}, {"index", i}};
        auto text = item["name"].toString();
        if (text.isEmpty()) continue;
        if (text == ".") {
            if (search && !add("single_label", "", source)) return std::nullopt;
            continue;
        }
        QString kind = "suffix";
        if (role == "nrpt") {
            if (text.startsWith('.')) text.remove(0, 1);
            else kind = text.contains('.') ? "exact" : "prefix";
        }
        bool ascii = true;
        for (const auto ch : text) ascii &= ch.unicode() < 128;
        if (!ascii && kind == "prefix") return std::nullopt;
        const auto canonical = canonicalProtectionName(text);
        if (!canonical) return std::nullopt;
        const auto name = *canonical;
        if (!add(kind, name, source) || (search && !add("single_label", "", source))) return std::nullopt;
    }
    QJsonArray targets;
    for (auto it = rules.cbegin(); it != rules.cend(); ++it)
        targets.append(QJsonObject{{"kind", it.key().first}, {"value", it.key().second}, {"sources", it.value()}});
    return QJsonObject{{"namespaces", *namespaces}, {"targets", targets}};
}

std::optional<QString> canonicalProtectionName(QString nameInput)
{
    if (nameInput.endsWith('.')) nameInput.chop(1);
    if (nameInput != nameInput.trimmed()) return std::nullopt;
    bool ascii = true;
    for (const auto ch : nameInput) ascii &= ch.unicode() < 128;
    if (nameInput.contains(QChar::ReplacementCharacter)) return std::nullopt;
    const auto name = ascii ? nameInput.toLower() : QString::fromLatin1(QUrl::toAce(nameInput)).toLower();
    if (name.isEmpty() || name.size() > 253) return std::nullopt;
    const QHostAddress literal(name);
    if (!literal.isNull() && literal.toString() == name) return std::nullopt;
    for (const auto &label : name.split('.')) {
        if (label.isEmpty() || label.size() > 63 || label.startsWith('-') || label.endsWith('-')) return std::nullopt;
        for (const auto ch : label)
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-' || ch == '_')) return std::nullopt;
    }
    return name;
}

QJsonObject protectionConfiguration(const QJsonArray &targets, const QJsonArray &names)
{
    QJsonArray prefixes, rules;
    for (const auto &target : targets) prefixes.append(target.toObject()["prefix"]);
    for (const auto &value : names) {
        const auto target = value.toObject();
        rules.append(QJsonObject{{"kind", target["kind"]}, {"value", target["value"]}});
    }
    return {{"protected", prefixes}, {"campus", QJsonArray{}}, {"protected_names", rules}, {"campus_names", QJsonArray{}}};
}
