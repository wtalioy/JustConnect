#include "networkprotection.h"
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <QRegularExpression>
#include <QUrl>
#include <limits>
#include <algorithm>
#include <utility>

namespace {
constexpr qsizetype MaxModelItems = 4096;

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
    auto add = [&](const QString &value, const QJsonObject &source, bool route, bool cloned = false) {
        const auto subnet = QHostAddress::parseSubnet(value);
        if (subnet.second < 0 || !subnet.first.scopeId().isEmpty()) return false;
        if (mapped(subnet.first)) return false;
        // Kernel-derived host caches inherit their parent scope and do not create new protection.
        if (cloned) return true;
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
        const auto row = routes[i].toObject();
        const auto destination = row.value("destination");
        if ((row.contains("cloned") && !row["cloned"].isBool()) || !destination.isString()
            || !add(destination.toString(), {{"kind", "route"}, {"route", i}}, true,row["cloned"].toBool()))
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
    if (dns.contains("resolv_conf")) {
        if (!dns["resolv_conf"].isObject()) return std::nullopt;
        const auto contents = dns["resolv_conf"].toObject().value("contents");
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

std::optional<QJsonObject> originalDnsProtection(const QJsonObject &dns)
{
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
        bool search = role == "search" || role == "search_route" || role == "search_configuration";
        if (provider == "dynamic_store") {
            if (!origin["key"].toString().startsWith("State:")) continue;
            const auto row = dns["dynamic_store"].toObject()[origin["key"].toString()].toObject();
            const auto noSearch = row["SupplementalMatchDomainsNoSearch"];
            // SystemConfiguration uses a CFNumber, not a CFBoolean, for this flag.
            if (!noSearch.isUndefined() && (!noSearch.isDouble() || noSearch != QJsonValue(noSearch.toInteger())
                || noSearch.toInteger() < std::numeric_limits<int>::min() || noSearch.toInteger() > std::numeric_limits<int>::max())) return std::nullopt;
            if (role == "match_configuration")
                search = noSearch.toInteger() == 0 && !row["ServerAddresses"].toArray().isEmpty();
            else if (role == "domain_configuration") search = !row.contains("SearchDomains");
            if ((role == "match_configuration" || role == "domain_configuration")
                && (row["Options"] == "pdns" || row["Options"].toString().contains("interface="))) search = false;
        }
        const QJsonObject source{{"kind", "namespace"}, {"index", i}};
        auto text = item["name"].toString();
        if (text.isEmpty()) continue;
        if (text == ".") {
            if (search && role != "match_configuration" && role != "domain_configuration"
                && !add("single_label", "", source)) return std::nullopt;
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
        if (provider == "dynamic_store" && role == "match_configuration"
            && (name.endsWith(".in-addr.arpa") || name.endsWith(".ip6.arpa"))) search = false;
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

namespace {
using IPv4Range = std::pair<quint64, quint64>;
using IPv4Ranges = QList<IPv4Range>;

std::optional<quint64> ipv4Number(const QString &text)
{
    const QHostAddress address(text);
    if (address.protocol() != QAbstractSocket::IPv4Protocol || address.toString() != text) return {};
    return address.toIPv4Address();
}

IPv4Ranges mergedRanges(IPv4Ranges ranges)
{
    std::sort(ranges.begin(), ranges.end());
    IPv4Ranges result;
    for (const auto &range : ranges) {
        if (!result.isEmpty() && range.first <= result.last().second + 1)
            result.last().second = std::max(result.last().second, range.second);
        else result.append(range);
    }
    return result;
}

IPv4Ranges subtractRanges(const IPv4Ranges &included, const IPv4Ranges &excluded)
{
    IPv4Ranges result;
    qsizetype index = 0;
    for (const auto &range : included) {
        auto first = range.first;
        while (index < excluded.size() && excluded[index].second < first) ++index;
        for (auto next = index; next < excluded.size() && excluded[next].first <= range.second; ++next) {
            const auto &blocked = excluded[next];
            if (blocked.first > first) result.append({first, blocked.first - 1});
            first = std::max(first, blocked.second + 1);
            if (first > range.second) break;
        }
        if (first <= range.second) result.append({first, range.second});
    }
    return result;
}

std::optional<QStringList> prefixesForRanges(const IPv4Ranges &ranges)
{
    QStringList result;
    for (const auto &range : ranges) {
        for (auto first = range.first; first <= range.second;) {
            // The owned backend permits /2 through /32; never synthesize a default route.
            quint64 span = quint64(1) << 30;
            int bits = 2;
            while (span > range.second - first + 1 || first % span) { span >>= 1; ++bits; }
            result.append(QHostAddress(quint32(first)).toString() + "/" + QString::number(bits));
            if (result.size() > MaxModelItems) return {};
            first += span;
        }
    }
    return result;
}
}

std::optional<QStringList> excludeCampusCaptureAddresses(const QStringList &ownedPrefixes, const QStringList &addresses)
{
    if (ownedPrefixes.size() > MaxModelItems || addresses.size() > MaxModelItems) return {};
    IPv4Ranges included, excluded;
    for (const auto &prefix : ownedPrefixes) {
        const auto subnet = QHostAddress::parseSubnet(prefix);
        if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol || subnet.second < 2 || subnet.second > 32) return {};
        const quint64 first = subnet.first.toIPv4Address(), span = quint64(1) << (32 - subnet.second);
        if (first % span || prefix != subnet.first.toString() + "/" + QString::number(subnet.second)) return {};
        included.append({first, first + span - 1});
    }
    for (const auto &text : addresses) {
        const auto address = ipv4Number(text);
        if (!address) return {};
        excluded.append({*address, *address});
    }
    return prefixesForRanges(subtractRanges(mergedRanges(included), mergedRanges(excluded)));
}

std::optional<QStringList> campusDnsDomains(const QJsonObject &resources)
{
    if (!resources["campus_dns_enabled"].isBool() || !resources["domain_resources"].isObject()
        || !resources["dns_records"].isObject()) return {};
    QStringList result;
    auto add = [&](QString name) {
        if (name.startsWith("*.")) name.remove(0,2);
        else if (name.startsWith('.')) name.remove(0,1);
        const auto canonical = canonicalProtectionName(name);
        if (!canonical || result.size() >= MaxModelItems) return false;
        result.append(*canonical); return true;
    };
    const auto domains = resources["domain_resources"].toObject(), records = resources["dns_records"].toObject();
    if (domains.size() > MaxModelItems || records.size() > MaxModelItems) return {};
    if (resources["campus_dns_enabled"].toBool())
        for (auto it = domains.begin(); it != domains.end(); ++it)
            if (!it.value().isArray() || (!it.value().toArray().isEmpty() && !add(it.key()))) return {};
    for (auto it = records.begin(); it != records.end(); ++it)
        if (!it.value().isArray() || !add(it.key())) return {};
    const QSet<QString> namespaces(result.begin(), result.end());
    result.clear();
    for (const auto &domain : namespaces) {
        auto suffix = domain;
        bool inherited = false;
        while (suffix.contains('.')) {
            suffix.remove(0,suffix.indexOf('.')+1);
            if (namespaces.contains(suffix)) { inherited = true; break; }
        }
        if (!inherited) result.append(domain);
    }
    result.sort();
    return result;
}

std::optional<QJsonArray> requiredOriginalDnsNames(const QJsonObject &resources, const QJsonObject &policy)
{
    const auto domains = campusDnsDomains(resources);
    if (!domains || !policy["protected_names"].isArray() || !policy["campus_names"].isArray()
        || policy["protected_names"].toArray().size() > MaxModelItems || policy["campus_names"].toArray().size() > MaxModelItems) return {};
    QJsonArray result;
    const auto choices = policy["campus_names"].toArray();
    for (const auto &entry : policy["protected_names"].toArray()) {
        if (!entry.isObject()) return {};
        const auto rule = entry.toObject();
        const auto kind = rule["kind"].toString(), value = rule["value"].toString();
        if (kind != "exact" && kind != "suffix" && kind != "prefix" && kind != "single_label") return {};
        if (kind == "exact" && choices.contains(value)) continue;
        for (const auto &domain : *domains) {
            const bool overlap = kind == "prefix" || (kind == "single_label" && !domain.contains('.'))
                || ((kind == "exact" || kind == "suffix") && (value == domain || value.endsWith('.'+domain)))
                || (kind == "suffix" && domain.endsWith('.'+value));
            if (overlap) { result.append(rule); break; }
        }
    }
    return result;
}

std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy, const QStringList &dynamicAddresses, const QJsonArray &originalDNS)
{
    if (!resources["ip_resources"].isArray() || !resources["domain_resources"].isObject()
        || !resources["dns_records"].isObject() || !resources["campus_dns"].isString()
        || !resources["campus_dns_enabled"].isBool() || !policy["protected"].isArray()
        || !policy["campus"].isArray() || !policy["protected_names"].isArray() || !policy["campus_names"].isArray()) return {};
    const auto ips = resources["ip_resources"].toArray(), protectedIPs = policy["protected"].toArray(), choices = policy["campus"].toArray();
    const auto domains = resources["domain_resources"].toObject(), records = resources["dns_records"].toObject();
    const auto names = policy["protected_names"].toArray(), campusNames = policy["campus_names"].toArray();
    for (const auto size : {ips.size(), protectedIPs.size(), choices.size(), domains.size(), records.size(), names.size(), campusNames.size(), dynamicAddresses.size()})
        if (size > MaxModelItems) return {};
    const auto required = requiredOriginalDnsNames(resources,policy);
    if (!required || originalDNS.size() > MaxModelItems) return {};
    QJsonArray forwarded;
    IPv4Ranges included, excluded, selected;
    IPv4Ranges originalServers;
    for (const auto &value : originalDNS) {
        if (!value.isObject()) return {};
        const auto row = value.toObject();
        if (!row["name"].isObject() || !names.contains(row["name"]) || !row["servers"].isArray() || row["servers"].toArray().isEmpty()) return {};
        forwarded.append(row["name"]);
        for (const auto &server : row["servers"].toArray()) {
            if (!server.isString()) return {};
            const QUrl endpoint("dns://"+server.toString());
            const QHostAddress address(endpoint.host());
            if (!endpoint.isValid() || endpoint.port() < 1 || endpoint.port() > 65535 || address.isNull()) return {};
            if (address.protocol() == QAbstractSocket::IPv4Protocol)
                originalServers.append({address.toIPv4Address(),address.toIPv4Address()});
            if (originalServers.size() > MaxModelItems) return {};
        }
    }
    for (const auto &name : *required) if (!forwarded.contains(name)) return {};
    CampusCaptureTargets result;
    auto add = [&](const QString &first, const QString &last) {
        const QHostAddress low(first), high(last);
        if (low.isNull() || high.isNull() || low.protocol() != high.protocol() || mapped(low) || mapped(high)
            || !low.scopeId().isEmpty() || !high.scopeId().isEmpty() || compare(low, high) > 0) return false;
        if (low.protocol() == QAbstractSocket::IPv4Protocol) {
            if (!ipv4Number(first) || !ipv4Number(last)) return false;
            included.append({low.toIPv4Address(), high.toIPv4Address()});
        }
        return included.size() <= MaxModelItems;
    };
    for (const auto &entry : ips) {
        if (!entry.isObject()) return {};
        const auto row = entry.toObject();
        const auto protocol = row["protocol"].toString();
        if (protocol == "icmp") continue; // The current transparent ingress carries TCP/UDP only.
        if (protocol != "all" && protocol != "tcp" && protocol != "udp") return {};
        const int firstPort = row["port_min"].toInt(-1), lastPort = row["port_max"].toInt(-1);
        if (firstPort < 1 || lastPort > 65535 || firstPort > lastPort
            || !add(row["ip_min"].toString(), row["ip_max"].toString())) return {};
    }
    for (const auto &address : dynamicAddresses)
        if (!ipv4Number(address) || !add(address,address)) return {};
    for (const auto &value : protectedIPs) {
        if (!value.isString()) return {};
        const auto subnet = QHostAddress::parseSubnet(value.toString());
        if (subnet.second <= 1 || mapped(subnet.first) || !subnet.first.scopeId().isEmpty()) return {};
        if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol) continue;
        const quint64 first = subnet.first.toIPv4Address(), span = quint64(1) << (32 - subnet.second);
        if (first % span || value.toString() != subnet.first.toString() + "/" + QString::number(subnet.second)) return {};
        excluded.append({first, first + span - 1});
    }
    for (const auto &value : choices) {
        if (!value.isString()) return {};
        const auto address = ipv4Number(value.toString());
        if (!address) return {};
        selected.append({*address, *address});
    }
    excluded = subtractRanges(mergedRanges(excluded), mergedRanges(selected));
    excluded.append(originalServers);
    // Match the helper's unicast address boundary; campus choices cannot capture these ranges.
    for (const auto &prefix : {"0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3"}) {
        const auto subnet = QHostAddress::parseSubnet(QString::fromLatin1(prefix));
        const quint64 first = subnet.first.toIPv4Address();
        excluded.append({first, first + (quint64(1) << (32 - subnet.second)) - 1});
    }
    // Name protection takes precedence over an IP-only campus choice.
    if (resources.contains("original_dns_records")) {
        if (!resources["original_dns_records"].isObject()) return {};
        const auto originalRecords = resources["original_dns_records"].toObject();
        if (originalRecords.size() > MaxModelItems) return {};
        qsizetype addressCount = 0;
        for (auto it = originalRecords.begin(); it != originalRecords.end(); ++it) {
            const auto name = canonicalProtectionName(it.key());
            if (!name || *name != it.key() || !it.value().isArray()) return {};
            bool protectedName = false;
            for (const auto &entry : names) {
                if (!entry.isObject()) return {};
                const auto rule = entry.toObject();
                const auto kind = rule["kind"].toString(), value = rule["value"].toString();
                if (kind == "exact") protectedName |= *name == value;
                else if (kind == "suffix") protectedName |= *name == value || name->endsWith('.' + value);
                else if (kind == "prefix") protectedName |= name->startsWith(value);
                else if (kind == "single_label") protectedName |= !name->contains('.');
                else return {};
            }
            if (!protectedName) return {};
            const bool chosen = campusNames.contains(*name);
            for (const auto &value : it.value().toArray()) {
                if (++addressCount > MaxModelItems || !value.isString()) return {};
                const auto address = ipv4Number(value.toString());
                if (!address) return {};
                if (!chosen) excluded.append({*address, *address});
            }
        }
    }
    const auto dnsDomains = campusDnsDomains(resources);
    if (!dnsDomains) return {};
    result.dnsDomains = *dnsDomains;
    const bool remoteDNS = resources["campus_dns_enabled"].toBool();
    if (remoteDNS) {
        const auto server = resources["campus_dns"].toString();
        const auto address = ipv4Number(server);
        if (!address || !add(server, server) || std::any_of(excluded.begin(), excluded.end(),
            [&](const IPv4Range &range) { return range.first <= *address && *address <= range.second; })) return {};
    }
    for (auto it = records.begin(); it != records.end(); ++it) {
        if (!it.value().isArray()) return {};
        for (const auto &value : it.value().toArray())
            if (!value.isString() || !add(value.toString(), value.toString())) return {};
    }
    const auto prefixes = prefixesForRanges(subtractRanges(mergedRanges(included), mergedRanges(excluded)));
    if (!prefixes) return {};
    result.ipv4Prefixes = *prefixes;
    return result;
}

std::optional<QStringList> updatedCampusCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const QStringList &dnsDomains, const QJsonArray &originalDNS)
{
    QStringList active;
    const auto addresses = resources.value("active_tun_addresses");
    if (!addresses.isUndefined()) {
        if (!addresses.isArray()) return {};
        for (const auto &address : addresses.toArray()) {
            if (!address.isString()) return {};
            active.append(address.toString());
        }
    }
    const auto result = campusCaptureTargets(resources,policy,active,originalDNS);
    if (!result || result->dnsDomains != dnsDomains) return {};
    return result->ipv4Prefixes;
}

std::optional<std::pair<QString, QString>> privateTUNAddresses(const QJsonObject &network, const QStringList &reservedPrefixes)
{
    const auto original = originalNetworkProtection(network);
    if (!original || reservedPrefixes.size() > MaxModelItems) return {};
    IPv4Ranges blocked;
    auto exclude = [&](const QString &text) {
        const auto subnet = QHostAddress::parseSubnet(text);
        if (subnet.second < 2 || mapped(subnet.first) || !subnet.first.scopeId().isEmpty()) return false;
        if (subnet.first.protocol() != QAbstractSocket::IPv4Protocol) return true;
        const quint64 first = subnet.first.toIPv4Address(), span = quint64(1) << (32-subnet.second);
        if (first % span || text != subnet.first.toString()+"/"+QString::number(subnet.second)) return false;
        blocked.append({first, first+span-1});
        return true;
    };
    for (const auto &entry : *original) if (!exclude(entry.toObject()["prefix"].toString())) return {};
    for (const auto &prefix : reservedPrefixes) if (!exclude(prefix)) return {};
    // A cache does not grant protection, but its currently used private address is unavailable for allocation.
    for (const auto &value : network["routes"].toArray()) {
        const auto row = value.toObject();
        const auto prefix = row["destination"].toString();
        if (row["cloned"] == true && QHostAddress::parseSubnet(prefix).second > 1 && !exclude(prefix)) return {};
    }
    blocked = mergedRanges(blocked);
    // RFC 1918 candidate pools are fixed protocol ranges, not fixed device addresses.
    for (const auto *pool : {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
        const auto subnet = QHostAddress::parseSubnet(QString::fromLatin1(pool));
        const quint64 start = subnet.first.toIPv4Address(), end = start+(quint64(1) << (32-subnet.second))-2;
        auto candidate = start+1;
        for (const auto &range : blocked) {
            if (range.second < candidate) continue;
            if (range.first > candidate+1) break;
            candidate = range.second+1;
            if (candidate+1 > end) break;
        }
        if (candidate+1 <= end)
            return std::pair{QHostAddress(quint32(candidate)).toString(), QHostAddress(quint32(candidate+1)).toString()};
    }
    return {};
}

std::optional<QStringList> tunAddressReservations(const QStringList &captures,const QJsonObject &dns,const QString &localDNS)
{
    auto reserved = captures;
    auto reserveLiteral = [&](const QString &token) {
        QHostAddress address(token);
        if (address.isNull()) address = QHostAddress(QUrl("dns://"+token).host());
        bool ipv4 = false;
        const auto number = address.toIPv4Address(&ipv4);
        if (ipv4) reserved.append(QHostAddress(number).toString()+"/32");
    };
    reserveLiteral(localDNS);
    QList<QJsonValue> pending{dns};
    while (!pending.isEmpty()) {
        const auto value = pending.takeLast();
        if (value.isObject()) for (const auto &entry : value.toObject()) pending.append(entry);
        else if (value.isArray()) for (const auto &entry : value.toArray()) pending.append(entry);
        else if (value.isString()) {
            // Conservatively reserve IP literals, including resolver-file tokens; this never changes DNS policy.
            auto text = value.toString();
            text.replace('#',' '); text.replace(';',' ');
            for (const auto &token : text.split(QRegularExpression("\\s+"),Qt::SkipEmptyParts)) reserveLiteral(token);
        }
        if (pending.size() > MaxModelItems || reserved.size() > MaxModelItems)
            return {};
    }
    reserved.removeDuplicates();
    return reserved;
}
