#include "campuscapture.h"
#include "networkprotection.h"
#include "networkmodel_p.h"
#include "infrastructure/dns/dnsdomains.h"
#include <QRegularExpression>
#include <QSet>
#include <QUrl>
#include <algorithm>

using namespace networkModel;

namespace {
using IPv4Range = std::pair<quint64, quint64>;
using IPv4Ranges = QList<IPv4Range>;

const IPv4Ranges &privateIPv4Ranges()
{
    static const auto ranges = [] {
        IPv4Ranges result;
        for (const auto *prefix : {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}) {
            const auto subnet = QHostAddress::parseSubnet(QString::fromLatin1(prefix));
            const quint64 start = subnet.first.toIPv4Address();
            result.append({start, start + (quint64(1) << (32-subnet.second)) - 1});
        }
        return result;
    }();
    return ranges;
}

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

std::optional<QStringList> domainDnsOverrideNames(const QJsonObject &resources)
{
    const auto exact = resources.value("domain_dns_names");
    if (exact.isUndefined()) return QStringList{};
    if (!exact.isArray() || exact.toArray().size() > MaxModelItems) return {};
    QStringList result;
    QSet<QString> seen;
    for (const auto &entry : exact.toArray()) {
        const auto host = entry.toString();
        if (!canonicalDnsDomain(host) || !canonicalProtectionName(host) || !host.contains('.') || seen.contains(host)) return {};
        seen.insert(host);
        result.append(host);
    }
    return result;
}

QStringList campusDnsDomainsToInstall(const QStringList &domains,const QJsonArray &sources)
{
    QStringList result;
    for(const auto &domain:domains){
        bool covered=false;
        for(const auto &value:sources){
            const auto source=value.toObject();
            if (source["supplemental_fallback"]==true) continue;
            const auto name=source["name"].toObject();const auto scope=name["value"].toString();
            covered|=(name["kind"]=="suffix" && (domain==scope || domain.endsWith('.'+scope)))
                || (name["kind"]=="single_label" && !domain.contains('.'));
        }
        if(!covered)result.append(domain);
    }
    return result;
}

std::optional<CampusCaptureTargets> campusCaptureTargets(const QJsonObject &resources, const QJsonObject &policy, const QStringList &dynamicAddresses, const QJsonArray &originalDNS, QString *diagnostic)
{
    const auto fail = [&](const QString &reason) -> std::optional<CampusCaptureTargets> {
        if (diagnostic) *diagnostic = reason;
        return {};
    };
    if (diagnostic) *diagnostic = QStringLiteral("Cannot derive safe campus capture targets: invalid resource or policy input.");
    if (!resources["ip_resources"].isArray() || !resources["domain_resources"].isObject()
        || !resources["dns_records"].isObject() || !resources["campus_dns"].isString()
        || !resources["campus_dns_enabled"].isBool() || !policy["protected"].isArray()
        || !policy["campus"].isArray() || !policy["protected_names"].isArray() || !policy["campus_names"].isArray()) return {};
    const auto ips = resources["ip_resources"].toArray(), protectedIPs = policy["protected"].toArray(), choices = policy["campus"].toArray();
    const auto domains = resources["domain_resources"].toObject(), records = resources["dns_records"].toObject();
    const auto names = policy["protected_names"].toArray(), campusNames = policy["campus_names"].toArray();
    for (const auto size : {ips.size(), protectedIPs.size(), choices.size(), domains.size(), records.size(), names.size(), campusNames.size(), dynamicAddresses.size()})
        if (size > MaxModelItems) return fail(QStringLiteral("Campus capture input exceeds the rule limit (%1 > %2).").arg(size).arg(MaxModelItems));
    const auto required = requiredOriginalDnsNames(resources,policy);
    const auto exact = domainDnsOverrideNames(resources);
    if (!required || !exact || originalDNS.size() > MaxModelItems) return {};
    QJsonArray forwarded;
    IPv4Ranges included, excluded, selected;
    IPv4Ranges originalServers;
    for (const auto &value : originalDNS) {
        if (!value.isObject()) return {};
        const auto row = value.toObject();
        if (!row["name"].isObject() || !row["servers"].isArray() || row["servers"].toArray().isEmpty()) return {};
        if (row["supplemental_fallback"] == true) {
            const auto name = row["name"].toObject();
            if (name["kind"] != "suffix" || !exact->contains(name["value"].toString())) return {};
        } else {
            if (!names.contains(row["name"])) return {};
            forwarded.append(row["name"]);
        }
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
    for (qsizetype index = 0; index < ips.size(); ++index) {
        const auto entry = ips[index];
        if (!entry.isObject()) return {};
        const auto row = entry.toObject();
        const auto protocol = row["protocol"].toString();
        if (protocol == "icmp") continue; // The current transparent ingress carries TCP/UDP only.
        if (protocol != "all" && protocol != "tcp" && protocol != "udp")
            return fail(QStringLiteral("Campus IP resource %1 has an unsupported transport.").arg(index));
        const int firstPort = row["port_min"].toInt(-1), lastPort = row["port_max"].toInt(-1);
        if (firstPort < 1 || lastPort > 65535 || firstPort > lastPort)
            return fail(QStringLiteral("Campus IP resource %1 has an invalid destination port range (%2-%3).").arg(index).arg(firstPort).arg(lastPort));
        if (!add(row["ip_min"].toString(), row["ip_max"].toString()))
            return fail(QStringLiteral("Campus IP resource %1 has an invalid address range or exceeds the rule limit.").arg(index));
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
    const auto authenticationAddress = resources.value("original_authentication_address");
    if (!authenticationAddress.isUndefined()) {
        if (!authenticationAddress.isString()) return {};
        const auto address = ipv4Number(authenticationAddress.toString());
        if (!address) return {};
        excluded.append({*address, *address});
    }
    IPv4Ranges reserved;
    // Match the helper's unicast address boundary; campus choices cannot capture these ranges.
    for (const auto &prefix : {"0.0.0.0/8", "127.0.0.0/8", "224.0.0.0/3"}) {
        const auto subnet = QHostAddress::parseSubnet(QString::fromLatin1(prefix));
        const quint64 first = subnet.first.toIPv4Address();
        reserved.append({first, first + (quint64(1) << (32 - subnet.second)) - 1});
    }
    excluded.append(reserved);
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
        if (!address || !add(server, server) || std::any_of(reserved.begin(), reserved.end(),
            [&](const IPv4Range &range) { return range.first <= *address && *address <= range.second; }))
            return fail(QStringLiteral("The campus DNS server is not a usable IPv4 address."));
        // Internal DNS uses the existing campus tunnel; subtraction below preserves a shared original endpoint.
    }
    for (auto it = records.begin(); it != records.end(); ++it) {
        if (!it.value().isArray()) return {};
        for (const auto &value : it.value().toArray())
            if (!value.isString() || !add(value.toString(), value.toString())) return {};
    }
    const auto fallback = resources.value("private_ip_ranges");
    if (!fallback.isUndefined() && !fallback.isArray()) return {};
    const auto fallbackRanges = fallback.toArray();
    if (fallbackRanges.size() > MaxModelItems) return {};
    const auto reservedRanges = subtractRanges(mergedRanges(included), mergedRanges(excluded));
    const auto reservedPrefixes = prefixesForRanges(reservedRanges);
    if (!reservedPrefixes) return fail(QStringLiteral("Campus capture prefixes exceed the rule limit after preserving original networks."));
    result.privateFallback = !fallbackRanges.isEmpty();
    result.reservedPrefixes = *reservedPrefixes;
    for (const auto &value : fallbackRanges) {
        const auto bounds = value.toArray();
        if (bounds.size() != 2) return {};
        const auto first = ipv4Number(bounds[0].toString()), last = ipv4Number(bounds[1].toString());
        if (!first || !last || *first > *last
            || !std::any_of(privateIPv4Ranges().begin(), privateIPv4Ranges().end(), [&](const auto &pool) {
                return pool.first <= *first && *last <= pool.second;
            })) return {};
        included.append({*first, *last});
    }
    const auto prefixes = result.privateFallback
        ? prefixesForRanges(subtractRanges(mergedRanges(included), mergedRanges(excluded))) : reservedPrefixes;
    if (!prefixes) return fail(QStringLiteral("Campus capture prefixes exceed the rule limit after preserving original networks."));
    result.ipv4Prefixes = *prefixes;
    if (diagnostic) *diagnostic = prefixes->isEmpty() && result.dnsDomains.isEmpty()
        ? QStringLiteral("No usable campus IPv4 target remains after preserving original networks.") : QString{};
    return result;
}

std::optional<QStringList> updatedCampusCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const QStringList &dnsDomains, const QJsonArray &originalDNS, const QStringList &deviceAddresses)
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
    if (result->privateFallback) return excludeCampusCaptureAddresses(result->ipv4Prefixes, deviceAddresses);
    return result->ipv4Prefixes;
}

CampusTunCapture prepareCampusTunCapture(const CampusCaptureTargets &targets,
    const QJsonObject &network, const QJsonObject &dns, const QString &localDNS)
{
    using Status = PlatformOperationResult::Status;
    const auto reserved = tunAddressReservations(targets.reservedPrefixes, dns, localDNS);
    if (!reserved) return {{Status::Failed, QStringLiteral("DNS address reservations exceed the complete input bound.")}};
    const auto addresses = privateTUNAddresses(network, *reserved);
    if (!addresses) return {{Status::Unsupported, QStringLiteral("No unused private IPv4 address pair is available.")}};
    const auto prefixes = targets.privateFallback
        ? excludeCampusCaptureAddresses(targets.ipv4Prefixes, {addresses->first, addresses->second})
        : std::optional{targets.ipv4Prefixes};
    if (!prefixes) return {{Status::Unsupported, QStringLiteral("Campus capture prefixes exceed the rule limit after excluding the private device.")}};
    return {{}, addresses->first, addresses->second, *prefixes};
}

std::optional<std::pair<QString, QString>> privateTUNAddresses(const QJsonObject &network, const QStringList &reservedPrefixes)
{
    const auto view = originalProxyNetworkView(network);
    const auto original = view ? originalNetworkProtection(*view) : std::nullopt;
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
    const auto proxyIndex = network["proxy_tunnel"].toObject()["interface_index"].toInteger();
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (proxyIndex <= 0 || row["index"] != proxyIndex) continue;
        for (const auto &address : row["addresses"].toArray()) {
            const auto subnet = QHostAddress::parseSubnet(address.toString());
            if (!exclude(subnet.first.toString()+'/'+QString::number(subnet.second))) return {};
        }
    }
    // A cache does not grant protection, but its currently used private address is unavailable for allocation.
    for (const auto &value : network["routes"].toArray()) {
        const auto row = value.toObject();
        const auto prefix = row["destination"].toString();
        if (row["cloned"] == true && QHostAddress::parseSubnet(prefix).second > 1 && !exclude(prefix)) return {};
    }
    blocked = mergedRanges(blocked);
    for (const auto &[start, broadcast] : privateIPv4Ranges()) {
        const auto end = broadcast - 1;
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
