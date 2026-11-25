#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include "application/campuscapture.h"
#include <QHostAddress>
#include <QNetworkInterface>
#include <algorithm>

namespace {
// resolv.conf nameservers speak plain DNS on the standard port; rows carry
// the "addr:port" endpoint form the campus capture planner and the core
// accept (brackets for IPv6 literals).
QStringList linuxOriginalDnsEndpoints(const QJsonArray &nameservers)
{
    QStringList endpoints;
    for (const auto &value : nameservers) {
        if (!value.isString()) continue;
        const QHostAddress address(value.toString());
        if (address.isNull() || address.isMulticast() || address == QHostAddress::AnyIPv4
            || address == QHostAddress::AnyIPv6 || address == QHostAddress::Broadcast) continue;
        endpoints.append((address.protocol() == QAbstractSocket::IPv6Protocol
            ? QLatin1Char('[') + address.toString() + QLatin1Char(']') : address.toString())
            + QStringLiteral(":53"));
    }
    return endpoints;
}

QStringList resolvedEndpoints(const QJsonArray &links, const QJsonObject &rule, bool onlyPlain = false)
{
    const auto kind = rule["kind"].toString();
    const auto name = rule["value"].toString();
    QStringList endpoints;
    qsizetype best = -1;
    bool safe = true;
    for (const auto &entry : links) {
        const auto link = entry.toObject();
        qsizetype match = link["default_route"].toBool() && kind != "single_label" ? 0 : -1;
        for (const auto &domain : link["domains"].toArray()) {
            auto scope = domain.toString().toLower();
            const bool routeOnly = scope.startsWith(QChar('~'));
            if (routeOnly) scope.remove(0, 1);
            if (scope == ".") {
                if (kind != "single_label") match = std::max<qsizetype>(match, 1);
                continue;
            }
            if (scope.endsWith('.')) scope.chop(1);
            if (scope.isEmpty() || scope == ".") continue;
            if (kind == "single_label" && !routeOnly) match = 1;
            else if ((kind == "exact" || kind == "suffix") && (name == scope || name.endsWith('.' + scope)))
                match = std::max(match, scope.size() + 1);
        }
        if (match < 0 || match < best) continue;
        const auto nativeServers = link["servers"].toArray();
        if (nativeServers.isEmpty()) continue;
        const auto servers = linuxOriginalDnsEndpoints(nativeServers);
        if (match > best) {
            endpoints.clear();
            safe = true;
        }
        if (onlyPlain && (link["plain_dns"] != true || servers.size() != nativeServers.size()
            || servers.contains("127.0.0.53:53") || servers.contains("127.0.0.54:53"))) safe = false;
        endpoints += servers;
        best = match;
    }
    endpoints.removeDuplicates();
    return safe ? endpoints : QStringList{};
}
}

std::optional<QJsonArray> linuxOriginalDnsSources(const QJsonObject &dns, const QJsonArray &required)
{
    if (required.isEmpty()) return QJsonArray{};
    const auto resolved = dns["resolved"].toObject().value("links");
    if (dns.contains("resolved") && !resolved.isArray()) return std::nullopt;
    const auto fallback = resolved.isArray() ? QStringList{}
        : linuxOriginalDnsEndpoints(dns["resolv_conf"].toObject()["nameservers"].toArray());
    QJsonArray sources;
    for (const auto &rule : required) {
        if (!rule.isObject()) return std::nullopt;
        const auto endpoints = resolved.isArray() ? resolvedEndpoints(resolved.toArray(), rule.toObject()) : fallback;
        if (endpoints.isEmpty()) return std::nullopt;
        const QJsonObject row{{"name", rule}, {"servers", QJsonArray::fromStringList(endpoints)}};
        if (!sources.contains(row)) sources.append(row);
    }
    return sources;
}

namespace {
struct LinuxDnsCapture {
    QStringList gatewayDomains, domains;
    QJsonArray originalSources, fallbacks;
};

std::optional<LinuxDnsCapture> linuxDnsCapture(const QJsonObject &resources, const QJsonObject &policy, const QJsonObject &dns)
{
    auto gatewayDomains = campusDnsDomains(resources);
    const auto exact = domainDnsOverrideNames(resources);
    if (!gatewayDomains || !exact) return {};
    const auto required = requiredOriginalDnsNames(*gatewayDomains, policy);
    if (!required) return {};
    auto sources = linuxOriginalDnsSources(dns, *required);
    if (!sources) return {};
    auto domains = campusDnsDomainsToInstall(*gatewayDomains, *sources);
    LinuxDnsCapture capture{std::move(*gatewayDomains), std::move(domains), std::move(*sources), {}};
    if (exact->isEmpty()) return capture;

    const auto links = dns["resolved"].toObject()["links"].toArray();
    const auto protectedNames = policy["protected_names"].toArray();
    const auto covers = [](const QString &scope, const QString &host) { return host == scope || host.endsWith('.' + scope); };
    for (const auto &host : *exact) {
        if (std::any_of(capture.domains.begin(), capture.domains.end(), [&](const auto &scope) { return covers(scope, host); })) continue;
        // A resolved route-only domain also catches descendants, so keep native split DNS in place.
        if (covers("local", host) || covers("in-addr.arpa", host) || covers("ip6.arpa", host)) continue;
        if (std::any_of(protectedNames.begin(), protectedNames.end(), [&](const auto &entry) {
            const auto rule = entry.toObject();
            const auto kind = rule["kind"].toString(), scope = rule["value"].toString();
            return kind == "prefix" || ((kind == "exact" || kind == "suffix") && covers(host, scope))
                || (kind == "suffix" && covers(scope, host));
        })) continue;
        const QJsonObject rule{{"kind", "suffix"}, {"value", host}};
        const auto servers = resolvedEndpoints(links, rule, true);
        if (servers.isEmpty()) continue;
        const QJsonObject source{{"name", rule}, {"servers", QJsonArray::fromStringList(servers)}, {"supplemental_fallback", true}};
        capture.fallbacks.append(source);
        capture.originalSources.append(source);
        capture.domains.append(host);
    }
    capture.domains.sort();
    return capture;
}
}

LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &protection,
    const QJsonObject &network, const QJsonObject &dns, const QString &localDNS, int mtu,
    const QStringList &dynamicAddresses)
{
    using Status = PlatformOperationResult::Status;
    const auto dnsCapture = linuxDnsCapture(resources, protection, dns);
    if (!dnsCapture)
        return {{Status::Unsupported, QStringLiteral("Cannot confirm the original Linux DNS sources for campus capture.")}, {}};
    QString captureDiagnostic;
    const auto targets = campusCaptureTargets(resources, protection, dynamicAddresses, dnsCapture->originalSources, &captureDiagnostic);
    if (!targets) return {{Status::Unsupported, captureDiagnostic}, {}};
    if (targets->ipv4Prefixes.isEmpty() && dnsCapture->domains.isEmpty())
        return {{Status::Unsupported, captureDiagnostic}, {}};
    const auto capture = prepareCampusTunCapture(*targets, network, dns, localDNS);
    if (!capture.result.succeeded()) return {capture.result, {}};
    if (!resources["underlay_interface"].isString())
        return {{Status::Failed, QStringLiteral("Missing original underlay preference.")}, {}};
    const auto interface = resources["underlay_interface"].toString();
    if (!interface.isEmpty()) {
        const auto actual = QNetworkInterface::interfaceFromName(interface);
        if (!actual.isValid() || !(actual.flags() & QNetworkInterface::IsUp))
            return {{Status::Failed, QStringLiteral("The confirmed underlay interface is no longer available.")}, {}};
    }
    LinuxHelperConfiguration result{capture.address, capture.peer, mtu, capture.prefixes, dnsCapture->domains};
    if (!validLinuxHelperRequest(linuxHelperApplyRequest(QUuid::createUuid(), QUuid::createUuid(), result)))
        return {{Status::Failed, QStringLiteral("Invalid or unsupported Linux capture configuration.")}, {}};
    return {{}, result, dnsCapture->fallbacks};
}

std::optional<QStringList> updatedLinuxCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const LinuxHelperConfiguration &configuration, const QJsonObject &dns, const QJsonArray &activeFallbacks)
{
    const auto dnsCapture = linuxDnsCapture(resources, policy, dns);
    if (!dnsCapture || dnsCapture->domains != configuration.dnsDomains || dnsCapture->fallbacks != activeFallbacks) return {};
    return updatedCampusCapturePrefixes(resources, policy, dnsCapture->gatewayDomains, dnsCapture->originalSources,
        {configuration.address, configuration.peer});
}
