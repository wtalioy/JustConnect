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

QStringList resolvedEndpoints(const QJsonArray &links, const QJsonObject &rule)
{
    const auto kind = rule["kind"].toString();
    const auto name = rule["value"].toString();
    QStringList endpoints;
    qsizetype best = -1;
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
        const auto servers = linuxOriginalDnsEndpoints(link["servers"].toArray());
        if (match > best) endpoints.clear();
        endpoints += servers;
        best = match;
    }
    endpoints.removeDuplicates();
    return endpoints;
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

LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &protection,
    const QJsonObject &network, const QJsonObject &dns, const QString &localDNS, int mtu,
    const QStringList &dynamicAddresses)
{
    using Status = PlatformOperationResult::Status;
    const auto domains = campusDnsDomains(resources);
    if (!domains) return {{Status::Unsupported, QStringLiteral("Cannot determine complete original DNS requirements.")}, {}};
    // Names the policy protects from campus capture must keep resolving via
    // the original resolvers: the rows prove those sources exist, reserve
    // their addresses outside the capture and drop every campus scope they
    // cover from the installed set, so the core refuses those names and
    // glibc-class resolvers fall through to the original servers.
    const auto required = requiredOriginalDnsNames(resources, protection);
    if (!required) return {{Status::Unsupported, QStringLiteral("Cannot determine complete original DNS requirements.")}, {}};
    QJsonArray originalSources;
    if (!required->isEmpty()) {
        const auto sources = linuxOriginalDnsSources(dns, *required);
        if (!sources)
            return {{Status::Unsupported, QStringLiteral("The original Linux DNS source cannot be confirmed for protected names.")}, {}};
        originalSources = *sources;
    }
    QString captureDiagnostic;
    const auto targets = campusCaptureTargets(resources, protection, dynamicAddresses, originalSources, &captureDiagnostic);
    if (!targets) return {{Status::Unsupported, captureDiagnostic}, {}};
    const auto installable = campusDnsDomainsToInstall(targets->dnsDomains, originalSources);
    if (targets->ipv4Prefixes.isEmpty() && installable.isEmpty())
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
    LinuxHelperConfiguration result{capture.address, capture.peer, mtu, capture.prefixes, installable};
    if (!validLinuxHelperRequest(linuxHelperApplyRequest(QUuid::createUuid(), QUuid::createUuid(), result)))
        return {{Status::Failed, QStringLiteral("Invalid or unsupported Linux capture configuration.")}, {}};
    return {{}, result};
}

std::optional<QStringList> updatedLinuxCapturePrefixes(const QJsonObject &resources, const QJsonObject &policy,
    const LinuxHelperConfiguration &configuration, const QJsonObject &network, const QJsonObject &dns)
{
    const auto domains = campusDnsDomains(resources);
    if (!domains) return {};
    // The protected-name forwarding plan must still be derivable from the
    // live DNS snapshot; losing the original resolvers ends the session.
    const auto required = requiredOriginalDnsNames(resources, policy);
    if (!required) return {};
    QJsonArray originalSources;
    if (!required->isEmpty()) {
        const auto sources = linuxOriginalDnsSources(dns, *required);
        if (!sources) return {};
        originalSources = *sources;
    }
    if (campusDnsDomainsToInstall(*domains, originalSources) != configuration.dnsDomains) return {};
    return updatedCampusCapturePrefixes(resources, policy, *domains, originalSources,
        {configuration.address, configuration.peer});
}
