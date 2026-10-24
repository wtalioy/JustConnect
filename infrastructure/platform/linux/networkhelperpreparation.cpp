#include "networkhelperpreparation.h"
#include "application/networkprotection.h"
#include "infrastructure/platform/tundevice.h"
#include "ownedroutetable.h"
#include <QHostAddress>
#include <QJsonDocument>
#include <QSet>
#include <QUrl>

namespace {
std::optional<QStringList> routeEndpoints(const QStringList &prefixes)
{
    if (prefixes.size() > LinuxRouteSnapshotRows) return {};
    QSet<QString> unique;
    QStringList result;
    for (const auto &prefix : prefixes) {
        if (!canonicalIpv4Prefix(prefix)) return {};
        const auto subnet = QHostAddress::parseSubnet(prefix);
        const quint64 first = subnet.first.toIPv4Address(), last = first + (quint64(1) << (32-subnet.second))-1;
        for (const auto number : {first,last}) {
            const auto address = QHostAddress(quint32(number)).toString();
            if (!unique.contains(address)) { unique.insert(address); result.append(address); }
        }
    }
    return result;
}
}

LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &policy,
    const QJsonObject &network, const DnsSnapshot &dns, const QString &localDNS, int mtu, const PlatformCommandRunner &reader)
{
    using Status = PlatformOperationResult::Status;
    const auto targets = campusCaptureTargets(resources, policy);
    if (!targets || targets->ipv4Prefixes.isEmpty()) return {{Status::Unsupported, "Cannot derive safe campus capture targets."}, {}};
    if (!dns.result.succeeded()) return {dns.result, {}};
    auto reserved = targets->ipv4Prefixes;
    auto reserveLiteral = [&](const QString &token) {
        QHostAddress address(token);
        if (address.isNull()) address = QHostAddress(QUrl("dns://"+token).host());
        bool ipv4 = false;
        const auto number = address.toIPv4Address(&ipv4);
        if (ipv4) reserved.append(QHostAddress(number).toString()+"/32");
    };
    reserveLiteral(localDNS);
    QList<QJsonValue> pending{dns.data};
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
        if (pending.size() > LinuxRouteSnapshotRows || reserved.size() > LinuxRouteSnapshotRows)
            return {{Status::Failed,"DNS address reservations exceed the complete input bound."},{}};
    }
    reserved.removeDuplicates();
    const auto addresses = privateTUNAddresses(network, reserved);
    if (!addresses) return {{Status::Unsupported, "No unused private IPv4 address pair is available."}, {}};
    if (!UnixTunDevice::validIpv4Configuration(addresses->first, addresses->second, mtu)
        || !resources["underlay_interface"].isString())
        return {{Status::Failed, "Invalid TUN MTU or missing underlay preference."}, {}};
    const auto preferred = resources["underlay_interface"].toString();
    if (!preferred.isEmpty() && !canonicalLinuxInterfaceName(preferred))
        return {{Status::Failed, "Invalid underlay interface name."}, {}};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {{Status::Unsupported, "A trusted system iproute2 executable is required."}, {}};
    const auto queries = routeEndpoints(targets->ipv4Prefixes);
    if (!queries) return {{Status::Failed,"Invalid route query endpoints."},{}};
    QByteArray batch;
    for (const auto &address : *queries) {
        batch += "route get " + address.toLatin1();
        if (!preferred.isEmpty()) batch += " oif " + preferred.toLatin1();
        batch += '\n';
    }
    // One process handles all read-only queries; each compact JSON array is one output line.
    const QStringList arguments{"-N", "-j", "-4", "-batch", "-"};
    const auto read = reader ? reader(utility, arguments)
        : runPlatformCommand(utility, arguments, LinuxRouteOperationTimeoutMs, batch);
    if (!read.result.succeeded()) return {read.result, {}};
    if (read.output.toUtf8().size() > LinuxRouteSnapshotBytes || read.output.contains(QChar::ReplacementCharacter))
        return {{Status::Failed, "Original route queries exceeded the complete output bound."}, {}};
    const auto lines = read.output.split('\n', Qt::SkipEmptyParts);
    if (lines.size() != queries->size()) return {{Status::Failed, "Incomplete original route query results."}, {}};
    LinuxHelperConfiguration config;
    config.address = addresses->first;
    config.peer = addresses->second;
    config.mtu = mtu;
    config.capturePrefixes = config.originalPrefixes = targets->ipv4Prefixes;
    config.dnsDomains = targets->dnsDomains;
    for (qsizetype index=0; index<lines.size(); ++index) {
        const auto document = QJsonDocument::fromJson(lines[index].toUtf8());
        if (!document.isArray() || document.array().size() != 1 || !document.array().first().isObject())
            return {{Status::Failed, "Invalid original route query result."}, {}};
        const auto row = document.array().first().toObject();
        const auto interface = row["dev"].toString(), source = row["prefsrc"].toString(), gateway = row["gateway"].toString();
        if (row["dst"] != (*queries)[index] || !canonicalLinuxInterfaceName(interface) || !canonicalUnicastIpv4(source)
            || (!gateway.isEmpty() && !canonicalUnicastIpv4(gateway)) || source == gateway
            || (!preferred.isEmpty() && interface != preferred) || row.contains("nhid") || row.contains("nexthops")
            || (row.contains("type") && row["type"] != "unicast")
            || !row["flags"].isArray() || !row["flags"].toArray().isEmpty())
            return {{Status::Unsupported, "Original exit is ambiguous or unsupported."}, {}};
        bool assigned = false;
        for (const auto &entry : network["interfaces"].toArray()) {
            const auto iface = entry.toObject();
            if (iface["name"] != interface || !iface["up"].toBool() || iface["loopback"].toBool()) continue;
            for (const auto &address : iface["addresses"].toArray())
                assigned |= address.isString() && QHostAddress(address.toString().section('/',0,0)) == QHostAddress(source);
        }
        if (!assigned) return {{Status::Failed, "Original source is absent from the network snapshot."}, {}};
        if (index == 0) {
            config.originalInterface = interface;
            config.originalSource = source;
            config.originalGateway = gateway;
        } else if (config.originalInterface != interface || config.originalSource != source || config.originalGateway != gateway)
            return {{Status::Unsupported, "Campus targets use different original exits."}, {}};
    }
    const auto valid = LinuxOwnedRouteTable::validate(config.originalInterface, config.originalSource, config.originalGateway, config.originalPrefixes);
    if (!valid.succeeded()) return {valid, {}};
    return {{}, config};
}

std::optional<QStringList> updatedLinuxCapturePrefixes(const QJsonObject &resources, const QJsonObject &previous,
    const QJsonObject &next, const LinuxHelperConfiguration &owned)
{
    const auto before = campusCaptureTargets(resources,previous);
    if (!before || before->dnsDomains != owned.dnsDomains) return {};
    for (const auto &prefix : before->ipv4Prefixes) if (!owned.capturePrefixes.contains(prefix)) return {};
    QStringList dynamic;
    for (const auto &prefix : owned.capturePrefixes) {
        if (before->ipv4Prefixes.contains(prefix)) continue;
        if (!canonicalIpv4Prefix(prefix) || !prefix.endsWith("/32")) return {};
        dynamic.append(prefix.chopped(3));
    }
    const auto result = campusCaptureTargets(resources,next,dynamic);
    if (!result || result->dnsDomains != owned.dnsDomains) return {};
    return result->ipv4Prefixes;
}

PlatformOperationResult verifyLinuxCaptureExit(const LinuxHelperConfiguration &owned, const QStringList &prefixes,
    const PlatformCommandRunner &reader)
{
    using Status = PlatformOperationResult::Status;
    if (!canonicalUnicastIpv4(owned.originalSource) || prefixes.size() > LinuxRouteSnapshotRows)
        return {Status::Failed,"Invalid original route verification input."};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    const auto queries = routeEndpoints(prefixes);
    if (!queries) return {Status::Failed,"Invalid capture prefixes."};
    if (queries->isEmpty()) return {};
    QByteArray batch;
    for (const auto &address : *queries)
        batch += "route get " + address.toLatin1() + " from " + owned.originalSource.toLatin1() + '\n';
    const QStringList args{"-N","-j","-4","-batch","-"};
    const auto read = reader ? reader(utility,args) : runPlatformCommand(utility,args,LinuxRouteOperationTimeoutMs,batch);
    if (!read.result.succeeded()) return read.result;
    if (read.output.toUtf8().size() > LinuxRouteSnapshotBytes || read.output.contains(QChar::ReplacementCharacter))
        return {Status::Failed,"Original exit verification exceeded its complete output budget."};
    const auto lines = read.output.split('\n',Qt::SkipEmptyParts);
    if (lines.size() != queries->size()) return {Status::Failed,"Incomplete original exit verification."};
    for (qsizetype i=0; i<lines.size(); ++i) {
        const auto parsed = QJsonDocument::fromJson(lines[i].toUtf8());
        const auto rows = parsed.array();
        if (!parsed.isArray() || rows.size() != 1 || !rows[0].isObject()) return {Status::Failed,"Invalid original exit verification."};
        const auto row = rows[0].toObject();
        if (row["dst"] != (*queries)[i] || row["from"] != owned.originalSource || row["dev"] != owned.originalInterface
            || row["gateway"].toString() != owned.originalGateway || row.contains("nhid") || row.contains("nexthops")
            || (row.contains("type") && row["type"] != "unicast") || !row["flags"].isArray() || !row["flags"].toArray().isEmpty())
            return {Status::Unsupported,"Changed capture targets no longer share the confirmed original exit."};
    }
    return {};
}
