#include "infrastructure/networkhelper/linux/networkhelperpreparation.h"
#include "application/networkprotection.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/routing/linux/ownedroutetable.h"
#include "infrastructure/routing/linux/originalexit.h"
#include <QHostAddress>
#include <QJsonDocument>
#include <QMap>
#include <QUrl>
#include <sys/socket.h>


namespace {
LinuxHelperPreparation prepareOriginalDNS(const QJsonArray &required, const QJsonObject &network,
    const QJsonObject &dns, const LinuxOriginalDNSReader &reader, QDeadlineTimer &deadline)
{
    using Status = PlatformOperationResult::Status;
    auto unsupported = [](const char *message) { return LinuxHelperPreparation{{Status::Unsupported,QString::fromLatin1(message)},{},{}}; };
    const auto protection = originalDnsProtection(dns);
    const auto resolved = dns["resolved"].toObject();
    if (!protection || resolved["status"] != "available") return unsupported("The original resolver context is unavailable.");
    if (!LinuxResolved::nativeStubRouting(resolved))
        return unsupported("The native stub resolver routing cannot be confirmed.");
    const auto targets = (*protection)["targets"].toArray(), namespaces = (*protection)["namespaces"].toArray();
    QMap<int,QJsonArray> scopes;
    for (const auto &value : required) {
        const auto rule = value.toObject();
        bool found = false;
        for (const auto &target : targets) {
            const auto row = target.toObject();
            if (row["kind"] != rule["kind"] || row["value"] != rule["value"]) continue;
            for (const auto &reference : row["sources"].toArray()) {
                const auto ref = reference.toObject();
                const auto at = ref["index"].toInt(-1);
                if (ref["kind"] != "namespace" || at < 0 || at >= namespaces.size())
                    return unsupported("A protected name has no replaceable native resolver context.");
                const auto origin = namespaces[at].toObject()["source"].toObject();
                if (origin["provider"] == "resolv_conf") continue;
                if (origin["provider"] != "resolved" || origin["interface_index"].toInt() <= 0)
                    return unsupported("A protected name requires an unsupported global resolver context.");
                auto &names = scopes[origin["interface_index"].toInt()];
                if (!names.contains(rule)) names.append(rule);
                found = true;
            }
        }
        if (!found) return unsupported("A protected name cannot be mapped to its native DNS interface.");
    }
    LinuxHelperPreparation result;
    qsizetype endpoints = 0;
    for (auto it = scopes.cbegin(); it != scopes.cend(); ++it) {
        QJsonObject interface;
        for (const auto &value : network["interfaces"].toArray()) {
            const auto row = value.toObject();
            if (row["index"] != it.key()) continue;
            if (!interface.isEmpty()) return unsupported("The original DNS interface is ambiguous.");
            interface = row;
        }
        const auto name = interface["name"].toString();
        if (!canonicalLinuxInterfaceName(name) || interface["up"] != true || interface["loopback"] != false)
            return unsupported("The original DNS interface is unavailable.");
        QString local;
        for (const auto &value : interface["addresses"].toArray()) {
            if (!value.isString()) return unsupported("The original DNS interface address is invalid.");
            const auto address = value.toString().section('/',0,0);
            if (canonicalUnicastIpv4(address)) { local = address; break; }
        }
        if (local.isEmpty()) return unsupported("The original DNS interface has no assigned IPv4 listener address.");
        const auto snapshot = reader ? reader(it.key(),deadline)
            : LinuxResolved::readLink(QDBusConnection::systemBus(),it.key(),deadline);
        if (!snapshot.result.succeeded()) return {snapshot.result,{},{}};
        const auto expected = snapshot.expectation(it.key());
        const auto observed = LinuxResolved::linkInputs(resolved,it.key(),name);
        if (snapshot.absent || !snapshot.extended || !observed || !LinuxResolved::providerIdentity(snapshot.provider)
            || (*observed)["profile"] != snapshot.profile || (*observed)["security"] != snapshot.security)
            return unsupported("The original DNS profile changed during preparation.");
        auto tls = snapshot.security.value("DNSOverTLS");
        if (tls == "") tls = resolved.value("DNSOverTLS");
        if (tls != "no") return unsupported("The native DNS transport cannot be downgraded to a plain relay.");
        const auto servers = snapshot.profile["dns"].toArray();
        if (servers.isEmpty()) return unsupported("The original DNS server list is empty.");
        bool loopback = true, anyLoopback = false;
        for (const auto &value : servers) {
            const QHostAddress address(value.toObject()["address"].toString());
            loopback &= address.isLoopback(); anyLoopback |= address.isLoopback();
        }
        if (loopback != anyLoopback) return unsupported("The native server list requires multiple query interfaces.");
        QString queryInterface = name;
        if (loopback) {
            queryInterface.clear();
            for (const auto &value : network["interfaces"].toArray()) {
                const auto row = value.toObject();
                if (row["up"] != true || row["loopback"] != true) continue;
                if (!queryInterface.isEmpty()) return unsupported("The loopback query interface is ambiguous.");
                queryInterface = row["name"].toString();
            }
            if (!canonicalLinuxInterfaceName(queryInterface)) return unsupported("No native loopback query interface is available.");
        }
        QJsonArray literals;
        for (const auto &value : servers) {
            const auto row = value.toObject();
            QHostAddress address(row["address"].toString());
            const auto port = row["port"].toInt(-1), family = row["family"].toInt();
            if (address.isNull() || address.isMulticast() || address == QHostAddress::AnyIPv4 || address == QHostAddress::AnyIPv6
                || address == QHostAddress::Broadcast || port < 0 || port > 65535
                || (family != AF_INET && family != AF_INET6)
                || (family == AF_INET) != (address.protocol() == QAbstractSocket::IPv4Protocol))
                return unsupported("The native DNS server is not a complete unicast endpoint.");
            if (address.protocol() == QAbstractSocket::IPv6Protocol && address.isLinkLocal()) address.setScopeId(queryInterface);
            // DNSEx port zero denotes the DNS protocol's standard port.
            const auto endpoint = (family == AF_INET6 ? '['+address.toString()+']' : address.toString()) + ':' + QString::number(port ? port : DnsServerPort);
            literals.append(endpoint);
        }
        for (const auto &rule : it.value()) {
            endpoints += literals.size();
            if (endpoints > LinuxRouteSnapshotRows) return unsupported("The original DNS source plan exceeds its complete bound.");
            result.originalSources.append(QJsonObject{{"name",rule},{"servers",literals},{"interface",queryInterface},
                {"source",QString::number(it.key())},{"listen",local+":0"}});
        }
        result.configuration.originalDns.append({name,local,0,expected});
    }
    return result;
}
}

LinuxHelperPreparation prepareLinuxNetworkHelper(const QJsonObject &resources, const QJsonObject &policy,
    const QJsonObject &network, const DnsSnapshot &dns, const QString &localDNS, int mtu, const PlatformCommandRunner &reader, const LinuxOriginalDNSReader &dnsReader)
{
    using Status = PlatformOperationResult::Status;
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto required = requiredOriginalDnsNames(resources,policy);
    if (!required) return {{Status::Unsupported,"Cannot determine the complete original DNS requirements."},{},{}};
    LinuxHelperPreparation original;
    if (!required->isEmpty()) {
        if (!dns.result.succeeded()) return {dns.result,{},{}};
        original = prepareOriginalDNS(*required,network,dns.data,dnsReader,deadline);
        if (!original.result.succeeded()) return original;
    }
    QString captureDiagnostic;
    const auto targets = campusCaptureTargets(resources, policy, {}, original.originalSources, &captureDiagnostic);
    if (!targets || (targets->ipv4Prefixes.isEmpty() && targets->dnsDomains.isEmpty())) return {{Status::Unsupported, captureDiagnostic}, {}};
    if (!dns.result.succeeded()) return {dns.result, {}};
    const auto reserved = tunAddressReservations(targets->ipv4Prefixes,dns.data,localDNS);
    if (!reserved) return {{Status::Failed,"DNS address reservations exceed the complete input bound."},{}};
    const auto addresses = privateTUNAddresses(network,*reserved);
    if (!addresses) return {{Status::Unsupported, "No unused private IPv4 address pair is available."}, {}};
    if (!UnixTunDevice::validIpv4Configuration(addresses->first, addresses->second, mtu)
        || !resources["underlay_interface"].isString())
        return {{Status::Failed, "Invalid TUN MTU or missing underlay preference."}, {}};
    const auto preferred = resources["underlay_interface"].toString();
    if (!preferred.isEmpty() && !canonicalLinuxInterfaceName(preferred))
        return {{Status::Failed, "Invalid underlay interface name."}, {}};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {{Status::Unsupported, "A trusted system iproute2 executable is required."}, {}};
    const auto queries = linuxRouteEndpoints(targets->ipv4Prefixes);
    if (!queries) return {{Status::Failed,"Invalid route query endpoints."},{}};
    QByteArray batch;
    for (const auto &address : *queries) {
        batch += "route get " + address.toLatin1();
        if (!preferred.isEmpty()) batch += " oif " + preferred.toLatin1();
        batch += '\n';
    }
    // One process handles all read-only queries; each compact JSON array is one output line.
    const QStringList arguments{"-N", "-j", "-4", "-batch", "-"};
    if (deadline.hasExpired()) return {{Status::TimedOut,"Original network preparation timed out."},{},{}};
    const auto read = reader ? reader(utility, arguments)
        : runPlatformCommand(utility, arguments, int(deadline.remainingTime()), batch);
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
    config.originalDns = original.configuration.originalDns;
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
    return {{}, config, original.originalSources};
}

std::optional<LinuxHelperConfiguration> completeLinuxOriginalDNS(LinuxHelperConfiguration configuration, const QJsonObject &listeners)
{
    if (listeners.size() != configuration.originalDns.size()) return {};
    for (auto &link : configuration.originalDns) {
        const auto source = QString::number(link.expected["index"].toInt());
        const auto value = listeners[source];
        if (!value.isString()) return {};
        const auto literal = value.toString();
        const QUrl endpoint("dns://"+literal);
        const auto port = endpoint.port(0);
        if (port < 1 || port > 65535 || literal != link.source+':'+QString::number(port)) return {};
        link.port = quint16(port);
    }
    return configuration;
}

PlatformOperationResult verifyLinuxCaptureExit(const LinuxHelperConfiguration &owned, const QStringList &prefixes,
    const PlatformCommandRunner &reader)
{
    return verifyLinuxOriginalExit(owned.originalInterface, owned.originalSource, owned.originalGateway, prefixes, reader);
}

std::optional<QJsonObject> linuxOriginalExitSnapshot(const QJsonObject &network, const LinuxHelperConfiguration &owned)
{
    if (!network["interfaces"].isArray() || !network["routes"].isArray() || !network["policy_rules"].isArray()) return {};
    int index = 0;
    for (const auto &value : network["interfaces"].toArray()) {
        const auto row = value.toObject();
        if (row["name"] != owned.originalInterface) continue;
        if (index || row["index"].toInt() <= 0 || row["up"] != true || row["loopback"] != false || !row["addresses"].isArray()) return {};
        bool assigned = false;
        for (const auto &address : row["addresses"].toArray())
            assigned |= address.toString().section('/',0,0) == owned.originalSource;
        if (!assigned) return {};
        index = row["index"].toInt();
    }
    if (!index) return {};
    QStringList routes, rules;
    for (const auto &value : network["routes"].toArray()) {
        const auto row = value.toObject();
        const auto prefix = QHostAddress::parseSubnet(row["destination"].toString());
        if (!value.isObject() || prefix.second < 0) return {};
        if (prefix.first.protocol() == QAbstractSocket::IPv4Protocol
            && (row["interface_index"] == index || prefix.second <= 1))
            routes.append(QString::fromUtf8(QJsonDocument(row).toJson(QJsonDocument::Compact)));
    }
    for (const auto &value : network["policy_rules"].toArray()) {
        if (!value.isObject()) return {};
        rules.append(QString::fromUtf8(QJsonDocument(value.toObject()).toJson(QJsonDocument::Compact)));
    }
    routes.sort();rules.sort();
    return QJsonObject{{"index",index},{"source",owned.originalSource},
        {"routes",QJsonArray::fromStringList(routes)},{"rules",QJsonArray::fromStringList(rules)}};
}
