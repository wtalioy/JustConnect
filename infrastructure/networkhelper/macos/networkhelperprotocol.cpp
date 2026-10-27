#include "infrastructure/networkhelper/macos/networkhelper.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/networkaddress/ipv4.h"
#include "infrastructure/dns/dnsdomains.h"
#include "infrastructure/tundevice/tundevice.h"
#include "infrastructure/routing/macos/tunroutes.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QSet>

namespace {
bool canonicalUuid(const QJsonValue &value)
{
    const QUuid id(value.toString());
    return !id.isNull() && id.toString(QUuid::WithoutBraces) == value;
}
bool bounded(const QJsonObject &packet)
{
    return QJsonDocument(packet).toJson(QJsonDocument::Compact).size() <= MacHelperPacketBytes;
}
}

QJsonObject macHelperRequest(const char *operation, const QUuid &owner, const QUuid &request)
{
    return {{"schema_version",MacHelperProtocol},{"operation",QString::fromLatin1(operation)},
        {"owner",owner.toString(QUuid::WithoutBraces)},{"request_id",request.toString(QUuid::WithoutBraces)}};
}
QJsonObject macHelperApplyRequest(const QUuid &owner, const QUuid &request, const MacHelperConfiguration &configuration)
{
    auto packet = macHelperRequest("apply",owner,request);
    packet["configuration"] = QJsonObject{{"address",configuration.address},{"peer",configuration.peer},
        {"mtu",configuration.mtu},{"prefixes",QJsonArray::fromStringList(configuration.capturePrefixes)},
        {"dns_domains",QJsonArray::fromStringList(configuration.dnsDomains)},{"original_dns",configuration.originalDns}};
    return packet;
}
bool validMacHelperRequest(const QJsonObject &packet)
{
    if (QJsonDocument(packet).toJson(QJsonDocument::Compact).size() > MacHelperRequestBytes || packet["schema_version"] != MacHelperProtocol || !canonicalUuid(packet["owner"])
        || !canonicalUuid(packet["request_id"])) return false;
    const auto operation = packet["operation"].toString();
    if (operation == "extend") return packet.size() == 5 && packet["addresses"].isArray();
    if (operation == "routes") return packet.size() == 5 && packet["prefixes"].isArray();
    if (operation == "apply") return packet.size() == 5 && packet["configuration"].isObject();
    return packet.size() == 4 && (operation == "probe" || operation == "restore" || operation == "recover" || operation == "cleanup");
}
QJsonObject macHelperExtendRequest(const QUuid &owner, const QUuid &request, const QStringList &addresses)
{
    auto packet = macHelperRequest("extend",owner,request);
    packet["addresses"] = QJsonArray::fromStringList(addresses); return packet;
}
std::optional<QStringList> parseMacHelperExtend(const QJsonObject &packet)
{
    if (!validMacHelperRequest(packet) || packet["operation"] != "extend" || packet["addresses"].toArray().isEmpty()
        || packet["addresses"].toArray().size() > MacRouteSnapshotRows) return {};
    QStringList addresses;
    for (const auto &value : packet["addresses"].toArray()) {
        if (!value.isString() || !canonicalUnicastIpv4(value.toString())) return {};
        if (!addresses.contains(value.toString())) addresses.append(value.toString());
    }
    return addresses;
}
QJsonObject macHelperRoutesRequest(const QUuid &owner, const QUuid &request, const QStringList &prefixes)
{
    auto packet = macHelperRequest("routes",owner,request);
    packet["prefixes"] = QJsonArray::fromStringList(prefixes); return packet;
}
std::optional<QStringList> parseMacHelperRoutes(const QJsonObject &packet)
{
    if (!validMacHelperRequest(packet) || packet["operation"] != "routes"
        || packet["prefixes"].toArray().size() > MacRouteSnapshotRows) return {};
    QStringList prefixes;
    for (const auto &value : packet["prefixes"].toArray()) {
        if (!value.isString() || !canonicalUnicastIpv4Prefix(value.toString()) || prefixes.contains(value.toString())) return {};
        prefixes.append(value.toString());
    }
    return prefixes;
}
std::optional<MacHelperConfiguration> parseMacHelperApply(const QJsonObject &packet)
{
    if (!validMacHelperRequest(packet) || packet["operation"] != "apply") return {};
    const auto configuration = packet["configuration"].toObject();
    const auto mtu = configuration["mtu"].toInteger(-1);
    if (configuration.size() != 6 || configuration["mtu"].toDouble(-1) != double(mtu)
        || !UnixTunDevice::validIpv4Configuration(configuration["address"].toString(),configuration["peer"].toString(),mtu)
        || !configuration["prefixes"].isArray() || configuration["prefixes"].toArray().isEmpty()
        || configuration["prefixes"].toArray().size() > MacRouteSnapshotRows || !configuration["dns_domains"].isArray()
        || !configuration["original_dns"].isArray() || configuration["original_dns"].toArray().size()>MacRouteSnapshotRows) return {};
    MacHelperConfiguration result{configuration["address"].toString(),configuration["peer"].toString(),int(mtu),{}};
    for (const auto &value : configuration["dns_domains"].toArray()) result.dnsDomains.append(value.toString());
    if (!result.dnsDomains.isEmpty() && !validTunDnsDomains(result.dnsDomains)) return {};
    QSet<QString> services;
    for(const auto &value:configuration["original_dns"].toArray()){
        const auto source=value.toObject();const auto service=source["service"].toString();
        const auto bytes=source["original"].toString().toLatin1();
        const auto decoded=QByteArray::fromBase64Encoding(bytes,QByteArray::AbortOnBase64DecodingErrors);
        const auto listener=source["listen"].toString();const auto separator=listener.lastIndexOf(':');
        const auto number=listener.mid(separator+1);bool portValid=false;const auto port=number.toUInt(&portValid);
        const QUuid serviceId(service);
        const auto identity=serviceId.toString(QUuid::WithoutBraces);
        if(source.size()!=4 || !validMacOriginalDnsContext(source["context"].toObject()) || serviceId.isNull() || identity.compare(service,Qt::CaseInsensitive)!=0 || services.contains(identity)
            || (!source["original"].isNull() && (!source["original"].isString() || !decoded || decoded.decoded.isEmpty() || decoded.decoded.toBase64()!=bytes))
            || separator<1 || !canonicalUnicastIpv4(listener.first(separator)) || !portValid || !port || port>65535 || QString::number(port)!=number)return {};
        services.insert(identity);result.originalDns.append(source);
    }
    QSet<QString> unique;
    for (const auto &value : configuration["prefixes"].toArray()) {
        const auto prefix = value.toString();
        if (!canonicalUnicastIpv4Prefix(prefix) || unique.contains(prefix) || ipv4PrefixContainsAddress(prefix,result.address)
            || ipv4PrefixContainsAddress(prefix,result.peer)) return {};
        unique.insert(prefix); result.capturePrefixes.append(prefix);
    }
    return result;
}
QJsonObject macHelperResponse(const QJsonObject &request, const PlatformOperationResult &result, const QJsonObject &device)
{
    QJsonObject packet{{"schema_version",MacHelperProtocol},{"operation",request["operation"]},
        {"owner",request["owner"]},{"request_id",request["request_id"]}};
    packet["status"] = int(result.status); packet["detail"] = result.detail; packet["changed"] = result.mayHaveChanged;
    if (!device.isEmpty()) packet["device"] = device;
    return packet;
}
std::optional<PlatformOperationResult> parseMacHelperResponse(const QJsonObject &packet, const QJsonObject &request)
{
    const auto status = packet["status"].toInteger(-1);
    const bool owners = packet.contains("owners"), network = packet.contains("network");
    const bool needsNetwork = status == 0 && (request["operation"] == "apply" || request["operation"] == "extend" || request["operation"] == "routes");
    if (!bounded(packet) || packet["schema_version"] != MacHelperProtocol || packet["request_id"] != request["request_id"]
        || packet["owner"] != request["owner"] || packet["operation"] != request["operation"]
        || !packet["detail"].isString() || !packet["changed"].isBool() || status < 0 || status > int(PlatformOperationResult::Status::TimedOut)
        || packet["status"].toDouble(-1) != double(status)
        || packet.size() != 7+int(packet.contains("device"))+int(owners)+int(network)
        || (packet.contains("device") && (request["operation"] != "apply" || status != 0 || !packet["device"].isObject()))) return {};
    if (network != needsNetwork || (network && (!packet["network"].isObject() || packet["network"].toObject().size() != 4
        || !packet["network"].toObject()["capture"].isObject() || !packet["network"].toObject()["dns"].isObject()
        || !packet["network"].toObject()["device_routes"].isArray() || !packet["network"].toObject()["original_dns"].isObject()))) return {};
    if (owners) {
        if (request["operation"] != "probe" || status != 0 || !packet["owners"].isArray() || packet["owners"].toArray().size() > MacRouteSnapshotRows) return {};
        QSet<QString> seen;
        for (const auto &value : packet["owners"].toArray()) {
            const auto item = value.toObject(); const auto phase = item["phase"].toString();
            if (item.size() != 2 || !canonicalUuid(item["owner"]) || seen.contains(item["owner"].toString())
                || (phase != "preparing" && phase != "active" && phase != "restored" && phase != "unknown")) return {};
            seen.insert(item["owner"].toString());
        }
    }
    if (request["operation"] == "probe" && status == 0 && !owners) return {};
    return PlatformOperationResult{PlatformOperationResult::Status(status),packet["detail"].toString(),packet["changed"].toBool()};
}
