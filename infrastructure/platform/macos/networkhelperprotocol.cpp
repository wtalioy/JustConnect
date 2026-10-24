#include "networkhelper.h"
#include "infrastructure/platform/ipv4.h"
#include "infrastructure/platform/dnsdomains.h"
#include "infrastructure/platform/tundevice.h"
#include "tunroutes.h"
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
        {"dns_domains",QJsonArray::fromStringList(configuration.dnsDomains)}};
    return packet;
}
bool validMacHelperRequest(const QJsonObject &packet)
{
    if (!bounded(packet) || packet["schema_version"] != MacHelperProtocol || !canonicalUuid(packet["owner"])
        || !canonicalUuid(packet["request_id"])) return false;
    const auto operation = packet["operation"].toString();
    if (operation == "apply") return packet.size() == 5 && packet["configuration"].isObject();
    return packet.size() == 4 && (operation == "probe" || operation == "restore" || operation == "recover" || operation == "cleanup");
}
std::optional<MacHelperConfiguration> parseMacHelperApply(const QJsonObject &packet)
{
    if (!validMacHelperRequest(packet) || packet["operation"] != "apply") return {};
    const auto configuration = packet["configuration"].toObject();
    const auto mtu = configuration["mtu"].toInteger(-1);
    if (configuration.size() != 5 || configuration["mtu"].toDouble(-1) != double(mtu)
        || !UnixTunDevice::validIpv4Configuration(configuration["address"].toString(),configuration["peer"].toString(),mtu)
        || !configuration["prefixes"].isArray() || configuration["prefixes"].toArray().isEmpty()
        || configuration["prefixes"].toArray().size() > MacRouteSnapshotRows || !configuration["dns_domains"].isArray()) return {};
    MacHelperConfiguration result{configuration["address"].toString(),configuration["peer"].toString(),int(mtu),{}};
    for (const auto &value : configuration["dns_domains"].toArray()) result.dnsDomains.append(value.toString());
    if (!result.dnsDomains.isEmpty() && !validTunDnsDomains(result.dnsDomains)) return {};
    QSet<QString> unique;
    for (const auto &value : configuration["prefixes"].toArray()) {
        const auto prefix = value.toString();
        if (!canonicalIpv4Prefix(prefix) || unique.contains(prefix) || ipv4PrefixContainsAddress(prefix,result.address)
            || ipv4PrefixContainsAddress(prefix,result.peer)) return {};
        // Local and non-unicast destinations cannot be reassigned to a campus device.
        const auto parts = prefix.split('/');
        in_addr address{}; ::inet_pton(AF_INET,parts[0].toLatin1().constData(),&address);
        const quint64 first = ntohl(address.s_addr), last = first+(quint64(1)<<(32-parts[1].toInt()))-1;
        if (first < 0x01000000ULL || last >= 0xe0000000ULL || (first <= 0x7fffffffULL && last >= 0x7f000000ULL)) return {};
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
    const bool owners = packet.contains("owners");
    if (!bounded(packet) || packet["schema_version"] != MacHelperProtocol || packet["request_id"] != request["request_id"]
        || packet["owner"] != request["owner"] || packet["operation"] != request["operation"]
        || !packet["detail"].isString() || !packet["changed"].isBool() || status < 0 || status > int(PlatformOperationResult::Status::TimedOut)
        || packet["status"].toDouble(-1) != double(status)
        || packet.size() != 7+int(packet.contains("device"))+int(owners)
        || (packet.contains("device") && (request["operation"] != "apply" || status != 0 || !packet["device"].isObject()))) return {};
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
