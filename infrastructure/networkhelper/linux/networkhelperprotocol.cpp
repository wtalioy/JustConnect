#include "infrastructure/networkhelper/linux/networkhelperprotocol.h"
#include "infrastructure/dns/dnsdomains.h"
#include "infrastructure/networkaddress/ipv4.h"
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
    return QJsonDocument(packet).toJson(QJsonDocument::Compact).size() <= LinuxHelperRequestBytes;
}
}

QJsonObject linuxHelperRequest(const char *operation, const QUuid &owner, const QUuid &request)
{
    return {{"version", LinuxHelperProtocol}, {"operation", QString::fromLatin1(operation)},
        {"owner", owner.toString(QUuid::WithoutBraces)}, {"request_id", request.toString(QUuid::WithoutBraces)}};
}
QJsonObject linuxHelperApplyRequest(const QUuid &owner, const QUuid &request, const LinuxHelperConfiguration &configuration)
{
    auto packet = linuxHelperRequest("apply", owner, request);
    packet["address"] = configuration.address;
    packet["peer"] = configuration.peer;
    packet["mtu"] = configuration.mtu;
    packet["prefixes"] = QJsonArray::fromStringList(configuration.capturePrefixes);
    packet["dns_domains"] = QJsonArray::fromStringList(configuration.dnsDomains);
    return packet;
}
QJsonObject linuxHelperExtendRequest(const QUuid &owner, const QUuid &request, const QStringList &addresses)
{
    auto packet = linuxHelperRequest("extend", owner, request);
    packet["addresses"] = QJsonArray::fromStringList(addresses);
    return packet;
}
QJsonObject linuxHelperRoutesRequest(const QUuid &owner, const QUuid &request, const QStringList &prefixes)
{
    auto packet = linuxHelperRequest("routes", owner, request);
    packet["prefixes"] = QJsonArray::fromStringList(prefixes);
    return packet;
}
bool validLinuxHelperRequest(const QJsonObject &packet)
{
    if (!bounded(packet) || packet["version"] != LinuxHelperProtocol || !canonicalUuid(packet["owner"])
        || !canonicalUuid(packet["request_id"])) return false;
    const auto operation = packet["operation"].toString();
    if (operation == "apply") return packet.size() == 9 && packet["mtu"].toInteger(-1) > 0
        && packet["mtu"].toDouble(-1) == double(packet["mtu"].toInteger(-1))
        && packet["address"].isString() && packet["peer"].isString()
        && packet["prefixes"].isArray() && packet["dns_domains"].isArray();
    if (operation == "extend") return packet.size() == 5 && packet["addresses"].isArray();
    if (operation == "routes") return packet.size() == 5 && packet["prefixes"].isArray();
    return packet.size() == 4 && (operation == "probe" || operation == "restore" || operation == "cleanup" || operation == "close");
}

std::optional<PlatformOperationResult> parseLinuxHelperResponse(const QJsonObject &packet, const QJsonObject &request)
{
    if (!bounded(packet) || packet["version"] != LinuxHelperProtocol
        || packet["operation"] != request["operation"] || packet["owner"] != request["owner"]
        || packet["request_id"] != request["request_id"] || !packet["status"].isString()) return {};
    const auto status = packet["status"].toString();
    PlatformOperationResult::Status mapped;
    if (status == QLatin1String(LinuxHelperStatusOk)) mapped = PlatformOperationResult::Status::Success;
    else if (status == QLatin1String(LinuxHelperStatusFailed)) mapped = PlatformOperationResult::Status::Failed;
    else if (status == QLatin1String(LinuxHelperStatusPermissionDenied)) mapped = PlatformOperationResult::Status::PermissionDenied;
    else if (status == QLatin1String(LinuxHelperStatusUnsupported)) mapped = PlatformOperationResult::Status::Unsupported;
    else return {};
    // Probe never mutates; every other operation may leave partial changes behind.
    const bool mutating = request["operation"] != "probe";
    // detail is optional (omitted when empty), as are device and dns_mode.
    const bool hasDetail = packet.contains("detail");
    if (hasDetail && !packet["detail"].isString()) return {};
    const int expected = 5 + int(hasDetail) + int(packet.contains("device")) + int(packet.contains("dns_mode"));
    if (packet.size() != expected) return {};
    if (status != QLatin1String(LinuxHelperStatusOk) && (packet.contains("device") || packet.contains("dns_mode"))) return {};
    if (packet.contains("dns_mode")) {
        if (!packet["dns_mode"].isString()) return {};
        const auto mode = packet["dns_mode"].toString();
        if (mode != QLatin1String("resolved") && mode != QLatin1String("file") && !mode.isEmpty()) return {};
    }
    return PlatformOperationResult{mapped, hasDetail ? packet["detail"].toString() : QString(), mutating};
}

QString parseLinuxHelperDnsMode(const QJsonObject &packet)
{
    return packet["dns_mode"].toString();
}

std::optional<LinuxHelperDevice> parseLinuxHelperDevice(const QJsonObject &packet)
{
    const auto device = packet["device"].toObject();
    if (!packet.contains("device") || !packet["device"].isObject() || device.size() != 5) return {};
    const auto name = device["name"].toString(), address = device["address"].toString(),
        peer = device["peer"].toString();
    const auto index = device["index"].toInteger(-1), mtu = device["mtu"].toInteger(-1);
    if (name.isEmpty() || name.size() > 15 || index <= 0 || mtu <= 0 || mtu > 65535
        || device["index"].toDouble(-1) != double(index) || device["mtu"].toDouble(-1) != double(mtu)
        || !canonicalUnicastIpv4(address) || !canonicalUnicastIpv4(peer) || address == peer) return {};
    return LinuxHelperDevice{name, int(index), int(mtu), address, peer};
}
