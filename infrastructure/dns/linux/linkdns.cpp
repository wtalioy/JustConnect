#include "infrastructure/dns/linux/linkdns.h"
#include "infrastructure/dns/linux/resolvedbus.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QDBusArgument>
#include <QDBusMetaType>
#include <QJsonDocument>
#include <ifaddrs.h>
#include <climits>
#include <unistd.h>

namespace LinuxResolved {
struct Endpoint { int family; QByteArray address; quint16 port; QString name; };
QDBusArgument &operator<<(QDBusArgument &out, const Endpoint &value)
{
    out.beginStructure(); out << value.family << value.address << value.port << value.name; out.endStructure(); return out;
}
const QDBusArgument &operator>>(const QDBusArgument &in, Endpoint &value)
{
    in.beginStructure(); in >> value.family >> value.address >> value.port >> value.name; in.endStructure(); return in;
}
}
Q_DECLARE_METATYPE(LinuxResolved::Endpoint)

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result failure(const char *message) { return {Status::Failed, QString::fromLatin1(message), true}; }
QString marker(const QUuid &owner) { return "justconnect-" + QString::fromLatin1(owner.toByteArray(QUuid::Id128)) + ".invalid"; }
bool sourceAssigned(const QString &name, quint32 index, const QString &source)
{
    if (!canonicalLinuxInterfaceName(name) || !index || ::if_nametoindex(name.toLatin1().constData()) != index
        || !canonicalUnicastIpv4(source)) return false;
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    in_addr expected{}; ::inet_pton(AF_INET, source.toLatin1().constData(), &expected);
    for (auto *address = addresses; address; address = address->ifa_next)
        if (address->ifa_addr && address->ifa_addr->sa_family == AF_INET && (address->ifa_flags & IFF_UP)
            && name == QString::fromLocal8Bit(address->ifa_name)
            && reinterpret_cast<sockaddr_in *>(address->ifa_addr)->sin_addr.s_addr == expected.s_addr) return true;
    return false;
}
bool recordFits(QJsonObject value)
{
    // Reserve the longest phase before the first native write.
    value["phase"] = "restoring";
    return QJsonDocument(value).toJson(QJsonDocument::Compact).size() <= LinuxRouteRecoveryBytes;
}
Result plainTransport(const QDBusConnection &bus, const LinuxResolved::LinkSnapshot &state, QDeadlineTimer &deadline)
{
    auto tls = state.security["DNSOverTLS"];
    if (tls == "") {
        const auto reply = LinuxResolved::call(bus, state.provider["owner"].toString(), LinuxResolved::managerPath,
            "org.freedesktop.DBus.Properties", "GetAll", {LinuxResolved::managerInterface}, deadline);
        if (reply.type() != QDBusMessage::ReplyMessage || reply.signature() != "a{sv}") {
            auto result = LinuxResolved::replyResult(reply);
            if (result.succeeded()) result = {Status::Failed, "Invalid native DNS transport properties."};
            result.mayHaveChanged = false; return result;
        }
        tls = QJsonValue::fromVariant(qdbus_cast<QVariantMap>(reply.arguments().first()).value("DNSOverTLS"));
    }
    if (tls != "no") return {Status::Unsupported, "The native DNS transport cannot be replaced by a plain local endpoint."};
    return {};
}
Result flushCaches(const QDBusConnection &bus, QDeadlineTimer &deadline)
{
    const auto reply = LinuxResolved::call(bus,LinuxResolved::service,LinuxResolved::managerPath,
        LinuxResolved::managerInterface,"FlushCaches",{},deadline);
    auto result = LinuxResolved::replyResult(reply);
    if (result.succeeded() && !reply.signature().isEmpty()) return failure("Invalid native DNS cache confirmation.");
    return result;
}
bool servers(const QJsonValue &value)
{
    if (!value.isArray() || value.toArray().isEmpty() || value.toArray().size() > LinuxRouteSnapshotRows) return false;
    for (const auto &item : value.toArray()) {
        const auto row = item.toObject();
        const auto family = row["family"].toInt(); const auto port = row["port"].toInteger();
        if (row.size() != 4 || !row["address"].isString() || !row["name"].isString()
            || (family != AF_INET && family != AF_INET6) || row["family"] != QJsonValue(family)
            || row["port"] != QJsonValue(port) || port < 0 || port > 65535
            || row["name"].toString().size() > 253 || row["name"].toString().contains(QChar::Null)) return false;
        in6_addr bytes{}; char canonical[INET6_ADDRSTRLEN]{};
        if (::inet_pton(family, row["address"].toString().toLatin1().constData(), &bytes) != 1
            || !::inet_ntop(family, &bytes, canonical, sizeof(canonical)) || row["address"] != QString::fromLatin1(canonical)) return false;
    }
    return true;
}
}

QJsonObject linuxLinkDnsEndpoint(const QUuid &owner, const QString &source, quint16 port)
{
    if (owner.isNull() || !canonicalUnicastIpv4(source) || port == 0) return {};
    return {{"family", AF_INET}, {"address", source}, {"port", port}, {"name", marker(owner)}};
}

bool LinuxLinkDns::identity() const
{
    return record["namespace"] == linuxNetworkNamespace() && !record["namespace"].toString().isEmpty()
        && ::if_nametoindex(record["interface"].toString().toLatin1().constData()) == record["index"].toInteger();
}
PlatformOperationResult LinuxLinkDns::save(const CheckpointWriter &checkpoint) const
{
    if (!recordFits(record)) return {Status::Failed, "Original DNS ownership exceeds its storage budget.", record["phase"] != "applying"};
    auto result = checkpoint(record);
    if (!result.succeeded() && record["phase"] != "applying") result.mayHaveChanged = true;
    return result;
}
PlatformOperationResult LinuxLinkDns::clear(const CheckpointWriter &checkpoint, QDeadlineTimer &deadline)
{
    if (record["phase"] != "released") {
        const auto flushed = flushCaches(bus,deadline);
        if (!flushed.succeeded()) return flushed;
    }
    record["phase"] = "released";
    auto result = save(checkpoint); if (!result.succeeded()) return result;
    result = checkpoint({}); if (!result.succeeded()) { result.mayHaveChanged = true; return result; }
    record = {}; return {};
}
PlatformOperationResult LinuxLinkDns::write(const QJsonArray &value, const QJsonObject &provider, QDeadlineTimer &deadline)
{
    qDBusRegisterMetaType<LinuxResolved::Endpoint>(); qDBusRegisterMetaType<QList<LinuxResolved::Endpoint>>();
    QList<LinuxResolved::Endpoint> endpoints;
    for (const auto &item : value) {
        const auto row = item.toObject(); const auto family = row["family"].toInt(); in6_addr bytes{};
        if (::inet_pton(family, row["address"].toString().toLatin1().constData(), &bytes) != 1) return failure("Invalid saved DNS endpoint.");
        endpoints.append({family, QByteArray(reinterpret_cast<const char *>(&bytes), family == AF_INET ? 4 : 16),
            quint16(row["port"].toInteger()), row["name"].toString()});
    }
    return LinuxResolved::replyResult(LinuxResolved::call(bus, provider["owner"].toString(), LinuxResolved::managerPath,
        LinuxResolved::managerInterface, "SetLinkDNSEx", {int(record["index"].toInteger()), QVariant::fromValue(endpoints)}, deadline));
}
PlatformOperationResult LinuxLinkDns::apply(const QUuid &owner, const QString &interface, const QString &source,
    quint16 port, const QJsonObject &expected, const CheckpointWriter &checkpoint)
{
    if (::geteuid() != 0) return {Status::PermissionDenied, "Original DNS replacement requires its privileged owner."};
    const auto index = ::if_nametoindex(interface.toLatin1().constData());
    if (!checkpoint || !record.isEmpty() || owner.isNull() || port == 0 || !sourceAssigned(interface, index, source))
        return {Status::Failed, "An inactive operation, durable checkpoint and assigned original DNS endpoint are required."};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto before = LinuxResolved::readLink(bus, int(index), deadline);
    if (!before.result.succeeded()) { auto result = before.result; result.mayHaveChanged = false; return result; }
    if (before.absent || !before.extended || !servers(before.profile["dns"])) return {Status::Unsupported, "No complete native DNS-server list is available."};
    if (expected.isEmpty() || before.expectation(int(index)) != expected)
        return {Status::Failed, "Original DNS no longer matches the prepared source."};
    auto transport = plainTransport(bus, before, deadline);
    if (!transport.succeeded()) return transport;
    // With DNSOverTLS disabled, the unused TLS name carries our crash-recovery tag.
    const QJsonArray after{linuxLinkDnsEndpoint(owner, source, port)};
    static const QRegularExpression ownedName("^justconnect-[0-9a-f]{32}[.]invalid$");
    for (const auto &value : before.profile["dns"].toArray())
        if (ownedName.match(value.toObject()["name"].toString()).hasMatch())
            return {Status::Failed, "Original DNS already contains a connection-owned endpoint."};
    record = {{"version", 1}, {"owner", owner.toString(QUuid::WithoutBraces)}, {"interface", interface}, {"index", qint64(index)},
        {"source", source}, {"namespace", linuxNetworkNamespace()}, {"provider", before.provider},
        {"before", before.profile["dns"]}, {"after", after}, {"phase", "applying"}};
    auto result = save(checkpoint);
    if (!result.succeeded()) {
        if (!result.mayHaveChanged) record = {};
        return result;
    }
    const auto current = LinuxResolved::readLink(bus, int(index), deadline);
    if (!identity() || !sourceAssigned(interface, index, source) || !current.result.succeeded()
        || current.expectation(int(index)) != expected) {
        if (!current.result.succeeded()) return current.result;
        const auto cleaned = clear(checkpoint, deadline);
        return {Status::Failed, "Original DNS changed before replacement.", !cleaned.succeeded()};
    }
    transport = plainTransport(bus, current, deadline);
    if (!transport.succeeded()) {
        transport.mayHaveChanged = !clear(checkpoint, deadline).succeeded();
        return transport;
    }
    result = write(after, current.provider, deadline);
    const auto actual = LinuxResolved::readLink(bus, int(index), deadline);
    if (result.succeeded() && sourceAssigned(interface, index, source) && actual.result.succeeded() && !actual.absent
        && actual.extended && actual.provider == current.provider && actual.profile["dns"] == after
        && actual.profile["domains"] == before.profile["domains"]
        && actual.profile["default_route"] == before.profile["default_route"] && actual.security == before.security
        && plainTransport(bus, actual, deadline).succeeded()) {
        result = flushCaches(bus,deadline);
        if (result.succeeded()) { record["phase"] = "active"; return save(checkpoint); }
    }
    if (result.succeeded()) result = actual.result.succeeded() ? failure("Cannot confirm the original DNS replacement.") : actual.result;
    QDeadlineTimer rollback(LinuxRouteOperationTimeoutMs);
    result.mayHaveChanged = !restore(rollback, checkpoint).succeeded(); return result;
}
PlatformOperationResult LinuxLinkDns::restore(const CheckpointWriter &checkpoint)
{
    if (record.isEmpty()) return {};
    if (!checkpoint) return failure("Original DNS recovery requires its durable checkpoint.");
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs); return restore(deadline, checkpoint);
}
PlatformOperationResult LinuxLinkDns::restore(QDeadlineTimer &deadline, const CheckpointWriter &checkpoint)
{
    if (::geteuid() != 0) return {Status::PermissionDenied, "Original DNS recovery requires its privileged owner."};
    if (record["phase"] == "released") return clear(checkpoint, deadline);
    if (!identity()) {
        char name[IFNAMSIZ]{};
        if (record["namespace"] == linuxNetworkNamespace()
            && ::if_nametoindex(record["interface"].toString().toLatin1().constData()) == 0
            && !::if_indextoname(quint32(record["index"].toInteger()), name)) {
            const auto gone = LinuxResolved::readLink(bus, int(record["index"].toInteger()), deadline);
            if (gone.result.succeeded() && gone.absent && gone.provider["bus"] == record["provider"].toObject()["bus"]) return clear(checkpoint, deadline);
        }
        return failure("Original DNS interface identity changed.");
    }
    const auto current = LinuxResolved::readLink(bus, int(record["index"].toInteger()), deadline);
    if (!current.result.succeeded()) return current.result;
    if (current.absent || current.provider["bus"] != record["provider"].toObject()["bus"])
        return failure("Original DNS provider identity changed.");
    if (!current.extended) return failure("Cannot completely inspect original DNS endpoint ownership.");
    const auto owned = record["after"].toArray().first();
    auto remaining = current.profile["dns"].toArray();
    if (!remaining.contains(owned)) return clear(checkpoint, deadline);
    // The unique DNSEx name marks our plain endpoint even across an interrupted native write.
    if (remaining == record["after"].toArray()) remaining = record["before"].toArray();
    else for (qsizetype i = remaining.size(); i-- > 0;) if (remaining[i] == owned) remaining.removeAt(i);
    record["phase"] = "restoring";
    auto result = save(checkpoint); if (!result.succeeded()) return result;
    const auto confirmed = LinuxResolved::readLink(bus, int(record["index"].toInteger()), deadline);
    if (!confirmed.result.succeeded()) return confirmed.result;
    if (!identity() || confirmed.absent || confirmed.provider != current.provider || confirmed.profile["dns"] != current.profile["dns"])
        return failure("Original DNS changed before restoration.");
    result = write(remaining, confirmed.provider, deadline); if (!result.succeeded()) return result;
    const auto restored = LinuxResolved::readLink(bus, int(record["index"].toInteger()), deadline);
    if (!restored.result.succeeded()) return restored.result;
    if (restored.absent || !restored.extended || restored.provider != confirmed.provider || restored.profile["dns"] != remaining)
        return failure("Cannot confirm the original DNS restoration.");
    return clear(checkpoint, deadline);
}
PlatformOperationResult LinuxLinkDns::validateRecovery(const QUuid &owner, const QJsonObject &saved)
{
    const auto after = saved["after"].toArray(); const auto endpoint = after.isEmpty() ? QJsonObject{} : after.first().toObject();
    if (owner.isNull() || saved.size() != 10 || saved["version"] != 1
        || saved["owner"] != owner.toString(QUuid::WithoutBraces) || saved["index"].toInteger() < 1 || saved["index"].toInteger() > INT_MAX || saved["index"] != QJsonValue(saved["index"].toInteger())
        || !canonicalLinuxInterfaceName(saved["interface"].toString()) || !canonicalUnicastIpv4(saved["source"].toString())
        || saved["namespace"].toString().isEmpty() || saved["namespace"] != linuxNetworkNamespace() || !LinuxResolved::providerIdentity(saved["provider"].toObject())
        || !servers(saved["before"]) || !servers(saved["after"]) || after.size() != 1
        || endpoint != linuxLinkDnsEndpoint(owner, saved["source"].toString(), quint16(endpoint["port"].toInteger()))
        || !QStringList{"applying", "active", "restoring", "released"}.contains(saved["phase"].toString())
        || !recordFits(saved))
        return {Status::Failed, "Invalid original DNS ownership record."};
    return {};
}
PlatformOperationResult LinuxLinkDns::recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint)
{
    if (::geteuid() != 0) return {Status::PermissionDenied, "Original DNS recovery requires its privileged owner."};
    if (!checkpoint || !record.isEmpty()) return {Status::Failed,"Original DNS recovery requires an inactive owner and durable checkpoint."};
    const auto valid = validateRecovery(owner,saved);
    if (!valid.succeeded()) return valid;
    record = saved; return restore(checkpoint);
}
