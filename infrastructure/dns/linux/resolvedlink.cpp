#include "infrastructure/dns/linux/resolvedlink.h"
#include "infrastructure/dns/linux/resolvedbus.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include <QDBusArgument>
#include <QDBusError>
#include <QDBusObjectPath>
#include <QDBusMetaType>
#include <climits>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <unistd.h>

namespace LinuxResolved {
namespace {
using Status = PlatformOperationResult::Status;
using Result = PlatformOperationResult;
Result failure(const char *message) { return {Status::Failed, QString::fromLatin1(message), true}; }
bool fields(const QJsonObject &value, std::initializer_list<const char *> keys)
{
    if (value.size() != qsizetype(keys.size())) return false;
    for (const auto *key : keys) if (!value.contains(QLatin1String(key))) return false;
    return true;
}
bool sameProviderNamespace(quint32 pid)
{
    // A held socket inode is unique; the provider's kernel table lists it only in the same netns.
    const int descriptor = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (descriptor < 0) return false;
    const auto close = qScopeGuard([&] { ::close(descriptor); });
    sockaddr_nl address{};
    address.nl_family = AF_NETLINK;
    struct stat identity{};
    if (::bind(descriptor, reinterpret_cast<const sockaddr *>(&address), sizeof(address)) != 0
        || ::fstat(descriptor, &identity) != 0 || !identity.st_ino) return false;
    QFile table(QString("/proc/%1/net/netlink").arg(pid));
    if (!table.open(QIODevice::ReadOnly)) return false;
    const auto data = table.read(LinuxRouteSnapshotBytes + 1);
    if (table.error() != QFileDevice::NoError || data.size() > LinuxRouteSnapshotBytes || !data.endsWith('\n')) return false;
    const auto inode = QByteArray::number(identity.st_ino);
    for (const auto &line : data.split('\n')) {
        const auto columns = line.simplified().split(' ');
        if (columns.size() == 10 && columns[1] == QByteArray::number(NETLINK_ROUTE) && columns[9] == inode) return true;
    }
    return false;
}
}
std::optional<QJsonObject> linkInputs(const QJsonObject &resolved, const QJsonValue &index, const QString &interface)
{
    if (resolved["status"] != "available" || !resolved["DNS"].isArray()
        || !resolved["Domains"].isArray() || !resolved["Links"].isArray()) return {};
    QJsonObject native;
    for (const auto &value : resolved["Links"].toArray()) {
        const auto row = value.toObject();
        if (row["interface_index"] != index) continue;
        if (!native.isEmpty() || row["name"] != interface || !row["DefaultRoute"].isBool()) return {};
        native = row;
    }
    if (native.isEmpty()) return {};
    QJsonObject security;
    for (const auto *key : {"DNSOverTLS", "DNSSEC"}) {
        if (!native.contains(key)) continue;
        if (!native[key].isString()) return {};
        security[key] = native[key];
    }
    QJsonArray servers, domains;
    for (const auto &value : resolved["DNS"].toArray()) {
        const auto row = value.toObject();
        if (row["interface_index"] != index) continue;
        if (row.size() != 5) return {};
        servers.append(QJsonObject{{"family", row["family"]}, {"address", row["address"]},
            {"port", row["port"]}, {"name", row["server_name"]}});
    }
    for (const auto &value : resolved["Domains"].toArray()) {
        const auto row = value.toObject();
        if (row["interface_index"] != index) continue;
        if (row.size() != 3) return {};
        domains.append(QJsonObject{{"name", row["domain"]}, {"route_only", row["route_only"]}});
    }
    return QJsonObject{{"profile", QJsonObject{{"dns", servers}, {"domains", domains}, {"default_route", native["DefaultRoute"]}}},
        {"security", security}};
}

bool providerIdentity(const QJsonObject &value)
{
    static const QRegularExpression id("^[0-9a-f]{32}$"), owner("^:[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+$");
    return fields(value, {"bus", "owner"}) && id.match(value["bus"].toString()).hasMatch()
        && owner.match(value["owner"].toString()).hasMatch();
}
QJsonObject LinkSnapshot::expectation(int index) const
{
    if (!result.succeeded() || absent || !extended || index <= 0) return {};
    return {{"index", index}, {"profile", profile}, {"security", security}, {"provider", provider}};
}
QDBusMessage call(const QDBusConnection &bus, const QString &destination, const QString &path,
                  const QString &interface, const QString &method, const QVariantList &args, QDeadlineTimer &deadline)
{
    if (deadline.hasExpired()) return QDBusMessage::createError(QDBusError::Timeout, "DNS operation timed out");
    auto message = QDBusMessage::createMethodCall(destination, path, interface, method);
    message.setAutoStartService(false); message.setArguments(args);
    return bus.call(message, QDBus::Block, int(qMin<qint64>(1000, deadline.remainingTime())));
}
Result replyResult(const QDBusMessage &reply)
{
    if (reply.type() == QDBusMessage::ReplyMessage) return {};
    const QDBusError error(reply);
    const auto status = error.type() == QDBusError::AccessDenied ? Status::PermissionDenied
        : error.type() == QDBusError::Timeout || error.type() == QDBusError::NoReply ? Status::TimedOut
        : error.type() == QDBusError::ServiceUnknown || error.name() == "org.freedesktop.DBus.Error.NameHasNoOwner" ? Status::Unsupported : Status::Failed;
    return {status, "Cannot read or update the resolver settings.", true};
}
LinkSnapshot readLink(const QDBusConnection &bus, int index, QDeadlineTimer &deadline)
{
    LinkSnapshot state;
    const auto id = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetId", {}, deadline);
    const auto owner = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "GetNameOwner", {service}, deadline);
    if (id.type() != QDBusMessage::ReplyMessage || owner.type() != QDBusMessage::ReplyMessage
        || id.signature() != "s" || owner.signature() != "s") {
        state.result = replyResult(owner.type() == QDBusMessage::ErrorMessage ? owner : id);
        if (state.result.succeeded()) state.result = failure("Invalid resolver provider identity.");
        return state;
    }
    state.provider = {{"bus", id.arguments().first().toString()}, {"owner", owner.arguments().first().toString()}};
    if (!providerIdentity(state.provider)) { state.result = failure("Invalid resolver provider identity."); return state; }
    const auto destination = state.provider["owner"].toString();
    const auto process = call(bus, "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
                              "GetConnectionUnixProcessID", {destination}, deadline);
    const auto pid = process.arguments().isEmpty() ? 0 : process.arguments().first().toUInt();
    if (process.type() != QDBusMessage::ReplyMessage || process.signature() != "u" || pid == 0 || pid > INT_MAX
        || !sameProviderNamespace(pid)) {
        state.result = {Status::Unsupported, "The resolver provider does not share the owned TUN network namespace."};
        return state;
    }
    const auto link = call(bus, destination, managerPath, managerInterface, "GetLink", {index}, deadline);
    if (link.type() == QDBusMessage::ErrorMessage && link.errorName() == service + ".NoSuchLink") {
        state.absent = true; return state;
    }
    if (link.type() != QDBusMessage::ReplyMessage || link.signature() != "o") {
        state.result = replyResult(link); if (state.result.succeeded()) state.result = failure("Invalid resolver link reply."); return state;
    }
    const auto path = qvariant_cast<QDBusObjectPath>(link.arguments().first()).path();
    const auto properties = call(bus, destination, path, "org.freedesktop.DBus.Properties", "GetAll", {LinuxResolved::linkInterface}, deadline);
    if (properties.type() != QDBusMessage::ReplyMessage || properties.signature() != "a{sv}") {
        state.result = replyResult(properties); if (state.result.succeeded()) state.result = failure("Invalid resolver properties reply."); return state;
    }
    const auto values = qdbus_cast<QVariantMap>(properties.arguments().first());
    const bool extended = values.contains("DNSEx");
    state.extended = extended;
    const auto dns = qvariant_cast<QDBusArgument>(values.value(extended ? "DNSEx" : "DNS"));
    const auto names = qvariant_cast<QDBusArgument>(values.value("Domains"));
    if (dns.currentSignature() != (extended ? "a(iayqs)" : "a(iay)") || names.currentSignature() != "a(sb)"
        || values.value("DefaultRoute").metaType() != QMetaType::fromType<bool>()) {
        state.result = failure("Incomplete resolver link properties."); return state;
    }
    QJsonArray servers, domains;
    dns.beginArray();
    while (!dns.atEnd()) {
        int family = 0; QByteArray bytes; quint16 port = 0; QString name;
        dns.beginStructure(); dns >> family >> bytes; if (extended) dns >> port >> name; dns.endStructure();
        char address[INET6_ADDRSTRLEN]{};
        if (servers.size() >= LinuxRouteSnapshotRows || (family != AF_INET && family != AF_INET6)
            || bytes.size() != (family == AF_INET ? 4 : 16) || name.size() > 253 || name.contains(QChar::Null)
            || !::inet_ntop(family, bytes.constData(), address, sizeof(address))) {
            state.result = failure("Invalid resolver DNS server."); return state;
        }
        servers.append(QJsonObject{{"family", family}, {"address", QString::fromLatin1(address)}, {"port", port}, {"name", name}});
    }
    dns.endArray(); names.beginArray();
    while (!names.atEnd()) {
        QString name; bool routeOnly = false;
        names.beginStructure(); names >> name >> routeOnly; names.endStructure();
        if (domains.size() >= LinuxRouteSnapshotRows || name.isEmpty() || name.size() > 253 || name.contains(QChar::Null)) {
            state.result = failure("Invalid resolver routing domain."); return state;
        }
        domains.append(QJsonObject{{"name", name}, {"route_only", routeOnly}});
    }
    names.endArray();
    for (const auto *key : {"DNSOverTLS", "DNSSEC"}) {
        if (!values.contains(key)) continue;
        if (values[key].metaType() != QMetaType::fromType<QString>()) {
            state.result = failure("Invalid resolver security property."); return state;
        }
        state.security[key] = values[key].toString();
    }
    state.profile = {{"dns", servers}, {"domains", domains}, {"default_route", values["DefaultRoute"].toBool()}};
    return state;
}

}
