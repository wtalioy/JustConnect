#include "tundns.h"
#include "iprouteutility.h"
#include "resolvedbus.h"
#include <QDBusArgument>
#include <QDBusError>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QDBusObjectPath>
#include <QJsonDocument>
#include <QRegularExpression>
#include <QSet>
#include <QThread>
#include <climits>
#include <unistd.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
using LinuxResolved::service;
using LinuxResolved::managerPath;
using LinuxResolved::managerInterface;
using Servers = QList<QPair<int, QByteArray>>;
using Domains = QList<QPair<QString, bool>>;
Result failure(const char *message) { return {Status::Failed, QString::fromLatin1(message), true}; }
bool fields(const QJsonObject &value, std::initializer_list<const char *> keys)
{
    if (value.size() != qsizetype(keys.size())) return false;
    for (const auto *key : keys) if (!value.contains(QLatin1String(key))) return false;
    return true;
}
bool domain(const QString &name)
{
    if (name.isEmpty() || name.size() > 253 || name.toLower() != name) return false;
    for (const auto &label : name.split('.')) {
        if (label.isEmpty() || label.size() > 63 || label.front() == '-' || label.back() == '-') return false;
        for (const auto c : label) if (!(c >= 'a' && c <= 'z') && !(c >= '0' && c <= '9') && c != '-') return false;
    }
    return true;
}
bool routingDomains(const QJsonValue &value)
{
    if (!value.isArray() || value.toArray().size() > LinuxRouteSnapshotRows) return false;
    QSet<QString> seen;
    for (const auto &item : value.toArray()) {
        const auto row = item.toObject(); const auto name = row["name"].toString();
        if (!item.isObject() || !fields(row, {"name", "route_only"}) || !domain(name)
            || row["route_only"] != true || seen.contains(name)) return false;
        seen.insert(name);
    }
    return true;
}
QJsonArray peerServer(const QString &peer)
{
    return {QJsonObject{{"family", AF_INET}, {"address", peer}, {"port", 53}, {"name", ""}}};
}
bool profile(const QJsonObject &value, const QString &peer)
{
    return fields(value, {"dns", "domains", "default_route"}) && value["default_route"].isBool()
        && value["dns"].isArray() && (value["dns"].toArray().isEmpty() || value["dns"].toArray() == peerServer(peer))
        && routingDomains(value["domains"]);
}
bool providerIdentity(const QJsonObject &value)
{
    static const QRegularExpression id("^[0-9a-f]{32}$"), owner("^:[A-Za-z0-9_-]+(\\.[A-Za-z0-9_-]+)+$");
    return fields(value, {"bus", "owner"}) && id.match(value["bus"].toString()).hasMatch()
        && owner.match(value["owner"].toString()).hasMatch();
}
bool stage(const QJsonObject &value, const QJsonObject &before, const QString &peer)
{
    return profile(value, peer) && (value == before || (value["default_route"] == false
        && (value["dns"].toArray().isEmpty() || !value["domains"].toArray().isEmpty())));
}
bool transition(const QJsonObject &applied, const QJsonObject &pending, const QJsonObject &before, bool restoring)
{
    QStringList changed;
    for (const auto &key : applied.keys()) if (applied[key] != pending[key]) changed.append(key);
    if (changed.size() != 1) return false;
    const auto key = changed.first();
    if (restoring) return pending[key] == before[key];
    return applied[key] == before[key] && (key == "default_route" ? pending[key] == false : !pending[key].toArray().isEmpty());
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
    return {status, "Cannot read or update the owned TUN resolver settings.", true};
}
}

LinuxTunDns::State LinuxTunDns::read(QDeadlineTimer &deadline) const
{
    State state;
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
    const auto link = call(bus, destination, managerPath, managerInterface, "GetLink", {int(record["index"].toInteger())}, deadline);
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
        servers.append(QJsonObject{{"family", family}, {"address", QString::fromLatin1(address)}, {"port", port ? port : 53}, {"name", name}});
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
    state.profile = {{"dns", servers}, {"domains", domains}, {"default_route", values["DefaultRoute"].toBool()}};
    return state;
}

bool LinuxTunDns::identity() const
{
    return !record.isEmpty() && !record["namespace"].toString().isEmpty() && record["namespace"] == linuxNetworkNamespace()
        && assignedLinuxTunPair(record["interface"].toString(), quint32(record["index"].toInteger()),
                                record["source"].toString(), record["peer"].toString());
}
PlatformOperationResult LinuxTunDns::save(const CheckpointWriter &checkpoint) const
{
    if (QJsonDocument(record).toJson(QJsonDocument::Compact).size() > LinuxRouteRecoveryBytes) return failure("TUN DNS ownership exceeds its storage budget.");
    return checkpoint ? checkpoint(record) : Result{};
}
PlatformOperationResult LinuxTunDns::clear(const CheckpointWriter &checkpoint)
{
    record["released"] = true;
    record["pending"] = QJsonObject{};
    const auto released = save(checkpoint); if (!released.succeeded()) return released;
    if (checkpoint) { const auto result = checkpoint({}); if (!result.succeeded()) return result; }
    record = {}; recovered = attempted = false; return {};
}

PlatformOperationResult LinuxTunDns::change(const QJsonObject &next, bool restoring, QDeadlineTimer &deadline, const CheckpointWriter &checkpoint)
{
    const auto applied = record["applied"].toObject();
    QStringList changed;
    for (const auto &key : applied.keys()) if (next[key] != applied[key]) changed.append(key);
    if (changed.size() != 1) return failure("A DNS checkpoint must change exactly one owned property.");
    record["pending"] = next; record["restoring"] = restoring; attempted = false;
    auto result = save(checkpoint); if (!result.succeeded()) return result;
    if (!identity()) return failure("TUN DNS interface ownership changed.");
    const auto current = read(deadline);
    if (!current.result.succeeded()) return current.result;
    if (current.absent || current.provider != record["provider"].toObject() || current.profile != applied)
        return failure("Resolver settings changed before the owned DNS update.");
    const auto key = changed.first();
    QVariantList arguments{int(record["index"].toInteger())}; QString method;
    if (key == "default_route") { method = "SetLinkDefaultRoute"; arguments.append(next[key].toBool()); }
    else if (key == "dns") {
        qDBusRegisterMetaType<Servers::value_type>(); qDBusRegisterMetaType<Servers>(); Servers servers;
        for (const auto &item : next[key].toArray()) {
            in_addr address{}; ::inet_pton(AF_INET, item.toObject()["address"].toString().toLatin1().constData(), &address);
            servers.append({AF_INET, QByteArray(reinterpret_cast<const char *>(&address), sizeof(address))});
        }
        method = "SetLinkDNS"; arguments.append(QVariant::fromValue(servers));
    } else {
        qDBusRegisterMetaType<Domains::value_type>(); qDBusRegisterMetaType<Domains>(); Domains domains;
        for (const auto &item : next[key].toArray()) domains.append({item.toObject()["name"].toString(), true});
        method = "SetLinkDomains"; arguments.append(QVariant::fromValue(domains));
    }
    attempted = true;
    const auto reply = call(bus, record["provider"].toObject()["owner"].toString(), managerPath, managerInterface, method, arguments, deadline);
    result = replyResult(reply); if (!result.succeeded()) return result;
    const auto actual = read(deadline);
    if (!actual.result.succeeded()) return actual.result;
    if (actual.absent || actual.provider != current.provider || actual.profile != next) return failure("Cannot confirm the complete TUN DNS update.");
    record["applied"] = next; record["pending"] = QJsonObject{}; attempted = false;
    return save(checkpoint);
}

PlatformOperationResult LinuxTunDns::apply(const UnixTunDevice &device, const QStringList &names, const CheckpointWriter &checkpoint)
{
    if (::geteuid() != 0) return {Status::PermissionDenied, "TUN DNS requires its privileged owner."};
    if (!record.isEmpty() || device.descriptor() < 0 || device.owner().isNull() || names.isEmpty()
        || names.size() > LinuxRouteSnapshotRows)
        return {Status::Failed, "An inactive DNS operation and newly owned configured TUN are required."};
    QJsonArray domains; QSet<QString> seen;
    for (const auto &name : names) {
        if (!domain(name) || seen.contains(name)) return {Status::Failed, "TUN DNS requires distinct canonical routing domains."};
        seen.insert(name); domains.append(QJsonObject{{"name", name}, {"route_only", true}});
    }
    const auto addresses = device.snapshot()["configuration"].toObject()["applied"].toObject()["ipv4"].toArray();
    if (addresses.size() != 1)
        return {Status::Failed, "An inactive DNS operation and newly owned configured TUN are required."};
    const auto source = addresses.first().toObject()["source"].toString(), peer = addresses.first().toObject()["peer"].toString();
    record = {{"version", 1}, {"owner", device.owner().toString(QUuid::WithoutBraces)}, {"interface", device.name()},
        {"index", qint64(device.index())}, {"source", source}, {"peer", peer}, {"namespace", linuxNetworkNamespace()}};
    if (!identity()) { record = {}; return {Status::Failed, "Cannot verify owned TUN DNS identity."}; }
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    auto original = read(deadline);
    while (original.result.succeeded() && original.absent && !deadline.hasExpired()) {
        QThread::msleep(10);
        original = read(deadline);
    }
    if (!original.result.succeeded() || original.absent || !original.profile["dns"].toArray().isEmpty() || !original.profile["domains"].toArray().isEmpty()) {
        record = {};
        auto result = original.result.succeeded() ? Result{Status::Unsupported, "A managed TUN with no existing DNS configuration is required."} : original.result;
        result.mayHaveChanged = false; return result;
    }
    record["provider"] = original.provider; record["before"] = original.profile; record["applied"] = original.profile;
    record["pending"] = QJsonObject{}; record["restoring"] = false; record["released"] = false;
    auto result = save(checkpoint);
    if (!result.succeeded()) { if (!result.mayHaveChanged) record = {}; return result; }
    for (const auto *key : {"default_route", "domains", "dns"}) {
        auto next = record["applied"].toObject();
        next[key] = QString(key) == "default_route" ? QJsonValue(false) : QString(key) == "domains" ? QJsonValue(domains) : QJsonValue(peerServer(peer));
        if (next == record["applied"].toObject()) continue;
        result = change(next, false, deadline, checkpoint);
        if (!result.succeeded()) {
            QDeadlineTimer rollback(LinuxRouteOperationTimeoutMs);
            const auto restored = restore(rollback, checkpoint);
            result.mayHaveChanged = !restored.succeeded(); return result;
        }
    }
    return {};
}

PlatformOperationResult LinuxTunDns::restore(const UnixTunDevice &device, const CheckpointWriter &checkpoint)
{
    if (record.isEmpty()) return {};
    if (device.descriptor() < 0 || record["owner"] != device.owner().toString(QUuid::WithoutBraces)
        || record["interface"] != device.name() || record["index"].toInteger() != device.index()) return failure("TUN DNS belongs to another device.");
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs); return restore(deadline, checkpoint);
}

PlatformOperationResult LinuxTunDns::restore(QDeadlineTimer &deadline, const CheckpointWriter &checkpoint)
{
    if (::geteuid() != 0) return {Status::PermissionDenied, "TUN DNS restoration requires its privileged owner."};
    if (record["released"] == true) return clear(checkpoint);
    if (!identity()) {
        char name[IFNAMSIZ]{};
        if (record["namespace"] == linuxNetworkNamespace()
            && ::if_nametoindex(record["interface"].toString().toLatin1().constData()) == 0
            && !::if_indextoname(quint32(record["index"].toInteger()), name)) {
            const auto gone = read(deadline);
            if (gone.result.succeeded() && gone.absent) return clear(checkpoint);
        }
        return failure("TUN DNS recovery requires the original namespace and interface identity.");
    }
    auto current = read(deadline); if (!current.result.succeeded()) return current.result;
    if (current.absent) return clear(checkpoint);
    const auto applied = record["applied"].toObject(), pending = record["pending"].toObject();
    if (current.provider != record["provider"].toObject()) {
        if (current.profile == record["before"].toObject()) return clear(checkpoint);
        return failure("The resolver restarted; existing DNS ownership is uncertain.");
    }
    if (!pending.isEmpty()) {
        const bool restoring = record["restoring"].toBool();
        if (recovered && ((restoring && current.profile == applied) || (!restoring && current.profile == pending)))
            return failure("An interrupted DNS change cannot be claimed after recovery.");
        if (current.profile == pending && (restoring || attempted)) record["applied"] = pending;
        else if (current.profile != applied) return clear(checkpoint);
        record["pending"] = QJsonObject{};
        auto result = save(checkpoint); if (!result.succeeded()) return result;
    } else if (current.profile != applied) return clear(checkpoint);
    for (const auto *key : {"dns", "domains", "default_route"}) {
        auto next = record["applied"].toObject(); next[key] = record["before"].toObject()[key];
        if (next == record["applied"].toObject()) continue;
        const auto result = change(next, true, deadline, checkpoint); if (!result.succeeded()) return result;
    }
    return clear(checkpoint);
}

PlatformOperationResult LinuxTunDns::recover(const QUuid &owner, const QJsonObject &saved, const CheckpointWriter &checkpoint)
{
    const auto peer = saved["peer"].toString(), source = saved["source"].toString();
    const auto before = saved["before"].toObject(), applied = saved["applied"].toObject(), pending = saved["pending"].toObject();
    const auto provider = saved["provider"].toObject();
    if (!record.isEmpty() || owner.isNull() || saved["version"] != 1 || saved["owner"] != owner.toString(QUuid::WithoutBraces)
        || !fields(saved, {"version", "owner", "interface", "index", "source", "peer", "namespace", "provider", "before", "applied", "pending", "restoring", "released"})
        || saved["interface"] != QString::fromLatin1(linuxTunName(owner)) || saved["namespace"].toString().isEmpty()
        || saved["namespace"] != linuxNetworkNamespace()
        || saved["index"].toInteger() <= 0 || saved["index"].toInteger() > INT_MAX || !saved["restoring"].isBool() || !saved["released"].isBool()
        || !canonicalUnicastIpv4(source) || !canonicalUnicastIpv4(peer) || source == peer
        || !providerIdentity(provider)
        || !saved["before"].isObject() || !saved["applied"].isObject() || !saved["pending"].isObject()
        || !profile(before, peer) || !before["dns"].toArray().isEmpty() || !before["domains"].toArray().isEmpty()
        || !stage(applied, before, peer) || (!pending.isEmpty() && (!stage(pending, before, peer)
            || !transition(applied, pending, before, saved["restoring"].toBool())))
        || QJsonDocument(saved).toJson(QJsonDocument::Compact).size() > LinuxRouteRecoveryBytes)
        return {Status::Failed, "Invalid authenticated TUN DNS recovery record."};
    record = saved; recovered = true; attempted = false;
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs); return restore(deadline, checkpoint);
}
