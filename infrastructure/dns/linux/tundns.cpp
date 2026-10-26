#include "infrastructure/dns/linux/tundns.h"
#include "infrastructure/dns/dnsdomains.h"
#include "infrastructure/routing/linux/iprouteutility.h"
#include "infrastructure/dns/linux/resolvedbus.h"
#include <QDBusArgument>
#include <QDBusMessage>
#include <QDBusMetaType>
#include <QJsonDocument>
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
constexpr int DnsPort = 53;
Result failure(const char *message) { return {Status::Failed, QString::fromLatin1(message), true}; }
bool fields(const QJsonObject &value, std::initializer_list<const char *> keys)
{
    if (value.size() != qsizetype(keys.size())) return false;
    for (const auto *key : keys) if (!value.contains(QLatin1String(key))) return false;
    return true;
}
bool routingDomains(const QJsonValue &value)
{
    if (!value.isArray() || value.toArray().size() > LinuxRouteSnapshotRows) return false;
    QSet<QString> seen;
    for (const auto &item : value.toArray()) {
        const auto row = item.toObject(); const auto name = row["name"].toString();
        if (!item.isObject() || !fields(row, {"name", "route_only"}) || !canonicalDnsDomain(name)
            || row["route_only"] != true || seen.contains(name)) return false;
        seen.insert(name);
    }
    return true;
}
QJsonArray peerServer(const QString &peer)
{
    return {QJsonObject{{"family", AF_INET}, {"address", peer}, {"port", DnsPort}, {"name", ""}}};
}
bool profile(const QJsonObject &value, const QString &peer)
{
    return fields(value, {"dns", "domains", "default_route"}) && value["default_route"].isBool()
        && value["dns"].isArray() && (value["dns"].toArray().isEmpty() || value["dns"].toArray() == peerServer(peer))
        && routingDomains(value["domains"]);
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
using LinuxResolved::call;
using LinuxResolved::replyResult;
using LinuxResolved::providerIdentity;

}

LinuxTunDns::State LinuxTunDns::read(QDeadlineTimer &deadline) const
{
    auto state = LinuxResolved::readLink(bus, int(record["index"].toInteger()), deadline);
    // The owned peer uses the effective DNS port; original-link records retain native DNSEx values.
    auto servers = state.profile["dns"].toArray();
    for (qsizetype i = 0; i < servers.size(); ++i) {
        auto row = servers[i].toObject();
        if (row["port"] == 0) row["port"] = DnsPort;
        servers[i] = row;
    }
    if (!state.profile.isEmpty()) state.profile["dns"] = servers;
    return state;
}

bool LinuxTunDns::identity() const
{
    return !record.isEmpty() && !record["namespace"].toString().isEmpty() && record["namespace"] == linuxNetworkNamespace()
        && assignedUnixTunPair(record["interface"].toString(), quint32(record["index"].toInteger()),
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
    if (!record.isEmpty() || device.descriptor() < 0 || device.owner().isNull())
        return {Status::Failed, "An inactive DNS operation and newly owned configured TUN are required."};
    if (!validTunDnsDomains(names)) return {Status::Failed, "TUN DNS requires distinct canonical routing domains."};
    QJsonArray domains;
    for (const auto &name : names) {
        domains.append(QJsonObject{{"name", name}, {"route_only", true}});
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
