#include "tunroutes.h"
#include "iprouteutility.h"
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QScopeGuard>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace {
using Status = PlatformOperationResult::Status;
QString routePrefix(const QJsonObject &row)
{
    const auto value = row["dst"].toString();
    if (value == "default") return "0.0.0.0/0";
    return value.contains('/') ? value : value + "/32";
}
bool canonicalPrefix(const QString &value, int minimum = 2)
{
    const auto parts = value.split('/');
    if (parts.size() != 2) return false;
    bool valid = false;
    const int bits = parts[1].toInt(&valid);
    in_addr address{};
    if (!valid || bits < minimum || bits > 32 || QString::number(bits) != parts[1]
        || ::inet_pton(AF_INET, parts[0].toLatin1().constData(), &address) != 1) return false;
    char canonical[INET_ADDRSTRLEN]{};
    if (!::inet_ntop(AF_INET, &address, canonical, sizeof(canonical)) || parts[0] != QString::fromLatin1(canonical)) return false;
    const quint32 host = ntohl(address.s_addr), mask = bits == 0 ? 0 : 0xffffffffu << (32 - bits);
    return (host & mask) == host;
}
bool assignedPair(const UnixTunDevice &device, const QString &source, const QString &peer)
{
    if (!canonicalPrefix(source + "/32") || !canonicalPrefix(peer + "/32")
        || source == "0.0.0.0" || peer == "0.0.0.0" || source == peer) return false;
    in_addr local{}, remote{};
    ::inet_pton(AF_INET, source.toLatin1().constData(), &local);
    ::inet_pton(AF_INET, peer.toLatin1().constData(), &remote);
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        if (QString::fromLatin1(entry->ifa_name) != device.name() || !(entry->ifa_flags & IFF_POINTOPOINT)
            || !entry->ifa_addr || entry->ifa_addr->sa_family != AF_INET
            || !entry->ifa_dstaddr || entry->ifa_dstaddr->sa_family != AF_INET) continue;
        if (reinterpret_cast<const sockaddr_in *>(entry->ifa_addr)->sin_addr.s_addr == local.s_addr
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_dstaddr)->sin_addr.s_addr == remote.s_addr) return true;
    }
    return false;
}
PlatformOperationResult write(const QString &utility, const QByteArray &batch, const QDeadlineTimer &deadline, bool recovering = false)
{
    const int remaining = int(deadline.remainingTime());
    if (remaining <= 0) return {Status::TimedOut, "Route batch deadline expired."};
    const QStringList args = recovering ? QStringList{"-4", "-force", "-batch", "-"} : QStringList{"-4", "-batch", "-"};
    return runPlatformCommand(utility, args, remaining, batch).result;
}
}

LinuxTunRoutes::ReadResult LinuxTunRoutes::read(const QString &utility, int timeoutMs) const
{
    if (timeoutMs <= 0) return {{Status::TimedOut, "Route snapshot deadline expired."}, {}};
    const QStringList args{"-N", "-j", "-4", "route", "show", "table", QString::number(RT_TABLE_MAIN)};
    const auto result = reader ? reader(utility, args) : runPlatformCommand(utility, args, timeoutMs);
    if (!result.result.succeeded()) return {result.result, {}};
    const auto bytes = result.output.toUtf8();
    const auto document = bytes.size() <= 1024 * 1024 && !result.output.contains(QChar::ReplacementCharacter)
        ? QJsonDocument::fromJson(bytes) : QJsonDocument{};
    if (!document.isArray() || document.array().size() > 4096)
        return {{Status::Failed, "Cannot read a complete route snapshot."}, {}};
    for (const auto &row : document.array())
        if (!row.isObject() || !row.toObject()["dst"].isString() || !canonicalPrefix(routePrefix(row.toObject()), 0))
            return {{Status::Failed, "Invalid route snapshot."}, {}};
    return {{}, document.array()};
}

bool LinuxTunRoutes::owns(const UnixTunDevice &device) const
{
    return device.descriptor() >= 0 && device.owner() == owner && device.name() == interfaceName
        && device.index() == interfaceIndex && interfaceIndex != 0
        && ::if_nametoindex(interfaceName.toLatin1().constData()) == interfaceIndex;
}

QJsonObject LinuxTunRoutes::find(const QJsonArray &rows, const QString &prefix) const
{
    for (const auto &value : rows) {
        const auto row = value.toObject();
        if (routePrefix(row) == prefix && row["dev"] == interfaceName && row["protocol"] == QString::number(RTPROT_STATIC)
            && row["metric"].toInteger(-1) == metric) return row;
    }
    return {};
}

bool LinuxTunRoutes::createdShape(const QJsonObject &row) const
{
    if (row.isEmpty() || (row.contains("scope") && row["scope"] != QString::number(RT_SCOPE_UNIVERSE))
        || row["prefsrc"] != sourceAddress || row["gateway"] != gatewayPeer || !row["flags"].isArray()
        || (row.contains("type") && row["type"] != "unicast")) return false;
    for (const auto &key : row.keys())
        if (key != "dst" && key != "dev" && key != "protocol" && key != "scope"
            && key != "metric" && key != "flags" && key != "type" && key != "prefsrc" && key != "gateway") return false;
    for (const auto &flag : row["flags"].toArray()) if (flag != "linkdown") return false;
    return true;
}

QByteArray LinuxTunRoutes::command(const QString &operation, const QString &prefix) const
{
    return QString("route %1 %2 dev %3 proto %4 scope %5 metric %6 table %7 src %8 via %9\n")
        .arg(operation, prefix, interfaceName, QString::number(RTPROT_STATIC), QString::number(RT_SCOPE_UNIVERSE),
             QString::number(metric), QString::number(RT_TABLE_MAIN), sourceAddress, gatewayPeer).toLatin1();
}

void LinuxTunRoutes::clear()
{
    entries.clear();
    owner = {};
    interfaceName.clear();
    sourceAddress.clear();
    gatewayPeer.clear();
    interfaceIndex = metric = 0;
}

QJsonObject LinuxTunRoutes::snapshot() const
{
    if (owner.isNull()) return {};
    QJsonArray routes;
    for (const auto &entry : entries)
        routes.append(QJsonObject{{"prefix", entry.prefix}, {"before", QJsonArray{}}, {"applied", entry.applied}});
    return {{"owner", owner.toString(QUuid::WithoutBraces)}, {"interface", interfaceName},
        {"index", qint64(interfaceIndex)}, {"source", sourceAddress}, {"peer", gatewayPeer},
        {"metric", qint64(metric)}, {"routes", routes}};
}

PlatformOperationResult LinuxTunRoutes::apply(const UnixTunDevice &device, const QString &source, const QString &peer, const QStringList &requested)
{
    if (!owner.isNull()) return {Status::Failed, "Owned routes must be restored before another apply."};
    if (requested.size() > 4096) return {Status::Failed, "Too many capture routes."};
    auto prefixes = requested;
    for (const auto &prefix : prefixes)
        if (!canonicalPrefix(prefix)) return {Status::Failed, "Capture routes require canonical IPv4 prefixes of length 2 through 32."};
    prefixes.removeDuplicates();
    if (prefixes.isEmpty()) return {};
    if (device.descriptor() < 0 || device.owner().isNull()) return {Status::Failed, "Capture routes require an owned TUN device."};
    if (!assignedPair(device, source, peer)) return {Status::Failed, "Capture routes require the owned device's nonzero IPv4 point-to-point addresses."};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported, "A trusted system iproute2 executable is required."};
    owner = device.owner();
    interfaceName = device.name();
    interfaceIndex = device.index();
    sourceAddress = source;
    gatewayPeer = peer;
    metric = 1u + owner.toByteArray(QUuid::Id128).left(8).toUInt(nullptr, 16) % 0xfffffffeu;
    if (!owns(device)) { clear(); return {Status::Failed, "TUN identity changed before route application."}; }
    QDeadlineTimer deadline(10000);
    const auto before = read(utility, int(deadline.remainingTime()));
    if (!before.result.succeeded()) { clear(); return before.result; }
    if (before.rows.size() + prefixes.size() > 4096) {
        clear();
        return {Status::Failed, "Capture routes exceed the complete snapshot capacity."};
    }
    for (const auto &value : before.rows) {
        if (prefixes.contains(routePrefix(value.toObject()))) {
            clear();
            return {Status::Failed, "An existing route cannot be adopted or replaced."};
        }
    }
    if (!owns(device) || !assignedPair(device, source, peer)) { clear(); return {Status::Failed, "TUN identity or addresses changed while reading routes."}; }
    QByteArray batch;
    for (const auto &prefix : prefixes) {
        entries.append({prefix, {}});
        batch += command("add", prefix);
    }
    auto applied = write(utility, batch, deadline);
    const auto after = read(utility, int(deadline.remainingTime()));
    bool complete = after.result.succeeded();
    if (complete) for (auto &entry : entries) {
        const auto row = find(after.rows, entry.prefix);
        if (createdShape(row)) entry.applied = row;
        else complete = false;
    }
    if (applied.succeeded() && complete) return {Status::Success, {}, true};
    if (applied.succeeded()) applied = after.result.succeeded()
        ? PlatformOperationResult{Status::Failed, "Cannot confirm all newly owned routes."} : after.result;
    const auto recovered = restore(device);
    applied.mayHaveChanged = true;
    if (!recovered.succeeded()) applied.detail += " Route rollback is incomplete; ownership records retained.";
    return applied;
}

PlatformOperationResult LinuxTunRoutes::restore(const UnixTunDevice &device)
{
    if (entries.isEmpty()) { clear(); return {}; }
    if (!owns(device)) return {Status::Failed, "Route ownership no longer matches the active TUN device.", true};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported, "A trusted system iproute2 executable is required.", true};
    QDeadlineTimer deadline(10000);
    const auto before = read(utility, int(deadline.remainingTime()));
    if (!before.result.succeeded()) {
        auto error = before.result;
        error.mayHaveChanged = true;
        return error;
    }
    QByteArray batch;
    bool external = false;
    for (auto it = entries.begin(); it != entries.end();) {
        const auto current = find(before.rows, it->prefix);
        if (current.isEmpty()) {
            for (const auto &value : before.rows) external |= routePrefix(value.toObject()) == it->prefix;
            it = entries.erase(it);
        }
        else if (it->applied.isEmpty() && !createdShape(current)) ++it;
        else if (!it->applied.isEmpty() && current != it->applied) {
            external = true;
            it = entries.erase(it);
        } else {
            it->applied = current;
            batch += command("del", it->prefix);
            ++it;
        }
    }
    if (entries.isEmpty()) {
        clear();
        return {Status::Success, external ? QString("External route changes were preserved.") : QString{}};
    }
    if (batch.isEmpty()) return {Status::Failed, "Cannot establish unconfirmed route ownership; records retained.", true};
    if (!owns(device)) return {Status::Failed, "TUN identity changed before route recovery.", true};
    const auto removed = write(utility, batch, deadline, true);
    const auto after = read(utility, int(deadline.remainingTime()));
    if (!after.result.succeeded()) {
        auto error = after.result;
        error.mayHaveChanged = true;
        return error;
    }
    for (auto it = entries.begin(); it != entries.end();) {
        const auto current = find(after.rows, it->prefix);
        if (current.isEmpty() || (!it->applied.isEmpty() && current != it->applied)) {
            external |= !current.isEmpty();
            it = entries.erase(it);
        } else ++it;
    }
    if (!entries.isEmpty()) return {removed.succeeded() ? Status::Failed : removed.status,
        "Cannot confirm route recovery; ownership records retained.", true};
    clear();
    return {Status::Success, external ? QString("External route changes were preserved.") : QString{}};
}
