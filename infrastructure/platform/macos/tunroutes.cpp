#include "tunroutes.h"
#include "infrastructure/platform/ipv4.h"
#include <QDeadlineTimer>
#include <QFileInfo>
#include <QJsonDocument>
#include <QSet>
#include <cstring>
#include <net/if_dl.h>
#include <net/route.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
QJsonArray matching(const QJsonArray &rows, const QString &prefix)
{
    QJsonArray result;
    for (const auto &row : rows) if (row.toObject()["prefix"] == prefix) result.append(row);
    return result;
}
int exactMatches(const QJsonArray &rows, const QJsonObject &applied)
{
    int count = 0;
    for (const auto &row : rows) if (row.toObject() == applied) ++count;
    return count;
}
bool utunName(const QString &name)
{
    if (!name.startsWith("utun") || name.size() <= 4 || name.size() >= IFNAMSIZ) return false;
    for (auto character : name.mid(4)) if (character < '0' || character > '9') return false;
    return true;
}
}

void MacTunRoutes::clear()
{
    owner = {}; interfaceName.clear(); boot.clear(); sourceAddress.clear(); peerAddress.clear(); interfaceIndex = 0; entries.clear();
}
bool MacTunRoutes::identity() const
{
    return !boot.isEmpty() && macBootSession() == boot && assignedUnixTunPair(interfaceName, interfaceIndex, sourceAddress, peerAddress);
}
bool MacTunRoutes::shape(const QJsonObject &row) const
{
    const auto flags = row["flags"].toInteger(-1);
    if (row.size() != 5 || flags < 0 || flags > 0xffffffffLL || row["flags"].toDouble(-1) != double(flags)
        || row["index"].toDouble(-1) != double(interfaceIndex) || !row["addresses"].isObject()
        || !row["metrics"].isArray() || row["metrics"].toArray().size() != 13
        || macRoutePrefix(row["addresses"].toObject(), quint32(flags)) != row["prefix"].toString()) return false;
    int metricIndex = 0;
    for (const auto &value : row["metrics"].toArray()) {
        const auto metric = value.toInteger(-2147483649LL);
        if (!value.isDouble() || value.toDouble() != double(metric)
            || metric < (metricIndex == 3 ? -2147483648LL : 0) || metric > 0xffffffffLL) return false;
        ++metricIndex;
    }
    const auto addresses = row["addresses"].toObject();
    for (auto it = addresses.begin(); it != addresses.end(); ++it) {
        bool valid = false; const auto index = it.key().toInt(&valid);
        const auto raw = QByteArray::fromHex(it.value().toString().toLatin1());
        if (!valid || index < 0 || index >= RTAX_MAX || QString::number(index) != it.key()
            || !it.value().isString() || QString::fromLatin1(raw.toHex()) != it.value().toString()
            || (raw.isEmpty() ? index != RTAX_NETMASK : raw.size() < 2 || quint8(raw[0]) != raw.size())) return false;
    }
    const auto gateway = QByteArray::fromHex(row["addresses"].toObject()[QString::number(RTAX_GATEWAY)].toString().toLatin1());
    sockaddr_dl link{};
    if (gateway.size() < 4 || gateway.size() > int(sizeof(link))) return false;
    std::memcpy(&link, gateway.constData(), size_t(gateway.size()));
    return row["index"].toInteger() == interfaceIndex && link.sdl_family == AF_LINK && link.sdl_index == interfaceIndex
        && (flags & (RTF_UP|RTF_STATIC|RTF_PROTO1)) == (RTF_UP|RTF_STATIC|RTF_PROTO1)
        && !(flags & (RTF_GATEWAY|RTF_REJECT|RTF_BLACKHOLE|RTF_IFSCOPE|RTF_WASCLONED|RTF_LOCAL|RTF_BROADCAST|RTF_MULTICAST));
}
QJsonObject MacTunRoutes::snapshot() const
{
    if (owner.isNull()) return {};
    QJsonArray routes;
    for (const auto &entry : entries) routes.append(QJsonObject{{"prefix", entry.prefix}, {"before", QJsonArray{}},
        {"applied", entry.applied}, {"delete_started", entry.deleting}});
    return {{"version", 1}, {"owner", owner.toString(QUuid::WithoutBraces)}, {"boot", boot}, {"interface", interfaceName},
        {"index", qint64(interfaceIndex)}, {"source", sourceAddress}, {"peer", peerAddress}, {"routes", routes}};
}
Result MacTunRoutes::save(const CheckpointWriter &checkpoint) const
{
    const auto record = snapshot();
    if (QJsonDocument(record).toJson(QJsonDocument::Compact).size() > NetworkJournalMaxBytes)
        return {Status::Failed, "macOS capture ownership exceeds its complete record budget.", true};
    auto result = checkpoint ? checkpoint(record) : Result{};
    if (!result.succeeded()) result.mayHaveChanged = true;
    return result;
}
Result MacTunRoutes::change(const QString &operation, const QString &prefix, int timeoutMs) const
{
    const QFileInfo program("/sbin/route");
    if (timeoutMs <= 0) return {Status::TimedOut, "macOS capture operation timed out.", true};
    if (!program.isExecutable() || program.ownerId() != 0 || program.isSymLink()
        || (program.permissions() & (QFileDevice::WriteGroup|QFileDevice::WriteOther)))
        return {Status::Unsupported, "A trusted system route utility is required."};
    const QStringList arguments{"-n", operation, "-inet", "-net", prefix, "-interface", interfaceName, "-static", "-proto1"};
    return (runner ? runner(program.absoluteFilePath(), arguments)
        : runPlatformCommand(program.absoluteFilePath(), arguments, timeoutMs, {}, QProcessEnvironment{})).result;
}
Result MacTunRoutes::apply(const UnixTunDevice &device, const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    if (!owner.isNull() || device.owner().isNull() || device.descriptor() < 0 || prefixes.isEmpty() || prefixes.size() > MacRouteSnapshotRows)
        return {Status::Failed, "Inactive route ownership and a configured owned utun are required."};
    const auto ipv4 = device.snapshot()["configuration"].toObject()["applied"].toObject()["ipv4"].toArray();
    if (ipv4.size() != 1 || !utunName(device.name())) return {Status::Failed, "A verified point-to-point utun is required."};
    const auto pair = ipv4.first().toObject();
    if (!assignedUnixTunPair(device.name(), device.index(), pair["source"].toString(), pair["peer"].toString()))
        return {Status::Failed, "The owned utun address identity changed."};
    const auto session = macBootSession();
    if (session.isEmpty()) return {Status::Failed, "Cannot bind capture ownership to the current boot."};
    QSet<QString> unique;
    for (const auto &prefix : prefixes) {
        if (!canonicalUnicastIpv4Prefix(prefix) || ipv4PrefixContainsAddress(prefix, pair["source"].toString())
            || ipv4PrefixContainsAddress(prefix, pair["peer"].toString())) return {Status::Failed, "Invalid or self-capturing IPv4 prefix."};
        unique.insert(prefix);
    }
    const auto initial = readMacRoutes();
    if (!initial.result.succeeded()) return initial.result;
    if (initial.rows.size()+unique.size() > MacRouteSnapshotRows) return {Status::Failed, "Capture routes exceed the complete native snapshot bound."};
    for (const auto &prefix : unique) if (!matching(initial.rows, prefix).isEmpty())
        return {Status::Failed, "An existing exact-prefix route is preserved; macOS replacement is not supported."};
    owner = device.owner(); interfaceName = device.name(); interfaceIndex = device.index(); boot = session;
    sourceAddress = pair["source"].toString(); peerAddress = pair["peer"].toString();
    auto result = append(unique.values(),checkpoint);
    if (result.succeeded()) return result;
    const auto recovered = restore(owner,checkpoint);
    if (!recovered.succeeded()) result.detail += " Recovery: "+recovered.detail;
    result.mayHaveChanged = !recovered.succeeded();
    return result;
}

Result MacTunRoutes::extend(const UnixTunDevice &device, const QStringList &addresses, const CheckpointWriter &checkpoint)
{
    if (owner.isNull() || device.owner() != owner || device.descriptor() < 0 || device.name() != interfaceName
        || device.index() != interfaceIndex || !identity() || addresses.isEmpty() || addresses.size() > MacRouteSnapshotRows)
        return {Status::Failed,"DNS captures require the active owned utun.",true};
    const auto current = readMacRoutes();
    if (!current.result.succeeded()) return current.result;
    for (const auto &entry : entries)
        if (entry.deleting || entry.applied.isEmpty() || exactMatches(matching(current.rows,entry.prefix),entry.applied) != 1)
            return {Status::Failed,"Existing capture ownership changed before DNS publication.",true};
    QStringList additions;
    for (const auto &address : addresses) {
        if (!canonicalUnicastIpv4(address) || address == sourceAddress || address == peerAddress)
            return {Status::Failed,"Invalid or self-capturing DNS address.",true};
        bool covered = false;
        for (const auto &entry : entries) covered |= ipv4PrefixContainsAddress(entry.prefix,address);
        const auto prefix = address+"/32";
        if (!covered && !additions.contains(prefix)) {
            if (!matching(current.rows,prefix).isEmpty()) return {Status::Failed,"External DNS address route is preserved.",true};
            additions.append(prefix);
        }
    }
    if (entries.size()+additions.size() > MacRouteSnapshotRows || current.rows.size()+additions.size() > MacRouteSnapshotRows)
        return {Status::Failed,"DNS captures exceed the complete native snapshot bound.",true};
    if (additions.isEmpty()) return {};
    return append(additions,checkpoint);
}

Result MacTunRoutes::reconcile(const UnixTunDevice &device, const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    if (owner.isNull() || device.owner() != owner || device.descriptor() < 0 || device.name() != interfaceName
        || device.index() != interfaceIndex || !identity() || prefixes.size() > MacRouteSnapshotRows)
        return {Status::Failed,"Capture changes require the active owned utun.",true};
    const auto current = readMacRoutes();
    if (!current.result.succeeded()) return current.result;
    QStringList before, additions, removals;
    for (const auto &entry : entries) {
        if (entry.deleting || entry.applied.isEmpty() || exactMatches(matching(current.rows,entry.prefix),entry.applied) != 1)
            return {Status::Failed,"Capture ownership changed before reconciliation.",true};
        before.append(entry.prefix);
        if (!prefixes.contains(entry.prefix)) removals.append(entry.prefix);
    }
    QSet<QString> unique;
    for (const auto &prefix : prefixes) {
        if (!canonicalUnicastIpv4Prefix(prefix) || unique.contains(prefix)
            || ipv4PrefixContainsAddress(prefix,sourceAddress) || ipv4PrefixContainsAddress(prefix,peerAddress))
            return {Status::Failed,"Invalid or self-capturing replacement prefix.",true};
        unique.insert(prefix);
        if (!before.contains(prefix)) {
            if (!matching(current.rows,prefix).isEmpty()) return {Status::Failed,"An external exact route is preserved.",true};
            additions.append(prefix);
        }
    }
    if (current.rows.size()+additions.size() > MacRouteSnapshotRows)
        return {Status::Failed,"Capture changes exceed the complete native snapshot bound.",true};
    if (auto removed = remove(removals,checkpoint); !removed.succeeded()) return removed;
    return append(additions,checkpoint);
}

Result MacTunRoutes::append(const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    QDeadlineTimer deadline(MacRouteOperationTimeoutMs);
    const auto failed = [](Result result) { result.mayHaveChanged = true; return result; };
    for (const auto &prefix : prefixes) {
        const auto before = readMacRoutes();
        if (!before.result.succeeded()) return failed(before.result);
        if (!identity() || !matching(before.rows, prefix).isEmpty()) return failed({Status::Failed, "Route or utun identity changed before capture."});
        entries.append({prefix, {}, false});
        if (const auto saved = save(checkpoint); !saved.succeeded()) { entries.removeLast(); return failed(saved); }
        const auto verified = readMacRoutes();
        if (!verified.result.succeeded()) { entries.removeLast(); return failed(verified.result); }
        if (!identity() || !matching(verified.rows, prefix).isEmpty()) {
            entries.removeLast(); return failed({Status::Failed, "Capture state changed while publishing intent."});
        }
        const auto written = change("add", prefix, int(deadline.remainingTime()));
        const auto after = readMacRoutes();
        if (!after.result.succeeded()) return failed(after.result);
        const auto rows = matching(after.rows, prefix);
        if (!written.succeeded()) return failed(written);
        QJsonArray owned;
        for (const auto &row : rows) if (shape(row.toObject())) owned.append(row);
        if (!identity() || owned.size() != 1)
            return failed({Status::Failed, "Cannot confirm the complete applied capture route."});
        entries.last().applied = owned.first().toObject();
        if (const auto saved = save(checkpoint); !saved.succeeded()) return failed(saved);
    }
    return {Status::Success, {}, true};
}

bool MacTunRoutes::load(const QUuid &id, const QJsonObject &saved)
{
    if (!owner.isNull() || id.isNull() || saved.size() != 8 || saved["version"] != 1
        || saved["owner"] != id.toString(QUuid::WithoutBraces) || saved["boot"] != macBootSession() || saved["boot"].toString().isEmpty()
        || !utunName(saved["interface"].toString()) || saved["index"].toInteger() <= 0 || saved["index"].toInteger() > 65535
        || !canonicalUnicastIpv4(saved["source"].toString()) || !canonicalUnicastIpv4(saved["peer"].toString()) || saved["source"] == saved["peer"]
        || !saved["routes"].isArray() || saved["routes"].toArray().size() > MacRouteSnapshotRows
        || QJsonDocument(saved).toJson(QJsonDocument::Compact).size() > NetworkJournalMaxBytes) return false;
    owner = id; interfaceName = saved["interface"].toString(); interfaceIndex = quint32(saved["index"].toInteger());
    boot = saved["boot"].toString(); sourceAddress = saved["source"].toString(); peerAddress = saved["peer"].toString();
    QSet<QString> unique;
    for (const auto &value : saved["routes"].toArray()) {
        const auto row = value.toObject(); const auto prefix = row["prefix"].toString(); const auto applied = row["applied"].toObject();
        if (row.size() != 4 || !canonicalIpv4Prefix(prefix) || unique.contains(prefix)
            || ipv4PrefixContainsAddress(prefix,sourceAddress) || ipv4PrefixContainsAddress(prefix,peerAddress)
            || !row["before"].isArray() || !row["before"].toArray().isEmpty()
            || !row["applied"].isObject() || !row["delete_started"].isBool() || (row["delete_started"].toBool() && applied.isEmpty())
            || (!applied.isEmpty() && (applied["prefix"] != prefix || !shape(applied)))) { clear(); return false; }
        unique.insert(prefix); entries.append({prefix, applied, row["delete_started"].toBool()});
    }
    return true;
}

bool MacTunRoutes::validRecord(const QUuid &id,const QJsonObject &saved)
{
    MacTunRoutes reader; return reader.load(id,saved);
}
Result MacTunRoutes::recover(const QUuid &id,const QJsonObject &saved,const CheckpointWriter &checkpoint)
{
    if (!load(id,saved)) return {Status::Failed,"Invalid or foreign macOS capture ownership."};
    return restore(id,checkpoint);
}


Result MacTunRoutes::restore(const QUuid &id, const CheckpointWriter &checkpoint)
{
    if (owner.isNull()) return {};
    if (id != owner || macBootSession() != boot) return {Status::Failed, "Capture recovery owner or boot differs.", true};
    const auto validIdentity = [&] {
        if (identity()) return true;
        char name[IFNAMSIZ]{};
        return !::if_nametoindex(interfaceName.toLatin1().constData()) && !::if_indextoname(interfaceIndex, name);
    };
    if (!validIdentity()) return {Status::Failed, "Capture device identity changed; saved ownership is retained.", true};
    QStringList prefixes;
    for (const auto &entry : entries) prefixes.append(entry.prefix);
    const auto result = remove(prefixes,checkpoint);
    if (!result.succeeded()) return result;
    if (checkpoint) { auto saved = checkpoint({}); if (!saved.succeeded()) { saved.mayHaveChanged = true; return saved; } }
    clear(); return {Status::Success, {}, true};
}

Result MacTunRoutes::remove(const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    QDeadlineTimer deadline(MacRouteOperationTimeoutMs);
    bool unresolved = false;
    for (auto it = entries.begin(); it != entries.end();) {
        if (!prefixes.contains(it->prefix)) { ++it; continue; }
        auto read = readMacRoutes();
        if (!read.result.succeeded()) { read.result.mayHaveChanged = true; return read.result; }
        const auto rows = matching(read.rows, it->prefix);
        const int exact = exactMatches(rows,it->applied);
        if (rows.isEmpty() || (!it->applied.isEmpty() && exact == 0)) {
            it = entries.erase(it); continue;
        }
        if (exact != 1 || it->applied.isEmpty() || it->deleting) { unresolved = true; ++it; continue; }
        it->deleting = true;
        if (const auto saved = save(checkpoint); !saved.succeeded()) { it->deleting = false; return saved; }
        const auto verified = readMacRoutes();
        if (!verified.result.succeeded() || !identity() || exactMatches(matching(verified.rows, it->prefix),it->applied) != 1) {
            it->deleting = false; const auto saved = save(checkpoint);
            if (!saved.succeeded()) return saved;
            return {Status::Failed, "Capture route changed while publishing deletion; it was preserved.", true};
        }
        auto removed = change("delete", it->prefix, int(deadline.remainingTime()));
        auto after = readMacRoutes();
        if (!after.result.succeeded()) { after.result.mayHaveChanged = true; return after.result; }
        const auto remaining = matching(after.rows, it->prefix);
        if (exactMatches(remaining,it->applied) == 0) it = entries.erase(it);
        else {
            removed.mayHaveChanged = true;
            return removed.succeeded() ? Result{Status::Failed, "Cannot confirm capture removal; ownership is retained.", true} : removed;
        }
        if (const auto saved = save(checkpoint); !saved.succeeded()) return saved;
    }
    if (unresolved) return {Status::Failed, "Interrupted or unconfirmed capture is unresolved; matching routes are retained.", true};
    if (!prefixes.isEmpty()) { const auto saved = save(checkpoint); if (!saved.succeeded()) return saved; }
    return {Status::Success, {}, !prefixes.isEmpty()};
}
