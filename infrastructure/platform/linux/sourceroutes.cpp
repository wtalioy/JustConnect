#include "sourceroutes.h"
#include "iprouteutility.h"
#include <QJsonDocument>
#include <QScopeGuard>
#include <QSet>
#include <ifaddrs.h>
#include <net/if.h>

namespace {
using Status = PlatformOperationResult::Status;
bool localRule(QJsonObject row)
{
    row.remove("protocol");
    return row == QJsonObject{{"priority",0},{"src","all"},{"table","255"}};
}
bool numericId(const QJsonValue &field, quint64 maximum)
{
    if (!field.isString()) return false;
    bool valid = false;
    const auto value = field.toString().toULongLong(&valid);
    return valid && value <= maximum && field.toString() == QString::number(value);
}
PlatformOperationResult write(const QString &utility, const QByteArray &batch, const QDeadlineTimer &deadline, bool recovering = false, bool *attempted = nullptr)
{
    if (deadline.hasExpired()) return {Status::TimedOut,"Source route operation deadline expired."};
    const QStringList args = recovering ? QStringList{"-4","-force","-batch","-"} : QStringList{"-4","-batch","-"};
    if (attempted) *attempted = true;
    return runPlatformCommand(utility,args,int(deadline.remainingTime()),batch).result;
}
}

bool LinuxSourceRoutes::identity() const
{
    return interfaceIndex && !networkNamespace.isEmpty() && linuxNetworkNamespace()==networkNamespace
        && ::if_nametoindex(interfaceName.toLatin1().constData()) == interfaceIndex;
}
bool LinuxSourceRoutes::sourceAssigned() const
{
    ifaddrs *addresses = nullptr;
    if (::getifaddrs(&addresses) != 0) return false;
    const auto release = qScopeGuard([&] { ::freeifaddrs(addresses); });
    in_addr expected{};
    ::inet_pton(AF_INET,sourceAddress.toLatin1().constData(),&expected);
    for (auto *entry = addresses; entry; entry = entry->ifa_next) {
        const auto label = QString::fromLatin1(entry->ifa_name);
        if ((label == interfaceName || label.startsWith(interfaceName+":")) && entry->ifa_addr && entry->ifa_addr->sa_family == AF_INET
            && reinterpret_cast<const sockaddr_in *>(entry->ifa_addr)->sin_addr.s_addr == expected.s_addr) return true;
    }
    return false;
}
LinuxSourceRoutes::ReadResult LinuxSourceRoutes::read(const QString &utility, const QDeadlineTimer &deadline) const
{
    ReadResult snapshot;
    for (const bool rules : {false,true}) {
        if (deadline.hasExpired()) return {{Status::TimedOut,"Source route snapshot deadline expired."},{},{}};
        const QStringList args = rules ? QStringList{"-N","-j","-4","rule","show"}
            : QStringList{"-N","-j","-4","route","show","table","all"};
        const auto command = reader ? reader(utility,args) : runPlatformCommand(utility,args,int(deadline.remainingTime()));
        if (!command.result.succeeded()) return {command.result,{},{}};
        const auto bytes = command.output.toUtf8();
        const auto document = bytes.size() <= LinuxRouteSnapshotBytes && !command.output.contains(QChar::ReplacementCharacter)
            ? QJsonDocument::fromJson(bytes) : QJsonDocument{};
        if (!document.isArray() || document.array().size() > LinuxRouteSnapshotRows)
            return {{Status::Failed,"Cannot read a complete source route/rule snapshot."},{},{}};
        for (const auto &value : document.array()) {
            const auto row = value.toObject();
            const bool table = numericId(row["table"],0xffffffffu);
            // iproute2 omits the main table, but an owned private-table row must name its table.
            const bool implicitMain = !row.contains("table") && !(row["dev"] == interfaceName
                && row["protocol"] == "4" && row["metric"].toInteger(-1) == metric);
            const auto action = row["action"].toString();
            const bool terminal = action=="3" || action=="6" || action=="7" || action=="8";
            const bool jump = row["goto"].toInteger(-1)>=0 && row["goto"].toInteger()<=0xffffffffLL;
            const bool validTable = rules ? (row.contains("table") ? table : terminal || jump) : table || implicitMain;
            if (!value.isObject() || !validTable
                || (row.contains("protocol") && !numericId(row["protocol"],255))
                || (!rules && row.contains("scope") && !numericId(row["scope"],255))
                || (rules ? row["priority"].toInteger(-1) < 0 || row["priority"].toInteger() > 0xffffffffLL
                : !row["dst"].isString() || !canonicalIpv4Prefix(ipv4RoutePrefix(row),0)))
                return {{Status::Failed,"Invalid source route/rule snapshot."},{},{}};
        }
        if (rules) snapshot.rules = document.array(); else snapshot.routes = document.array();
    }
    for (const auto &value : snapshot.routes) {
        const auto row = value.toObject();
        if (row["table"] == QString::number(table) && row["dev"] == interfaceName && row["protocol"] == "4"
            && row["metric"].toInteger(-1) == metric) {
            const auto prefix = ipv4RoutePrefix(row);
            if (snapshot.ownedRoutes.contains(prefix)) return {{Status::Failed,"Ambiguous owned source route."},{},{},{}};
            snapshot.ownedRoutes.insert(prefix,row);
        }
    }
    return snapshot;
}
QJsonObject LinuxSourceRoutes::findRoute(const ReadResult &rows, const QString &prefix) const
{
    return rows.ownedRoutes.value(prefix);
}
QJsonObject LinuxSourceRoutes::findRule(const QJsonArray &rows) const
{
    for (const auto &value : rows) {
        const auto row = value.toObject();
        if (row["priority"] == 1 && row["table"] == QString::number(table) && row["protocol"] == "4"
            && (row["src"] == sourceAddress || row["src"] == sourceAddress + "/32")) return row;
    }
    return {};
}
bool LinuxSourceRoutes::routeShape(const QJsonObject &row, const QString &prefix) const
{
    const bool link = gatewayAddress.isEmpty() || prefix == gatewayAddress + "/32";
    if (row.isEmpty() || row["prefsrc"] != sourceAddress || !row["flags"].isArray()
        || (row.contains("type") && row["type"] != "unicast")
        || (link ? row["scope"] != "253" || row.contains("gateway")
                 : row["gateway"] != gatewayAddress || (row.contains("scope") && row["scope"] != "0"))) return false;
    for (const auto &flag : row["flags"].toArray()) if (flag != "linkdown") return false;
    for (const auto &key : row.keys())
        if (key != "dst" && key != "dev" && key != "table" && key != "protocol" && key != "scope" && key != "type"
            && key != "metric" && key != "flags" && key != "prefsrc" && key != "gateway") return false;
    return true;
}
bool LinuxSourceRoutes::ruleShape(const QJsonObject &row) const
{
    return !row.isEmpty() && row.size() == 4 && row.contains("priority") && row.contains("src")
        && row.contains("table") && row.contains("protocol");
}
QByteArray LinuxSourceRoutes::routeCommand(const QString &operation, const QString &prefix) const
{
    const bool link = gatewayAddress.isEmpty() || prefix == gatewayAddress + "/32";
    return QString("route %1 %2 dev %3 proto 4 scope %4 metric %5 table %6 src %7%8\n")
        .arg(operation,prefix,interfaceName,link ? "253" : "0",QString::number(metric),QString::number(table),sourceAddress,
             link ? QString{} : " via " + gatewayAddress).toLatin1();
}
QByteArray LinuxSourceRoutes::ruleCommand(const QString &operation) const
{
    return QString("rule %1 priority 1 from %2/32 table %3 protocol 4\n").arg(operation,sourceAddress,QString::number(table)).toLatin1();
}
void LinuxSourceRoutes::clear()
{
    entries.clear();appliedRule = {};rulePending = false;ruleDeleting = false;owner = {};
    interfaceName.clear();sourceAddress.clear();gatewayAddress.clear();networkNamespace.clear();interfaceIndex = table = metric = 0;
}
QJsonObject LinuxSourceRoutes::snapshot() const
{
    if (owner.isNull()) return {};
    QJsonArray routes;
    for (const auto &entry : entries) routes.append(QJsonObject{{"prefix",entry.prefix},{"before",QJsonArray{}},
        {"applied",entry.applied},{"delete_started",entry.deleting}});
    return {{"owner",owner.toString(QUuid::WithoutBraces)},{"namespace",networkNamespace},{"interface",interfaceName},{"index",qint64(interfaceIndex)},
        {"source",sourceAddress},{"gateway",gatewayAddress},{"table",qint64(table)},{"priority",1},{"metric",qint64(metric)},
        {"routes",routes},{"rule_pending",rulePending},{"rule_delete_started",ruleDeleting},{"rule_before",QJsonArray{}},{"rule_applied",appliedRule}};
}
PlatformOperationResult LinuxSourceRoutes::saveCheckpoint(const CheckpointWriter &writer) const
{
    return writer ? writer(snapshot()) : PlatformOperationResult{};
}
PlatformOperationResult LinuxSourceRoutes::recover(const QUuid &id, const QJsonObject &saved, const CheckpointWriter &checkpoint)
{
    if (!owner.isNull()) return {Status::Failed,"Active source ownership cannot be replaced by a saved record."};
    const auto invalid = PlatformOperationResult{Status::Failed,"Invalid saved source route ownership."};
    if (id.isNull() || saved.size()!=14 || saved["owner"]!=id.toString(QUuid::WithoutBraces)
        || QJsonDocument(saved).toJson(QJsonDocument::Compact).size()>MaxSnapshotBytes
        || !saved["interface"].isString() || !saved["source"].isString() || !saved["gateway"].isString()
        || !canonicalLinuxInterfaceName(saved["interface"].toString())
        || !canonicalUnicastIpv4(saved["source"].toString()) || (!saved["gateway"].toString().isEmpty() && !canonicalUnicastIpv4(saved["gateway"].toString()))
        || saved["source"]==saved["gateway"] || saved["index"].toInteger(-1)<=0 || saved["index"].toInteger()>0xffffffffLL
        || saved["priority"]!=1 || !saved["routes"].isArray() || saved["routes"].toArray().size()>LinuxRouteSnapshotRows
        || !saved["rule_pending"].isBool() || !saved["rule_delete_started"].isBool()
        || !saved["rule_before"].isArray() || !saved["rule_before"].toArray().isEmpty()
        || !saved["rule_applied"].isObject()) return invalid;
    const auto namespaceId = linuxNetworkNamespace();
    if (namespaceId.isEmpty() || saved["namespace"]!=namespaceId) return invalid;
    if (saved["table"].toInteger(-1)!=linuxSourceTable(id)
        || saved["metric"].toInteger(-1)!=linuxRouteMetric(id)) return invalid;
    bool accepted = false;
    const auto discard = qScopeGuard([&] { if (!accepted) clear(); });
    owner = id;networkNamespace = namespaceId;interfaceName = saved["interface"].toString();interfaceIndex = quint32(saved["index"].toInteger());
    sourceAddress = saved["source"].toString();gatewayAddress = saved["gateway"].toString();
    table = quint32(saved["table"].toInteger());metric = quint32(saved["metric"].toInteger());
    rulePending = saved["rule_pending"].toBool();appliedRule = saved["rule_applied"].toObject();
    ruleDeleting = saved["rule_delete_started"].toBool();
    if (!appliedRule.isEmpty() && (!rulePending || !ruleShape(appliedRule) || findRule(QJsonArray{appliedRule})!=appliedRule)) return invalid;
    if (ruleDeleting && (!rulePending || appliedRule.isEmpty())) return invalid;
    QSet<QString> prefixes;
    for (const auto &value : saved["routes"].toArray()) {
        const auto entry = value.toObject();
        const auto prefix = entry["prefix"].toString();
        if (!value.isObject() || entry.size()!=4 || !entry["delete_started"].isBool() || !canonicalIpv4Prefix(prefix) || prefixes.contains(prefix)
            || !entry["before"].isArray() || !entry["before"].toArray().isEmpty() || !entry["applied"].isObject()
            || (prefix==gatewayAddress+"/32" && !entries.isEmpty())) return invalid;
        const auto row = entry["applied"].toObject();
        if (!row.isEmpty() && (!routeShape(row,prefix) || ipv4RoutePrefix(row)!=prefix || row["dev"]!=interfaceName
            || row["table"]!=QString::number(table) || row["protocol"]!="4" || row["metric"].toInteger(-1)!=metric)) return invalid;
        const bool deleting = entry["delete_started"].toBool();
        if (deleting && (row.isEmpty() || rulePending || ruleDeleting)) return invalid;
        prefixes.insert(prefix);entries.append({prefix,row,deleting});
    }
    accepted = true;
    return restore(id,checkpoint);
}
PlatformOperationResult LinuxSourceRoutes::validate(const QString &interface, const QString &source,
                                                   const QString &gateway, const QStringList &requested)
{
    if (!canonicalLinuxInterfaceName(interface)
        || !canonicalUnicastIpv4(source) || (!gateway.isEmpty() && !canonicalUnicastIpv4(gateway)) || source == gateway || requested.isEmpty() || requested.size() > LinuxRouteSnapshotRows)
        return {Status::Failed,"Invalid original interface, source, gateway or target count."};
    for (const auto &prefix : requested)
        if (!canonicalIpv4Prefix(prefix) || prefix == gateway + "/32") return {Status::Failed,"Invalid original destination prefix."};
    return {};
}
PlatformOperationResult LinuxSourceRoutes::apply(const QUuid &id, const QString &interface, const QString &source,
                                                const QString &gateway, const QStringList &requested,
                                                const CheckpointWriter &writeAhead)
{
    if (!owner.isNull() || id.isNull()) return {Status::Failed,"Source route ownership is missing or already active."};
    const auto valid = validate(interface, source, gateway, requested);
    if (!valid.succeeded()) return valid;
    auto prefixes = requested;
    prefixes.removeDuplicates();
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    const auto namespaceId = linuxNetworkNamespace();
    if (namespaceId.isEmpty()) return {Status::Failed,"Cannot identify the Linux boot and network namespace."};
    owner = id;networkNamespace = namespaceId;interfaceName = interface;sourceAddress = source;gatewayAddress = gateway;
    interfaceIndex = ::if_nametoindex(interfaceName.toLatin1().constData());
    table = linuxSourceTable(id);metric = linuxRouteMetric(id);
    const auto discard = qScopeGuard([&] { if (entries.isEmpty() && !rulePending) clear(); });
    if (!identity() || !sourceAssigned()) return {Status::Failed,"Original source is not assigned to the selected live interface."};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto available = [&](const ReadResult &state) -> PlatformOperationResult {
        if (!state.result.succeeded()) return state.result;
        if (state.routes.size()+prefixes.size()+(gateway.isEmpty() ? 0 : 1)>LinuxRouteSnapshotRows || state.rules.size()+1>LinuxRouteSnapshotRows)
            return {Status::Failed,"Source routes exceed complete snapshot capacity."};
        for (const auto &value : state.routes)
            if (value.toObject()["table"]==QString::number(table)) return {Status::Failed,"An existing route table cannot be adopted."};
        for (const auto &value : state.rules) {
            const auto row = value.toObject();
            if (row["table"]==QString::number(table) || (row["priority"].toInteger()<=1 && !localRule(row)))
                return {Status::Failed,"An existing early rule or table reference cannot be adopted."};
        }
        return {};
    };
    const auto before = available(read(utility,deadline));
    if (!before.succeeded()) return before;
    if (!identity() || !sourceAssigned()) return {Status::Failed,"Original interface/source changed before application."};
    if (!gateway.isEmpty()) entries.append({gateway + "/32",{}});
    for (const auto &prefix : prefixes) entries.append({prefix,{}});
    rulePending = true;
    if (writeAhead) {
        const auto saved = saveCheckpoint(writeAhead);
        if (!saved.succeeded()) { if (!saved.mayHaveChanged) clear();return saved; }
        auto checked = available(read(utility,deadline));
        if (checked.succeeded() && (!identity() || !sourceAssigned())) checked = {Status::Failed,"Original interface/source changed during checkpoint publication."};
        if (!checked.succeeded()) { checked.mayHaveChanged = true;return checked; }
    }
    QByteArray batch;
    for (const auto &entry : entries) batch += routeCommand("add",entry.prefix);
    batch += ruleCommand("add");
    auto result = write(utility,batch,deadline);
    const auto after = read(utility,deadline);
    bool confirmed = after.result.succeeded();
    if (confirmed) {
        for (auto &entry : entries) {
            const auto row = findRoute(after,entry.prefix);
            if (routeShape(row,entry.prefix)) entry.applied = row; else confirmed = false;
        }
        const auto rule = findRule(after.rules);
        if (ruleShape(rule)) appliedRule = rule; else confirmed = false;
        int count = 0;
        for (const auto &value : after.routes) count += value.toObject()["table"] == QString::number(table);
        if (count != entries.size()) confirmed = false;
        int references = 0;
        for (const auto &value : after.rules) {
            const auto row = value.toObject();
            if (row["table"] == QString::number(table)) { ++references;if (row != appliedRule) confirmed = false; }
            if (row["priority"].toInteger() <= 1 && row != appliedRule && !localRule(row)) confirmed = false;
        }
        if (references != 1) confirmed = false;
        confirmed &= identity() && sourceAssigned();
    }
    if (result.succeeded() && confirmed) {
        const auto saved = saveCheckpoint(writeAhead);
        if (saved.succeeded()) return {Status::Success,{},true};
        result = saved;
    }
    if (result.succeeded()) result = after.result.succeeded()
        ? PlatformOperationResult{Status::Failed,"Cannot confirm owned source routes/rule."} : after.result;
    const auto recovered = restore(id,writeAhead);
    result.mayHaveChanged = true;
    if (!recovered.succeeded()) result.detail += " Recovery incomplete; source ownership records retained.";
    return result;
}
PlatformOperationResult LinuxSourceRoutes::extend(const QUuid &id, const QStringList &addresses, const CheckpointWriter &checkpoint)
{
    const auto invalid = PlatformOperationResult{Status::Failed,"DNS addresses require confirmed source route ownership."};
    if (id.isNull() || id != owner || !rulePending || ruleDeleting || appliedRule.isEmpty()
        || addresses.isEmpty() || addresses.size() > LinuxRouteSnapshotRows) return invalid;
    for (const auto &entry : entries) if (entry.deleting || entry.applied.isEmpty()) return invalid;
    QStringList prefixes;
    for (const auto &address : addresses) {
        if (!canonicalUnicastIpv4(address) || address == sourceAddress || address == gatewayAddress) return invalid;
        bool covered = false;
        for (const auto &entry : entries) covered |= ipv4PrefixContainsAddress(entry.prefix,address);
        if (!covered) prefixes.append(address+"/32");
    }
    return ensurePrefixes(id, prefixes, checkpoint);
}

PlatformOperationResult LinuxSourceRoutes::ensurePrefixes(const QUuid &id, const QStringList &requested, const CheckpointWriter &checkpoint)
{
    const auto invalid = PlatformOperationResult{Status::Failed,"Route additions require confirmed source ownership."};
    if (id.isNull() || id != owner || !rulePending || ruleDeleting || appliedRule.isEmpty()
        || requested.size() > LinuxRouteSnapshotRows) return invalid;
    for (const auto &entry : entries) if (entry.deleting || entry.applied.isEmpty()) return invalid;
    QStringList prefixes;
    for (const auto &prefix : requested) {
        if (!canonicalIpv4Prefix(prefix) || prefix == gatewayAddress + "/32") return invalid;
        bool present = false;
        for (const auto &entry : entries) present |= entry.prefix == prefix;
        if (!present) prefixes.append(prefix);
    }
    prefixes.removeDuplicates();
    if (entries.size()+prefixes.size() > LinuxRouteSnapshotRows) return invalid;
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto existing = entries;
    const auto verify = [&](const ReadResult &state) -> PlatformOperationResult {
        if (!state.result.succeeded()) return state.result;
        if (!identity() || !sourceAssigned() || state.routes.size()+prefixes.size() > LinuxRouteSnapshotRows) return invalid;
        int routes = 0, rules = 0;
        for (const auto &row : state.routes) routes += row.toObject()["table"] == QString::number(table);
        for (const auto &value : state.rules) {
            const auto row = value.toObject();
            if (row["table"] == QString::number(table)) {
                if (row != appliedRule) return invalid;
                ++rules;
            }
            if (row["priority"].toInteger() <= 1 && row != appliedRule && !localRule(row)) return invalid;
        }
        if (routes != existing.size() || rules != 1) return invalid;
        for (const auto &entry : existing)
            if (!sameLinuxRoute(findRoute(state,entry.prefix),entry.applied)) return invalid;
        return {};
    };
    if (auto result = verify(read(utility,deadline)); !result.succeeded()) return result;
    if (prefixes.isEmpty()) return {};
    QByteArray batch;
    for (const auto &prefix : prefixes) { entries.append({prefix,{}}); batch += routeCommand("add",prefix); }
    const auto abandon = [&](PlatformOperationResult result) {
        entries = existing;
        const auto saved = saveCheckpoint(checkpoint);
        if (!saved.succeeded()) result = saved;
        result.mayHaveChanged = true;
        return result;
    };
    if (auto result = saveCheckpoint(checkpoint); !result.succeeded()) return abandon(result);
    if (auto result = verify(read(utility,deadline)); !result.succeeded()) return abandon(result);
    bool attempted = false;
    auto result = write(utility,batch,deadline,false,&attempted);
    if (!attempted) return abandon(result);
    const auto after = read(utility,deadline);
    bool confirmed = after.result.succeeded() && identity() && sourceAssigned();
    if (after.result.succeeded()) {
        int routes = 0, rules = 0;
        for (const auto &row : after.routes) routes += row.toObject()["table"] == QString::number(table);
        for (const auto &value : after.rules) {
            const auto row = value.toObject();
            if (row["table"] == QString::number(table)) { ++rules; confirmed &= row == appliedRule; }
            if (row["priority"].toInteger() <= 1 && row != appliedRule && !localRule(row)) confirmed = false;
        }
        confirmed &= routes == entries.size() && rules == 1;
        for (const auto &entry : existing) confirmed &= sameLinuxRoute(findRoute(after,entry.prefix),entry.applied);
        confirmed &= findRule(after.rules) == appliedRule;
        for (qsizetype index = existing.size(); index < entries.size(); ++index) {
            auto &entry = entries[index];
            const auto row = findRoute(after,entry.prefix);
            if (routeShape(row,entry.prefix)) entry.applied = row; else confirmed = false;
        }
    }
    if (const auto saved = saveCheckpoint(checkpoint); !saved.succeeded()) result = saved;
    if (result.succeeded() && !confirmed) result = after.result.succeeded() ? invalid : after.result;
    result.mayHaveChanged = true;
    return result;
}

PlatformOperationResult LinuxSourceRoutes::restore(const QUuid &id, const CheckpointWriter &checkpoint)
{
    if (owner.isNull()) return {};
    if (id!=owner) return {Status::Failed,"Source route owner changed.",true};
    const auto failedRecovery = [](PlatformOperationResult result) { result.mayHaveChanged = true;return result; };
    const auto complete = [&](bool external) {
        const auto saved = checkpoint ? checkpoint(QJsonObject{}) : PlatformOperationResult{};
        if (!saved.succeeded()) return failedRecovery(saved);
        clear();
        return PlatformOperationResult{Status::Success,external ? QString("External source route changes were preserved.") : QString{}};
    };
    if (entries.isEmpty() && !rulePending) return complete(false);
    if (!identity()) return {Status::Failed,"Source route namespace or original interface identity changed.",true};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required.",true};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto references = [&](const ReadResult &state, const QJsonObject &expected) {
        int count = 0;
        for (const auto &value : state.rules) {
            const auto row = value.toObject();
            if (row["table"]==QString::number(table)) {
                if (expected.isEmpty() || row!=expected) return false;
                ++count;
            }
        }
        return expected.isEmpty() ? count==0 : count==1;
    };
    auto before = read(utility,deadline);
    if (!before.result.succeeded()) return failedRecovery(before.result);
    const auto currentRule = findRule(before.rules);
    const auto expected = rulePending && (appliedRule.isEmpty() ? ruleShape(currentRule) : currentRule==appliedRule)
        ? currentRule : QJsonObject{};
    if (!references(before,expected)) return {Status::Failed,"External or ambiguous rule references the owned table; records retained without writes.",true};
    if (ruleDeleting && !currentRule.isEmpty())
        return {Status::Failed,"Interrupted source rule deletion is unresolved; matching state is preserved.",true};
    bool external = false, released = false;
    if (rulePending && currentRule.isEmpty())
        for (const auto &value : before.rules) external |= value.toObject()["priority"]==1;
    if (!identity()) return {Status::Failed,"Original interface renamed while reading recovery state.",true};
    if (rulePending && !currentRule.isEmpty()) {
        appliedRule = currentRule;ruleDeleting = true;
        const auto saved = saveCheckpoint(checkpoint);
        if (!saved.succeeded()) { ruleDeleting = false;return failedRecovery(saved); }
        if (checkpoint) {
            const auto verified = read(utility,deadline);
            if (!verified.result.succeeded() || !identity() || !references(verified,appliedRule)) {
                ruleDeleting = false;
                return verified.result.succeeded() ? PlatformOperationResult{Status::Failed,"Source rule changed during deletion checkpoint publication.",true}
                    : failedRecovery(verified.result);
            }
        }
        const auto removed = write(utility,ruleCommand("del"),deadline);
        if (removed.succeeded()) {
            rulePending = false;ruleDeleting = false;appliedRule = {};
            const auto savedRelease = saveCheckpoint(checkpoint);
            if (!savedRelease.succeeded()) return failedRecovery(savedRelease);
            released = true;
        }
        before = read(utility,deadline);
        if (!before.result.succeeded()) return failedRecovery(before.result);
        if (!references(before,{})) return {removed.succeeded() ? Status::Failed : removed.status,
            "Source lookup remains or changed; its route table is retained.",true};
    }
    rulePending = false;ruleDeleting = false;appliedRule = {};
    if (!released) {
        const auto savedRelease = saveCheckpoint(checkpoint);
        if (!savedRelease.succeeded()) return failedRecovery(savedRelease);
    }
    QByteArray batch;
    QSet<QString> prefixes, planned;
    for (const auto &entry : entries) prefixes.insert(entry.prefix);
    for (const auto &value : before.routes) {
        const auto row = value.toObject();
        if (row["table"]==QString::number(table) && (!prefixes.contains(ipv4RoutePrefix(row))
            || findRoute(before,ipv4RoutePrefix(row))!=row)) external = true;
    }
    bool unresolved = false;
    // Delete next-hop routes last, after removing the source lookup and its destination routes.
    for (int i=entries.size()-1; i>=0; --i) {
        auto &entry = entries[i];
        const auto current = findRoute(before,entry.prefix);
        if (current.isEmpty() || (!entry.applied.isEmpty() && !sameLinuxRoute(current,entry.applied))) {
            external |= !current.isEmpty();entries.removeAt(i);
        } else if (entry.deleting) unresolved = true;
        else if (entry.applied.isEmpty() && !routeShape(current,entry.prefix)) continue;
        else { entry.applied = current;planned.insert(entry.prefix);batch += routeCommand("del",entry.prefix); }
    }
    if (unresolved) {
        const auto saved = saveCheckpoint(checkpoint);
        return saved.succeeded() ? PlatformOperationResult{Status::Failed,"Interrupted source route deletion is unresolved; matching state is preserved.",true}
            : failedRecovery(saved);
    }
    if (!identity()) return {Status::Failed,"Original interface renamed before source recovery.",true};
    PlatformOperationResult removed;
    if (!batch.isEmpty()) {
        for (auto &entry : entries) if (planned.contains(entry.prefix)) entry.deleting = true;
        const auto saved = saveCheckpoint(checkpoint);
        if (!saved.succeeded()) {
            for (auto &entry : entries) if (planned.contains(entry.prefix)) entry.deleting = false;
            return failedRecovery(saved);
        }
        if (checkpoint) {
            const auto verified = read(utility,deadline);
            bool unchanged = verified.result.succeeded() && identity() && references(verified,{});
            for (const auto &entry : entries)
                if (planned.contains(entry.prefix)) unchanged &= sameLinuxRoute(findRoute(verified,entry.prefix),entry.applied);
            if (!unchanged) {
                for (auto &entry : entries) if (planned.contains(entry.prefix)) entry.deleting = false;
                return verified.result.succeeded() ? PlatformOperationResult{Status::Failed,"Source routes or references changed during deletion checkpoint publication.",true}
                    : failedRecovery(verified.result);
            }
        }
        removed = write(utility,batch,deadline,true);
    }
    const auto after = read(utility,deadline);
    if (!after.result.succeeded()) return failedRecovery(after.result);
    for (auto it=entries.begin(); it!=entries.end();) {
        const auto current = findRoute(after,it->prefix);
        if (current.isEmpty() || (!it->applied.isEmpty() && !sameLinuxRoute(current,it->applied))
            || (planned.contains(it->prefix) && removed.succeeded())) {
            external |= !current.isEmpty();it = entries.erase(it);
        } else ++it;
    }
    if (!entries.isEmpty()) {
        const auto saved = saveCheckpoint(checkpoint);
        if (!saved.succeeded()) return failedRecovery(saved);
        return {removed.succeeded() ? Status::Failed : removed.status,"Cannot confirm source route recovery; ownership records retained.",true};
    }
    for (const auto &value : after.routes) external |= value.toObject()["table"]==QString::number(table);
    return complete(external);
}
