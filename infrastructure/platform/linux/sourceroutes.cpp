#include "sourceroutes.h"
#include "iprouteutility.h"
#include <QJsonDocument>
#include <QFile>
#include <QRegularExpression>
#include <QScopeGuard>
#include <QSet>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/stat.h>

namespace {
using Status = PlatformOperationResult::Status;
QString currentNamespace()
{
    struct stat identity{};
    QFile boot("/proc/sys/kernel/random/boot_id");
    if (::stat("/proc/thread-self/ns/net",&identity)!=0 || !boot.open(QIODevice::ReadOnly)) return {};
    const auto id = QString::fromLatin1(boot.read(64)).trimmed();
    if (QUuid(id).isNull() || QUuid(id).toString(QUuid::WithoutBraces)!=id) return {};
    return id+":"+QString::number(identity.st_dev)+":"+QString::number(identity.st_ino);
}
bool unicast(const QString &value)
{
    if (!canonicalIpv4Prefix(value + "/32")) return false;
    const int first = value.section('.',0,0).toInt();
    return first > 0 && first < 224 && first != 127;
}
bool sameRoute(QJsonObject current, QJsonObject saved)
{
    for (auto *row : {&current,&saved}) {
        if (!(*row)["flags"].isArray()) return false;
        for (const auto &flag : (*row)["flags"].toArray()) if (flag != "linkdown") return false;
        row->remove("flags");
        if ((*row)["type"] == "unicast") row->remove("type");
    }
    return current == saved;
}
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
PlatformOperationResult write(const QString &utility, const QByteArray &batch, const QDeadlineTimer &deadline, bool recovering = false)
{
    if (deadline.hasExpired()) return {Status::TimedOut,"Source route operation deadline expired."};
    const QStringList args = recovering ? QStringList{"-4","-force","-batch","-"} : QStringList{"-4","-batch","-"};
    return runPlatformCommand(utility,args,int(deadline.remainingTime()),batch).result;
}
}

bool LinuxSourceRoutes::identity() const
{
    return interfaceIndex && !networkNamespace.isEmpty() && currentNamespace()==networkNamespace
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
        const auto document = bytes.size() <= 1024*1024 && !command.output.contains(QChar::ReplacementCharacter)
            ? QJsonDocument::fromJson(bytes) : QJsonDocument{};
        if (!document.isArray() || document.array().size() > 4096)
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
    entries.clear();appliedRule = {};rulePending = false;owner = {};
    interfaceName.clear();sourceAddress.clear();gatewayAddress.clear();networkNamespace.clear();interfaceIndex = table = metric = 0;
}
QJsonObject LinuxSourceRoutes::snapshot() const
{
    if (owner.isNull()) return {};
    QJsonArray routes;
    for (const auto &entry : entries) routes.append(QJsonObject{{"prefix",entry.prefix},{"before",QJsonArray{}},{"applied",entry.applied}});
    return {{"owner",owner.toString(QUuid::WithoutBraces)},{"namespace",networkNamespace},{"interface",interfaceName},{"index",qint64(interfaceIndex)},
        {"source",sourceAddress},{"gateway",gatewayAddress},{"table",qint64(table)},{"priority",1},{"metric",qint64(metric)},
        {"routes",routes},{"rule_pending",rulePending},{"rule_before",QJsonArray{}},{"rule_applied",appliedRule}};
}
PlatformOperationResult LinuxSourceRoutes::recover(const QUuid &id, const QJsonObject &saved)
{
    if (!owner.isNull()) return {Status::Failed,"Active source ownership cannot be replaced by a saved record."};
    const auto invalid = PlatformOperationResult{Status::Failed,"Invalid saved source route ownership."};
    if (id.isNull() || saved.size()!=13 || saved["owner"]!=id.toString(QUuid::WithoutBraces)
        || QJsonDocument(saved).toJson(QJsonDocument::Compact).size()>MaxSnapshotBytes
        || !saved["interface"].isString() || !saved["source"].isString() || !saved["gateway"].isString()
        || !QRegularExpression("^[A-Za-z0-9_.-]{1,15}$").match(saved["interface"].toString()).hasMatch()
        || !unicast(saved["source"].toString()) || (!saved["gateway"].toString().isEmpty() && !unicast(saved["gateway"].toString()))
        || saved["source"]==saved["gateway"] || saved["index"].toInteger(-1)<=0 || saved["index"].toInteger()>0xffffffffLL
        || saved["priority"]!=1 || !saved["routes"].isArray() || saved["routes"].toArray().size()>4096
        || !saved["rule_pending"].isBool() || !saved["rule_before"].isArray() || !saved["rule_before"].toArray().isEmpty()
        || !saved["rule_applied"].isObject()) return invalid;
    const auto namespaceId = currentNamespace();
    if (namespaceId.isEmpty() || saved["namespace"]!=namespaceId) return invalid;
    const auto hash = id.toByteArray(QUuid::Id128).left(8).toUInt(nullptr,16);
    if (saved["table"].toInteger(-1)!=1000000000u+hash%1000000000u
        || saved["metric"].toInteger(-1)!=1u+hash%0xfffffffeu) return invalid;
    bool accepted = false;
    const auto discard = qScopeGuard([&] { if (!accepted) clear(); });
    owner = id;networkNamespace = namespaceId;interfaceName = saved["interface"].toString();interfaceIndex = quint32(saved["index"].toInteger());
    sourceAddress = saved["source"].toString();gatewayAddress = saved["gateway"].toString();
    table = quint32(saved["table"].toInteger());metric = quint32(saved["metric"].toInteger());
    rulePending = saved["rule_pending"].toBool();appliedRule = saved["rule_applied"].toObject();
    if (!appliedRule.isEmpty() && (!rulePending || !ruleShape(appliedRule) || findRule(QJsonArray{appliedRule})!=appliedRule)) return invalid;
    QSet<QString> prefixes;
    for (const auto &value : saved["routes"].toArray()) {
        const auto entry = value.toObject();
        const auto prefix = entry["prefix"].toString();
        if (!value.isObject() || entry.size()!=3 || !canonicalIpv4Prefix(prefix) || prefixes.contains(prefix)
            || !entry["before"].isArray() || !entry["before"].toArray().isEmpty() || !entry["applied"].isObject()
            || (prefix==gatewayAddress+"/32" && !entries.isEmpty())) return invalid;
        const auto row = entry["applied"].toObject();
        if (!row.isEmpty() && (!routeShape(row,prefix) || ipv4RoutePrefix(row)!=prefix || row["dev"]!=interfaceName
            || row["table"]!=QString::number(table) || row["protocol"]!="4" || row["metric"].toInteger(-1)!=metric)) return invalid;
        prefixes.insert(prefix);entries.append({prefix,row});
    }
    accepted = true;
    return restore(id);
}
PlatformOperationResult LinuxSourceRoutes::apply(const QUuid &id, const QString &interface, const QString &source,
                                                const QString &gateway, const QStringList &requested)
{
    if (!owner.isNull() || id.isNull()) return {Status::Failed,"Source route ownership is missing or already active."};
    if (!QRegularExpression("^[A-Za-z0-9_.-]{1,15}$").match(interface).hasMatch()
        || !unicast(source) || (!gateway.isEmpty() && !unicast(gateway)) || source == gateway || requested.isEmpty() || requested.size() > 4096)
        return {Status::Failed,"Invalid original interface, source, gateway or target count."};
    auto prefixes = requested;
    for (const auto &prefix : prefixes)
        if (!canonicalIpv4Prefix(prefix) || prefix == gateway + "/32") return {Status::Failed,"Invalid original destination prefix."};
    prefixes.removeDuplicates();
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    const auto namespaceId = currentNamespace();
    if (namespaceId.isEmpty()) return {Status::Failed,"Cannot identify the Linux boot and network namespace."};
    owner = id;networkNamespace = namespaceId;interfaceName = interface;sourceAddress = source;gatewayAddress = gateway;
    interfaceIndex = ::if_nametoindex(interfaceName.toLatin1().constData());
    const auto hash = id.toByteArray(QUuid::Id128).left(8).toUInt(nullptr,16);
    table = 1000000000u + hash % 1000000000u;metric = 1u + hash % 0xfffffffeu;
    const auto discard = qScopeGuard([&] { if (entries.isEmpty() && !rulePending) clear(); });
    if (!identity() || !sourceAssigned()) return {Status::Failed,"Original source is not assigned to the selected live interface."};
    QDeadlineTimer deadline(10000);
    const auto before = read(utility,deadline);
    if (!before.result.succeeded()) return before.result;
    if (before.routes.size() + prefixes.size() + (gateway.isEmpty() ? 0 : 1) > 4096 || before.rules.size() + 1 > 4096)
        return {Status::Failed,"Source routes exceed complete snapshot capacity."};
    for (const auto &value : before.routes)
        if (value.toObject()["table"] == QString::number(table)) return {Status::Failed,"An existing route table cannot be adopted."};
    for (const auto &value : before.rules) {
        const auto row = value.toObject();
        if (row["table"] == QString::number(table) || (row["priority"].toInteger() <= 1
            && !localRule(row)))
            return {Status::Failed,"An existing early rule or table reference cannot be adopted."};
    }
    if (!identity() || !sourceAssigned()) return {Status::Failed,"Original interface/source changed before application."};
    if (!gateway.isEmpty()) entries.append({gateway + "/32",{}});
    for (const auto &prefix : prefixes) entries.append({prefix,{}});
    rulePending = true;
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
    if (result.succeeded() && confirmed) return {Status::Success,{},true};
    if (result.succeeded()) result = after.result.succeeded()
        ? PlatformOperationResult{Status::Failed,"Cannot confirm owned source routes/rule."} : after.result;
    const auto recovered = restore(id);
    result.mayHaveChanged = true;
    if (!recovered.succeeded()) result.detail += " Recovery incomplete; source ownership records retained.";
    return result;
}
PlatformOperationResult LinuxSourceRoutes::restore(const QUuid &id)
{
    if (owner.isNull()) return {};
    if (id != owner || !identity()) return {Status::Failed,"Source route owner, namespace or original interface identity changed.",true};
    const auto utility = trustedIpRouteUtility();
    if (utility.isEmpty()) return {Status::Unsupported,"A trusted system iproute2 executable is required.",true};
    QDeadlineTimer deadline(10000);
    auto before = read(utility,deadline);
    if (!before.result.succeeded()) { auto error = before.result;error.mayHaveChanged = true;return error; }
    const auto currentRule = findRule(before.rules);
    int references = 0;
    for (const auto &value : before.rules) {
        const auto row = value.toObject();
        references += row["table"] == QString::number(table);
        if (row["table"] == QString::number(table) && (row != currentRule || !rulePending
            || (appliedRule.isEmpty() ? !ruleShape(row) : row != appliedRule)))
            return {Status::Failed,"External rule references the owned table; records retained without writes.",true};
    }
    if (references > 1) return {Status::Failed,"Ambiguous source table references; records retained without writes.",true};
    bool external = false;
    if (rulePending && currentRule.isEmpty())
        for (const auto &value : before.rules) external |= value.toObject()["priority"]==1;
    if (!identity()) return {Status::Failed,"Original interface renamed while reading recovery state.",true};
    if (rulePending && !currentRule.isEmpty()) {
        appliedRule = currentRule;
        const auto removed = write(utility,ruleCommand("del"),deadline);
        if (removed.succeeded()) { rulePending = false;appliedRule = {}; }
        before = read(utility,deadline);
        if (!before.result.succeeded()) { auto error = before.result;error.mayHaveChanged = true;return error; }
        for (const auto &value : before.rules)
            if (value.toObject()["table"] == QString::number(table))
                return {removed.succeeded() ? Status::Failed : removed.status,
                    "Source lookup remains or changed; its route table is retained.",true};
    }
    rulePending = false;appliedRule = {};
    QByteArray batch;
    QSet<QString> prefixes;
    for (const auto &entry : entries) prefixes.insert(entry.prefix);
    for (const auto &value : before.routes) {
        const auto row = value.toObject();
        if (row["table"] == QString::number(table) && (!prefixes.contains(ipv4RoutePrefix(row))
            || findRoute(before,ipv4RoutePrefix(row)) != row)) external = true;
    }
    // Delete next-hop routes last, after removing the source lookup and its destination routes.
    for (int i = entries.size()-1; i >= 0; --i) {
        auto &entry = entries[i];
        const auto current = findRoute(before,entry.prefix);
        if (current.isEmpty() || (!entry.applied.isEmpty() && !sameRoute(current,entry.applied))) {
            external |= !current.isEmpty();entries.removeAt(i);
        } else if (entry.applied.isEmpty() && !routeShape(current,entry.prefix)) continue;
        else { entry.applied = current;batch += routeCommand("del",entry.prefix); }
    }
    if (!identity()) return {Status::Failed,"Original interface renamed before source recovery.",true};
    PlatformOperationResult removed;
    if (!batch.isEmpty()) removed = write(utility,batch,deadline,true);
    const auto after = read(utility,deadline);
    if (!after.result.succeeded()) { auto error = after.result;error.mayHaveChanged = true;return error; }
    const auto remainingRule = findRule(after.rules);
    if (remainingRule.isEmpty()) { rulePending = false;appliedRule = {}; }
    for (auto it = entries.begin(); it != entries.end();) {
        const auto current = findRoute(after,it->prefix);
        if (current.isEmpty() || (!it->applied.isEmpty() && !sameRoute(current,it->applied))) {
            external |= !current.isEmpty();it = entries.erase(it);
        } else ++it;
    }
    if (rulePending || !entries.isEmpty()) return {removed.succeeded() ? Status::Failed : removed.status,
        "Cannot confirm source route recovery; ownership records retained.",true};
    clear();
    return {Status::Success,external ? QString("External source route changes were preserved.") : QString{}};
}
