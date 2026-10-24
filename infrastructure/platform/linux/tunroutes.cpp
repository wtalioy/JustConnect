#include "tunroutes.h"
#include <QDeadlineTimer>
#include <QJsonDocument>
#include <QScopeGuard>
#include <QSet>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>

namespace {
using Result = PlatformOperationResult;
using Status = Result::Status;
Result write(const QString &utility, const QByteArray &batch, const QDeadlineTimer &deadline, bool recovering = false, bool *attempted = nullptr)
{
    const int remaining = int(deadline.remainingTime());
    if (remaining <= 0) return {Status::TimedOut, "Route batch deadline expired."};
    const QStringList args = recovering ? QStringList{"-4", "-force", "-batch", "-"} : QStringList{"-4", "-batch", "-"};
    if(attempted)*attempted=true;
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
    const auto document = bytes.size() <= LinuxRouteSnapshotBytes && !result.output.contains(QChar::ReplacementCharacter)
        ? QJsonDocument::fromJson(bytes) : QJsonDocument{};
    if (!document.isArray() || document.array().size() > LinuxRouteSnapshotRows)
        return {{Status::Failed, "Cannot read a complete route snapshot."}, {}};
    QSet<QString> owned;
    for (const auto &value : document.array()) {
        const auto row=value.toObject();const auto prefix=ipv4RoutePrefix(row);
        if (!value.isObject() || !row["dst"].isString() || !canonicalIpv4Prefix(prefix,0))
            return {{Status::Failed, "Invalid route snapshot."}, {}};
        if(row["dev"]==interfaceName && row["protocol"]==QString::number(RTPROT_STATIC) && row["metric"].toInteger(-1)==metric) {
            if(owned.contains(prefix))return {{Status::Failed,"Ambiguous owned capture route."},{}};
            owned.insert(prefix);
        }
    }
    return {{}, document.array()};
}

bool LinuxTunRoutes::identity() const
{
    return interfaceIndex && !networkNamespace.isEmpty() && linuxNetworkNamespace()==networkNamespace
        && ::if_nametoindex(interfaceName.toLatin1().constData())==interfaceIndex;
}
bool LinuxTunRoutes::owns(const UnixTunDevice &device) const
{
    return device.descriptor() >= 0 && device.owner() == owner && device.name() == interfaceName
        && device.index() == interfaceIndex && identity();
}
QJsonObject LinuxTunRoutes::find(const QJsonArray &rows, const QString &prefix) const
{
    for (const auto &value : rows) {
        const auto row = value.toObject();
        if (ipv4RoutePrefix(row) == prefix && row["dev"] == interfaceName && row["protocol"] == QString::number(RTPROT_STATIC)
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
    entries.clear();owner={};interfaceName.clear();sourceAddress.clear();gatewayPeer.clear();networkNamespace.clear();
    interfaceIndex=metric=0;legacy=false;
}
QJsonObject LinuxTunRoutes::snapshot() const
{
    if (!legacy) {
        auto record = capture.snapshot();
        if (!record.isEmpty()) record["version"] = 2;
        return record;
    }
    if (owner.isNull()) return {};
    QJsonArray routes;
    for (const auto &entry : entries)
        routes.append(QJsonObject{{"prefix",entry.prefix},{"before",QJsonArray{}},{"applied",entry.applied},{"delete_started",entry.deleting}});
    return {{"version",1},{"owner",owner.toString(QUuid::WithoutBraces)},{"namespace",networkNamespace},{"interface",interfaceName},
        {"index",qint64(interfaceIndex)},{"source",sourceAddress},{"peer",gatewayPeer},{"metric",qint64(metric)},{"routes",routes}};
}
Result LinuxTunRoutes::saveCheckpoint(const CheckpointWriter &checkpoint) const
{
    if(!checkpoint)return {};
    const auto record=snapshot();
    if(QJsonDocument(record).toJson(QJsonDocument::Compact).size()>MaxSnapshotBytes)
        return {Status::Failed,"Capture ownership record exceeds its budget."};
    return checkpoint(record);
}
Result LinuxTunRoutes::recover(const QUuid &id, const QJsonObject &saved, const CheckpointWriter &checkpoint)
{
    if(!owner.isNull() || !capture.snapshot().isEmpty())return {Status::Failed,"Active capture ownership cannot be replaced."};
    if (saved["version"] == 2) {
        if (saved.size() != 15) return {Status::Failed,"Invalid saved capture lookup."};
        auto lookup = saved;lookup.remove("version");
        return capture.recover(id,lookup,captureWriter(checkpoint));
    }
    const Result invalid{Status::Failed,"Invalid saved capture route ownership."};
    if(id.isNull() || saved.size()!=9 || saved["version"]!=1 || saved["owner"]!=id.toString(QUuid::WithoutBraces)
        || QJsonDocument(saved).toJson(QJsonDocument::Compact).size()>MaxSnapshotBytes
        || saved["interface"]!=QString::fromLatin1(linuxTunName(id)) || saved["index"].toInteger(-1)<=0 || saved["index"].toInteger()>0xffffffffLL
        || !canonicalUnicastIpv4(saved["source"].toString()) || !canonicalUnicastIpv4(saved["peer"].toString()) || saved["source"]==saved["peer"]
        || saved["metric"].toInteger(-1)!=linuxRouteMetric(id) || !saved["routes"].isArray() || saved["routes"].toArray().size()>LinuxRouteSnapshotRows)
        return invalid;
    const auto namespaceId=linuxNetworkNamespace();
    if(namespaceId.isEmpty() || saved["namespace"]!=namespaceId)return invalid;
    const auto liveIndex=::if_nametoindex(saved["interface"].toString().toLatin1().constData());
    if(liveIndex && liveIndex!=quint32(saved["index"].toInteger()))return invalid;
    bool accepted=false;const auto discard=qScopeGuard([&]{if(!accepted)clear();});
    owner=id;networkNamespace=namespaceId;interfaceName=saved["interface"].toString();interfaceIndex=quint32(saved["index"].toInteger());
    sourceAddress=saved["source"].toString();gatewayPeer=saved["peer"].toString();metric=linuxRouteMetric(id);
    QSet<QString> prefixes;
    for(const auto &value:saved["routes"].toArray()) {
        const auto entry=value.toObject();const auto prefix=entry["prefix"].toString();const auto row=entry["applied"].toObject();
        if(!value.isObject() || entry.size()!=4 || !canonicalIpv4Prefix(prefix) || prefixes.contains(prefix)
            || !entry["before"].isArray() || !entry["before"].toArray().isEmpty() || !entry["applied"].isObject() || !entry["delete_started"].isBool()
            || (!row.isEmpty() && (!createdShape(row) || find(QJsonArray{row},prefix)!=row))
            || (entry["delete_started"].toBool() && row.isEmpty()))return invalid;
        prefixes.insert(prefix);entries.append({prefix,row,entry["delete_started"].toBool()});
    }
    accepted=true;legacy=true;return restore(id,checkpoint);
}
LinuxTunRoutes::CheckpointWriter LinuxTunRoutes::captureWriter(const CheckpointWriter &checkpoint) const
{
    if (!checkpoint) return {};
    return [checkpoint](const QJsonObject &lookup) {
        auto record = lookup;
        if (!record.isEmpty()) record["version"] = 2;
        return checkpoint(record);
    };
}
bool LinuxTunRoutes::validDevice(const UnixTunDevice &device) const
{
    const auto saved = capture.snapshot();
    return !legacy && !saved.isEmpty() && device.owner().toString(QUuid::WithoutBraces) == saved["owner"]
        && device.descriptor() >= 0 && device.name() == saved["interface"] && device.index() == saved["index"].toInteger()
        && assignedLinuxTunPair(device.name(),device.index(),saved["source"].toString(),gatewayPeer);
}
Result LinuxTunRoutes::validatePrefixes(const QStringList &prefixes) const
{
    if (prefixes.size() > LinuxRouteSnapshotRows) return {Status::Failed,"Too many capture routes."};
    for (const auto &prefix : prefixes)
        if (!canonicalIpv4Prefix(prefix) || ipv4PrefixContainsAddress(prefix,sourceAddress) || ipv4PrefixContainsAddress(prefix,gatewayPeer))
            return {Status::Failed,"Capture prefixes must be canonical and exclude the owned TUN endpoints."};
    return {};
}
Result LinuxTunRoutes::apply(const UnixTunDevice &device, const QString &source, const QString &peer,
                             const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    if (legacy || !capture.snapshot().isEmpty()) return {Status::Failed,"Owned routes must be restored before another apply."};
    if (device.owner().isNull() || device.descriptor() < 0 || device.name() != QString::fromLatin1(linuxTunName(device.owner()))
        || !assignedLinuxTunPair(device.name(),device.index(),source,peer))
        return {Status::Failed,"Capture requires an exclusively owned live TUN and its assigned endpoints."};
    sourceAddress = source;gatewayPeer = peer;
    if (auto valid = validatePrefixes(prefixes); !valid.succeeded()) return valid;
    if (prefixes.isEmpty()) return {};
    return capture.apply(device.owner(),device.name(),source,{},prefixes,captureWriter(checkpoint));
}
Result LinuxTunRoutes::extend(const UnixTunDevice &device, const QStringList &addresses, const CheckpointWriter &checkpoint)
{
    if (!validDevice(device) || addresses.contains(gatewayPeer)) return {Status::Failed,"DNS capture requires the active owned TUN."};
    return capture.extend(device.owner(),addresses,captureWriter(checkpoint));
}
Result LinuxTunRoutes::reconcile(const UnixTunDevice &device, const QStringList &prefixes, const CheckpointWriter &checkpoint)
{
    if (!validDevice(device)) return {Status::Failed,"Capture replacement requires the active owned TUN."};
    if (auto valid = validatePrefixes(prefixes); !valid.succeeded()) return valid;
    return capture.reconcile(device.owner(),prefixes,captureWriter(checkpoint));
}
Result LinuxTunRoutes::restore(const UnixTunDevice &device, const CheckpointWriter &checkpoint)
{
    if (!legacy) {
        if (capture.snapshot().isEmpty()) return {};
        if (device.owner().toString(QUuid::WithoutBraces) != capture.snapshot()["owner"] || device.descriptor() < 0)
            return {Status::Failed,"Route ownership no longer matches the active TUN device.",true};
        return capture.restore(device.owner(),captureWriter(checkpoint));
    }
    if(owner.isNull())return {};
    if(!owns(device))return {Status::Failed,"Route ownership no longer matches the active TUN device.",true};
    return restore(owner,checkpoint);
}
Result LinuxTunRoutes::restore(const QUuid &id, const CheckpointWriter &checkpoint)
{
    if(owner.isNull())return {};
    if(id!=owner || linuxNetworkNamespace()!=networkNamespace)return {Status::Failed,"Capture owner or network namespace changed.",true};
    const auto failed=[](Result result){result.mayHaveChanged=true;return result;};
    const auto complete=[&](bool external) {
        const auto result=checkpoint?checkpoint(QJsonObject{}):Result{};
        if(!result.succeeded())return failed(result);
        clear();
        return Result{Status::Success,external?QString("External route changes were preserved."):QString{}};
    };
    // Only recovery of v1 main-table records uses this path.
    if(entries.isEmpty())return complete(false);
    const auto utility=trustedIpRouteUtility();if(utility.isEmpty())return {Status::Unsupported,"A trusted system iproute2 executable is required.",true};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);const auto before=read(utility,int(deadline.remainingTime()));
    if(!before.result.succeeded())return failed(before.result);
    bool external=false,unresolved=false;QSet<QString> planned;QByteArray batch;
    for(auto it=entries.begin();it!=entries.end();) {
        const auto current=find(before.rows,it->prefix);
        if(current.isEmpty() || (!it->applied.isEmpty() && !sameLinuxRoute(current,it->applied))) {
            if(current.isEmpty())for(const auto &value:before.rows)external|=ipv4RoutePrefix(value.toObject())==it->prefix;
            else external=true;
            it=entries.erase(it);
        } else if(it->deleting || it->applied.isEmpty()){unresolved=true;++it;}
        else {it->applied=current;planned.insert(it->prefix);batch+=command("del",it->prefix);++it;}
    }
    if(entries.isEmpty())return complete(external);
    if(!identity())return {Status::Failed,"TUN identity changed before route recovery.",true};
    if(unresolved && batch.isEmpty())return {Status::Failed,"Interrupted or unconfirmed capture ownership is unresolved; matching state is preserved.",true};
    for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=true;
    if(auto saved=saveCheckpoint(checkpoint);!saved.succeeded()) {
        for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=false;
        return failed(saved);
    }
    if(checkpoint) {
        const auto verified=read(utility,int(deadline.remainingTime()));bool unchanged=verified.result.succeeded() && identity();
        for(const auto &entry:entries)if(planned.contains(entry.prefix))
            unchanged&=sameLinuxRoute(find(verified.rows,entry.prefix),entry.applied);
        if(!unchanged) {
            for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=false;
            return verified.result.succeeded()?Result{Status::Failed,"Capture routes changed during deletion checkpoint publication.",true}:failed(verified.result);
        }
    }
    bool attempted=false;const auto removed=write(utility,batch,deadline,true,&attempted);
    if(!attempted)for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=false;
    const auto after=read(utility,int(deadline.remainingTime()));
    if(!after.result.succeeded())return failed(after.result);
    for(auto it=entries.begin();it!=entries.end();) {
        const auto current=find(after.rows,it->prefix);
        if(current.isEmpty() || (!it->applied.isEmpty() && !sameLinuxRoute(current,it->applied)) || (planned.contains(it->prefix) && removed.succeeded())) {
            external|=!current.isEmpty();it=entries.erase(it);
        } else ++it;
    }
    if(entries.isEmpty())return complete(external);
    if(auto saved=saveCheckpoint(checkpoint);!saved.succeeded())return failed(saved);
    return {removed.succeeded()?Status::Failed:removed.status,"Cannot confirm route recovery; ownership records retained.",true};
}
