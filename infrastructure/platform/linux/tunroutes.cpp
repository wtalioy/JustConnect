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
    interfaceIndex=metric=0;origin=Origin::Prepared;
}
QJsonObject LinuxTunRoutes::snapshot() const
{
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
    if(!owner.isNull())return {Status::Failed,"Active capture ownership cannot be replaced."};
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
    sourceAddress=saved["source"].toString();gatewayPeer=saved["peer"].toString();metric=linuxRouteMetric(id);origin=Origin::Recovered;
    QSet<QString> prefixes;
    for(const auto &value:saved["routes"].toArray()) {
        const auto entry=value.toObject();const auto prefix=entry["prefix"].toString();const auto row=entry["applied"].toObject();
        if(!value.isObject() || entry.size()!=4 || !canonicalIpv4Prefix(prefix) || prefixes.contains(prefix)
            || !entry["before"].isArray() || !entry["before"].toArray().isEmpty() || !entry["applied"].isObject() || !entry["delete_started"].isBool()
            || (!row.isEmpty() && (!createdShape(row) || find(QJsonArray{row},prefix)!=row))
            || (entry["delete_started"].toBool() && row.isEmpty()))return invalid;
        prefixes.insert(prefix);entries.append({prefix,row,entry["delete_started"].toBool()});
    }
    accepted=true;return restore(id,checkpoint);
}
Result LinuxTunRoutes::apply(const UnixTunDevice &device, const QString &source, const QString &peer,
                             const QStringList &requested, const CheckpointWriter &checkpoint)
{
    if (!owner.isNull()) return {Status::Failed,"Owned routes must be restored before another apply."};
    if (requested.size()>LinuxRouteSnapshotRows)return {Status::Failed,"Too many capture routes."};
    auto prefixes=requested;
    for(const auto &prefix:prefixes)if(!canonicalIpv4Prefix(prefix))return {Status::Failed,"Capture routes require canonical IPv4 prefixes of length 2 through 32."};
    prefixes.removeDuplicates();if(prefixes.isEmpty())return {};
    if(device.descriptor()<0 || device.owner().isNull())return {Status::Failed,"Capture routes require an owned TUN device."};
    if(!assignedLinuxTunPair(device.name(),device.index(),source,peer))return {Status::Failed,"Capture routes require the owned device's nonzero IPv4 point-to-point addresses."};
    const auto utility=trustedIpRouteUtility();if(utility.isEmpty())return {Status::Unsupported,"A trusted system iproute2 executable is required."};
    const auto namespaceId=linuxNetworkNamespace();if(namespaceId.isEmpty())return {Status::Failed,"Cannot identify the Linux boot and network namespace."};
    owner=device.owner();interfaceName=device.name();interfaceIndex=device.index();sourceAddress=source;gatewayPeer=peer;
    networkNamespace=namespaceId;metric=linuxRouteMetric(owner);
    if(!owns(device)){clear();return {Status::Failed,"TUN identity changed before route application."};}
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);
    const auto available=[&](const ReadResult &state)->Result {
        if(!state.result.succeeded())return state.result;
        if(state.rows.size()+prefixes.size()>LinuxRouteSnapshotRows)return {Status::Failed,"Capture routes exceed the complete snapshot capacity."};
        for(const auto &value:state.rows)if(prefixes.contains(ipv4RoutePrefix(value.toObject())))
            return {Status::Failed,"An existing route cannot be adopted or replaced."};
        return {};
    };
    if(auto result=available(read(utility,int(deadline.remainingTime())));!result.succeeded()){clear();return result;}
    if(!owns(device) || !assignedLinuxTunPair(device.name(),device.index(),source,peer)){clear();return {Status::Failed,"TUN identity or addresses changed while reading routes."};}
    QByteArray batch;for(const auto &prefix:prefixes){entries.append({prefix,{}});batch+=command("add",prefix);}
    if(auto result=saveCheckpoint(checkpoint);!result.succeeded()){if(!result.mayHaveChanged)clear();return result;}
    if(checkpoint) {
        auto result=available(read(utility,int(deadline.remainingTime())));
        if(result.succeeded() && (!owns(device) || !assignedLinuxTunPair(device.name(),device.index(),source,peer)))result={Status::Failed,"TUN identity or addresses changed during checkpoint publication."};
        if(!result.succeeded()){result.mayHaveChanged=true;return result;}
    }
    bool attempted=false;auto result=write(utility,batch,deadline,false,&attempted);
    origin=attempted?Origin::Live:Origin::Prepared;
    const auto after=read(utility,int(deadline.remainingTime()));
    bool confirmed=after.result.succeeded() && owns(device);
    if(after.result.succeeded())for(auto &entry:entries) {
        const auto row=find(after.rows,entry.prefix);if(createdShape(row))entry.applied=row;else confirmed=false;
    }
    if(auto saved=saveCheckpoint(checkpoint);!saved.succeeded()){saved.mayHaveChanged=true;return saved;}
    if(result.succeeded() && confirmed)return {Status::Success,{},true};
    if(result.succeeded())result=after.result.succeeded()?Result{Status::Failed,"Cannot confirm all newly owned routes."}:after.result;
    const auto recovered=restore(device,checkpoint);result.mayHaveChanged=true;
    if(!recovered.succeeded())result.detail+=" Route rollback is incomplete; ownership records retained.";
    return result;
}
Result LinuxTunRoutes::extend(const UnixTunDevice &device, const QStringList &addresses, const CheckpointWriter &checkpoint)
{
    const Result invalid{Status::Failed,"DNS addresses require confirmed capture route ownership."};
    if (addresses.isEmpty() || addresses.size() > LinuxRouteSnapshotRows || !owns(device)
        || !assignedLinuxTunPair(interfaceName,interfaceIndex,sourceAddress,gatewayPeer)) return invalid;
    for (const auto &entry : entries) if (entry.deleting || entry.applied.isEmpty()) return invalid;
    QStringList prefixes;
    for (const auto &address : addresses) {
        if (!canonicalUnicastIpv4(address) || address == sourceAddress || address == gatewayPeer) return invalid;
        bool covered = false;
        for (const auto &entry : entries) covered |= ipv4PrefixContainsAddress(entry.prefix,address);
        if (!covered) prefixes.append(address+"/32");
    }
    return addPrefixes(device, prefixes, checkpoint);
}

Result LinuxTunRoutes::addPrefixes(const UnixTunDevice &device, const QStringList &requested, const CheckpointWriter &checkpoint)
{
    const Result invalid{Status::Failed,"Route additions require confirmed capture ownership."};
    if (requested.size() > LinuxRouteSnapshotRows || !owns(device)
        || !assignedLinuxTunPair(interfaceName,interfaceIndex,sourceAddress,gatewayPeer)) return invalid;
    for (const auto &entry : entries) if (entry.deleting || entry.applied.isEmpty()) return invalid;
    QStringList prefixes;
    for (const auto &prefix : requested) {
        if (!canonicalIpv4Prefix(prefix)) return invalid;
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
    const auto verify = [&](const ReadResult &state) -> Result {
        if (!state.result.succeeded()) return state.result;
        if (!owns(device) || !assignedLinuxTunPair(interfaceName,interfaceIndex,sourceAddress,gatewayPeer)
            || state.rows.size()+prefixes.size() > LinuxRouteSnapshotRows) return invalid;
        for (const auto &entry : existing)
            if (!sameLinuxRoute(find(state.rows,entry.prefix),entry.applied)) return invalid;
        for (const auto &row : state.rows)
            if (prefixes.contains(ipv4RoutePrefix(row.toObject()))) return invalid;
        return {};
    };
    if (auto result = verify(read(utility,int(deadline.remainingTime()))); !result.succeeded()) return result;
    if (prefixes.isEmpty()) return {};
    QByteArray batch;
    for (const auto &prefix : prefixes) { entries.append({prefix,{}}); batch += command("add",prefix); }
    const auto abandon = [&](Result result) {
        entries = existing;
        const auto saved = saveCheckpoint(checkpoint);
        if (!saved.succeeded()) result = saved;
        result.mayHaveChanged = true;
        return result;
    };
    if (auto result = saveCheckpoint(checkpoint); !result.succeeded()) return abandon(result);
    if (auto result = verify(read(utility,int(deadline.remainingTime()))); !result.succeeded()) return abandon(result);
    bool attempted = false;
    auto result = write(utility,batch,deadline,false,&attempted);
    if (!attempted) return abandon(result);
    origin = Origin::Recovered; // Unconfirmed additions must retain ambiguity during later recovery.
    const auto after = read(utility,int(deadline.remainingTime()));
    bool confirmed = after.result.succeeded() && owns(device)
        && assignedLinuxTunPair(interfaceName,interfaceIndex,sourceAddress,gatewayPeer);
    if (after.result.succeeded()) {
        for (const auto &entry : existing) confirmed &= sameLinuxRoute(find(after.rows,entry.prefix),entry.applied);
        for (qsizetype index = existing.size(); index < entries.size(); ++index) {
            auto &entry = entries[index];
            const auto row = find(after.rows,entry.prefix);
            if (createdShape(row)) entry.applied = row; else confirmed = false;
        }
    }
    if (const auto saved = saveCheckpoint(checkpoint); !saved.succeeded()) result = saved;
    if (result.succeeded() && !confirmed) result = after.result.succeeded() ? invalid : after.result;
    result.mayHaveChanged = true;
    return result;
}

Result LinuxTunRoutes::reconcile(const UnixTunDevice &device, const QStringList &requested, const CheckpointWriter &checkpoint)
{
    // Add replacements before withdrawing old capture, keeping egress available throughout.
    QSet<QString> previous;
    for (const auto &entry : entries) previous.insert(entry.prefix);
    const QSet<QString> retained(requested.begin(), requested.end());
    const auto added = addPrefixes(device, requested, checkpoint);
    if (!added.succeeded()) return added;
    auto result = restore(owner, checkpoint, &retained);
    result.mayHaveChanged |= added.mayHaveChanged || previous != retained;
    return result;
}

Result LinuxTunRoutes::restore(const UnixTunDevice &device, const CheckpointWriter &checkpoint)
{
    if(owner.isNull())return {};
    if(!owns(device))return {Status::Failed,"Route ownership no longer matches the active TUN device.",true};
    return restore(owner,checkpoint);
}
Result LinuxTunRoutes::restore(const QUuid &id, const CheckpointWriter &checkpoint, const QSet<QString> *retained)
{
    if(owner.isNull())return {};
    if(id!=owner || linuxNetworkNamespace()!=networkNamespace)return {Status::Failed,"Capture owner or network namespace changed.",true};
    const auto failed=[](Result result){result.mayHaveChanged=true;return result;};
    const auto complete=[&](bool external) {
        const auto result=checkpoint?checkpoint(retained ? snapshot() : QJsonObject{}):Result{};
        if(!result.succeeded())return failed(result);
        if (!retained) clear();
        return Result{Status::Success,external?QString("External route changes were preserved."):QString{}};
    };
    // This live instance knows no native write was attempted; a fresh instance must retain ambiguity.
    if(origin==Origin::Prepared || entries.isEmpty())return complete(false);
    const auto utility=trustedIpRouteUtility();if(utility.isEmpty())return {Status::Unsupported,"A trusted system iproute2 executable is required.",true};
    QDeadlineTimer deadline(LinuxRouteOperationTimeoutMs);const auto before=read(utility,int(deadline.remainingTime()));
    if(!before.result.succeeded())return failed(before.result);
    bool external=false,unresolved=false;QSet<QString> planned;QByteArray batch;
    for(auto it=entries.begin();it!=entries.end();) {
        if (retained && retained->contains(it->prefix)) {
            if (!sameLinuxRoute(find(before.rows,it->prefix),it->applied))
                return {Status::Failed,"Retained capture changed during reconciliation.",true};
            ++it; continue;
        }
        const auto current=find(before.rows,it->prefix);
        if(current.isEmpty() || (!it->applied.isEmpty() && !sameLinuxRoute(current,it->applied))) {
            if(current.isEmpty())for(const auto &value:before.rows)external|=ipv4RoutePrefix(value.toObject())==it->prefix;
            else external=true;
            it=entries.erase(it);
        } else if(it->deleting || (origin==Origin::Recovered && it->applied.isEmpty())){unresolved=true;++it;}
        else if(it->applied.isEmpty() && !createdShape(current)){unresolved=true;++it;}
        else {it->applied=current;planned.insert(it->prefix);batch+=command("del",it->prefix);++it;}
    }
    if(entries.isEmpty() || (retained && batch.isEmpty() && !unresolved))return complete(external);
    if(!identity())return {Status::Failed,"TUN identity changed before route recovery.",true};
    if(unresolved && batch.isEmpty())return {Status::Failed,"Interrupted or unconfirmed capture ownership is unresolved; matching state is preserved.",true};
    for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=true;
    if(auto saved=saveCheckpoint(checkpoint);!saved.succeeded()) {
        for(auto &entry:entries)if(planned.contains(entry.prefix))entry.deleting=false;
        return failed(saved);
    }
    if(checkpoint) {
        const auto verified=read(utility,int(deadline.remainingTime()));bool unchanged=verified.result.succeeded() && identity();
        for(const auto &entry:entries)if(planned.contains(entry.prefix) || (retained && retained->contains(entry.prefix)))
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
    bool retainedChanged = false;
    for(auto it=entries.begin();it!=entries.end();) {
        if (retained && retained->contains(it->prefix)) {
            retainedChanged |= !sameLinuxRoute(find(after.rows,it->prefix),it->applied);
            ++it; continue;
        }
        const auto current=find(after.rows,it->prefix);
        if(current.isEmpty() || (!it->applied.isEmpty() && !sameLinuxRoute(current,it->applied)) || (planned.contains(it->prefix) && removed.succeeded())) {
            external|=!current.isEmpty();it=entries.erase(it);
        } else ++it;
    }
    bool remaining = false;
    for (const auto &entry : entries) remaining |= !retained || !retained->contains(entry.prefix);
    if(!remaining && !retainedChanged)return complete(external);
    if(auto saved=saveCheckpoint(checkpoint);!saved.succeeded())return failed(saved);
    return {removed.succeeded()?Status::Failed:removed.status,"Cannot confirm route recovery; ownership records retained.",true};
}
