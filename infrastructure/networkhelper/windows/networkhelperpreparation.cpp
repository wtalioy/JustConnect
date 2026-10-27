#include "infrastructure/networkhelper/windows/networkhelperpreparation.h"
#include "application/networkprotection.h"
#include "infrastructure/dns/windows/dnscontract.h"
#include "infrastructure/dns/domainlimits.h"
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <QUuid>
#include <algorithm>

namespace {
QSet<QString> namespaces(const QJsonArray &values)
{
    QSet<QString> result;
    for(const auto &value:values)result.insert(value.toString().toLower());
    return result;
}
bool sameServer(const QString &left,const QString &right)
{
    QHostAddress a(left),b(right);a.setScopeId({});b.setScopeId({});
    return !a.isNull() && !b.isNull() && a==b;
}
WindowsHelperPreparation prepareOriginalDNS(const QJsonArray &required,const QJsonObject &network,const QJsonObject &dns)
{
    using Status=PlatformOperationResult::Status;
    const auto unsupported=[](const char *message){return WindowsHelperPreparation{{Status::Unsupported,QString::fromLatin1(message)},{}};};
    const auto protection=originalDnsProtection(dns);
    const auto global=dns["native_global"].toObject();const auto text=global["Value"].toObject()["SettingFlags"].toString();
    bool valid=false;const auto flags=text.toULongLong(&valid);
    if(!protection || global["Status"]!=0 || !valid || QString::number(flags)!=text || !WindowsDNS::plainGlobalPolicy(flags)
        || !dns["nrpt_sources"].isArray() || !dns["nrpt"].isArray() || !dns["configured_encryption"].isArray() || !dns["doh"].isArray())
        return unsupported("The original Windows DNS source or security policy cannot be confirmed.");
    const bool encrypted=(flags&(WindowsDNS::EnableDoh|WindowsDNS::EnableDot)) && !(flags&WindowsDNS::EncryptionDisabled);
    if(encrypted && dns["doh_supported"]!=true)return unsupported("The original Windows DNS encryption table is unavailable.");
    QStringList local;
    for(const auto &item:network["interfaces"].toArray()){
        const auto row=item.toObject();if(row["up"]!=true)continue;
        for(const auto &value:row["addresses"].toArray()){
            const QHostAddress address(value.toString().section('/',0,0));
            if(address.protocol()==QAbstractSocket::IPv4Protocol && address.isLoopback() && !local.contains(address.toString()))local.append(address.toString());
        }
    }
    local.sort();if(local.isEmpty())return unsupported("No assigned IPv4 loopback DNS listener is available.");
    const auto listen=local.first(),endpoint=listen+':'+QString::number(WindowsDNS::ServerPort);
    const auto facts=(*protection)["namespaces"].toArray(),policies=dns["nrpt"].toArray();
    QMap<QString,QJsonObject> selected;QMap<QString,QJsonArray> serverGroups;
    for(const auto &rule:required){
        bool found=false;
        for(const auto &targetValue:(*protection)["targets"].toArray()){
            const auto target=targetValue.toObject();const auto name=rule.toObject();
            if(target["kind"]!=name["kind"] || target["value"]!=name["value"])continue;
            for(const auto &reference:target["sources"].toArray()){
                const auto ref=reference.toObject();const auto at=ref["index"].toInt(-1);
                if(ref["kind"]!="namespace" || at<0 || at>=facts.size())return unsupported("A protected Windows name lacks a native namespace source.");
                const auto origin=facts[at].toObject()["source"].toObject();const auto index=origin["row"].toInt(-1);
                if(origin["provider"]!="nrpt" || index<0 || index>=policies.size())return unsupported("The protected name requires an unsupported Windows DNS provider.");
                const auto policy=policies[index].toObject();const auto names=namespaces(policy["Namespace"].toArray());
                const auto servers=policy["NameServers"].toArray();
                if(names.isEmpty() || servers.isEmpty())return unsupported("The original Windows DNS namespace has no explicit server group.");
                QJsonObject source;
                for(const auto &value:dns["nrpt_sources"].toArray()){
                    const auto candidate=value.toObject();const auto scopes=namespaces(candidate["namespaces"].toArray());
                    if(!scopes.contains(names))continue;
                    if(!source.isEmpty())return unsupported("The original Windows DNS provider is ambiguous.");
                    source=candidate;
                }
                const QUuid id(source["id"].toString());
                if(source.isEmpty() || source["store"]!="local" || id.isNull()
                    || source["id"].toString().compare(id.toString(QUuid::WithBraces),Qt::CaseInsensitive)!=0
                    || !source["class"].isString() || !source["servers"].isString() || !source["owner"].isNull()
                    || source["version"].toInteger(-1)!=WindowsDNS::NrptVersion || source["options"].toInteger(-1)!=WindowsDNS::GenericServersOption)
                    return unsupported("The original Windows DNS provider is managed, active or not replaceable.");
                for(const auto &server:servers){
                    const QHostAddress address(server.toString());
                    if(!server.isString() || address.isNull() || address.isMulticast() || address==QHostAddress::AnyIPv4
                        || address==QHostAddress::AnyIPv6 || address==QHostAddress::Broadcast || sameServer(server.toString(),listen))
                        return unsupported("The original Windows DNS server is not a distinct unicast endpoint.");
                    if(encrypted){
                        for(const auto &known:dns["configured_encryption"].toArray())if(sameServer(server.toString(),known.toString()))return unsupported("The original Windows DNS source requires native encryption.");
                        for(const auto &known:dns["doh"].toArray())if(sameServer(server.toString(),known.toObject()["ServerAddress"].toString()))return unsupported("The original Windows DNS source requires native encryption.");
                    }
                }
                const auto key=id.toString(QUuid::WithBraces).toUpper();
                if(serverGroups.contains(key) && serverGroups[key]!=servers)return unsupported("One Windows DNS source has conflicting effective server groups.");
                selected[key]=source;serverGroups[key]=servers;found=true;
            }
        }
        if(!found)return unsupported("The original Windows DNS requirements are not fully mapped.");
    }
    WindowsHelperPreparation result;QJsonArray requests,contexts;QList<QJsonObject> routes;QMap<QString,QJsonArray> routed;
    qsizetype count=0;
    for(auto it=selected.begin();it!=selected.end();++it){
        const auto source=it.value();const auto servers=serverGroups[it.key()];QJsonArray endpoints;
        for(const auto &server:servers){
            const auto text=QHostAddress(server.toString()).toString();
            endpoints.append((text.contains(':')?'['+text+']':text)+':'+QString::number(WindowsDNS::ServerPort));
        }
        const auto scopes=namespaces(source["namespaces"].toArray());
        if(scopes.contains("."))return unsupported("A default Windows NRPT source requires an explicit default query context.");
        for(const auto &scope:scopes){
            bool represented=false;
            for(const auto &value:policies){
                const auto policy=value.toObject();if(!namespaces(policy["Namespace"].toArray()).contains(scope))continue;
                if(policy["NameServers"]!=servers)return unsupported("The original Windows DNS source has a shadowed namespace.");
                represented=true;
            }
            if(!represented)return unsupported("The effective Windows DNS source changed during preparation.");
        }
        for(const auto &targetValue:(*protection)["targets"].toArray()){
            const auto target=targetValue.toObject();bool belongs=false;
            for(const auto &reference:target["sources"].toArray()){
                const auto at=reference.toObject()["index"].toInt(-1);
                if(at>=0 && at<facts.size() && facts[at].toObject()["role"]=="nrpt"
                    && scopes.contains(facts[at].toObject()["name"].toString().toLower()))belongs=true;
            }
            if(!belongs)continue;
            const QJsonObject name{{"kind",target["kind"]},{"value",target["value"]}};
            const auto key=name["kind"].toString()+'/'+name["value"].toString();
            if(routed.contains(key)){
                if(routed[key]!=endpoints)return unsupported("A native Windows DNS namespace has ambiguous upstreams.");
                continue;
            }
            routed[key]=endpoints;count+=endpoints.size();
            if(count>qsizetype(NetworkDnsDomainLimit))return unsupported("The original Windows DNS source plan exceeds its bound.");
            routes.append(QJsonObject{{"name",name},{"servers",endpoints},{"interface",""},{"source",endpoint},{"listen",endpoint}});
        }
        requests.append(QJsonObject{{"source",source},{"servers",servers},{"listen",listen}});contexts.append(source);
    }
    const auto priority=[](const QJsonObject &route){const auto kind=route["name"].toObject()["kind"].toString();return kind=="exact"?3:kind=="prefix"?2:1;};
    std::stable_sort(routes.begin(),routes.end(),[&](const auto &a,const auto &b){
        if(priority(a)!=priority(b))return priority(a)>priority(b);
        return a["name"].toObject()["value"].toString().size()>b["name"].toObject()["value"].toString().size();
    });
    for(const auto &route:routes)result.originalSources.append(route);
    result.configuration["original_dns"]=requests;
    result.originalContext={{"sources",contexts},{"global",global},{"doh",dns["doh"]},{"configured_encryption",dns["configured_encryption"]}};
    return result;
}
}

WindowsHelperPreparation prepareWindowsNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu)
{
    using Status=PlatformOperationResult::Status;
    const auto required=requiredOriginalDnsNames(resources,protection);
    if(!required)return {{Status::Unsupported,"Cannot determine complete original DNS requirements."},{}};
    auto original=required->isEmpty()?WindowsHelperPreparation{}:prepareOriginalDNS(*required,network,dns);
    if(!original.result.succeeded())return original;
    const auto targets=campusCaptureTargets(resources,protection,{},original.originalSources);
    if(!targets || targets->ipv4Prefixes.isEmpty())return {{Status::Unsupported,"Cannot derive safe campus capture targets."},{}};
    const auto reserved=tunAddressReservations(targets->ipv4Prefixes,dns,localDNS);
    if(!reserved)return {{Status::Failed,"DNS address reservations exceed the complete input bound."},{}};
    const auto addresses=privateTUNAddresses(network,*reserved);
    if(!addresses)return {{Status::Unsupported,"No unused private IPv4 address pair is available."},{}};
    if(!resources["underlay_interface"].isString())return {{Status::Failed,"Missing original underlay preference."},{}};
    const auto preferred=resources["underlay_interface"].toString();
    if(!preferred.isEmpty()){
        bool available=false;
        for(const auto &item:network["interfaces"].toArray()){
            const auto row=item.toObject();
            available|=row["name"]==preferred && row["up"]==true;
        }
        if(!available)return {{Status::Failed,"The confirmed underlay interface is no longer available."},{}};
    }
    return {{},{{"address",addresses->first},{"peer",addresses->second},{"mtu",mtu},
        {"capture_prefixes",QJsonArray::fromStringList(targets->ipv4Prefixes)},
        {"dns_domains",QJsonArray::fromStringList(campusDnsDomainsToInstall(targets->dnsDomains,original.originalSources))},
        {"original_dns",original.configuration.value("original_dns").toArray()}},original.originalSources,original.originalContext};
}


std::optional<QJsonObject> completeWindowsOriginalDNS(QJsonObject configuration,const QJsonObject &listeners)
{
    QSet<QString> expected;
    for(const auto &value:configuration["original_dns"].toArray())expected.insert(value.toObject()["listen"].toString()+':'+QString::number(WindowsDNS::ServerPort));
    if(listeners.size()!=expected.size())return {};
    for(const auto &endpoint:expected)if(listeners[endpoint]!=endpoint)return {};
    return configuration;
}
bool windowsOriginalDnsSourcesMatch(const QJsonArray &sources,const QJsonObject &context,
    const QJsonObject &network,const QJsonObject &dns)
{
    if(sources.isEmpty())return context.isEmpty();
    QJsonArray names;for(const auto &value:sources)names.append(value.toObject()["name"]);
    const auto current=prepareOriginalDNS(names,network,dns);
    return current.result.succeeded() && current.originalSources==sources && current.originalContext==context;
}
std::optional<QStringList> updatedWindowsCapturePrefixes(const QJsonObject &resources,const QJsonObject &policy,
    const QJsonObject &configuration,const QJsonArray &originalSources)
{
    const auto domains=campusDnsDomains(resources);if(!domains)return {};
    if(QJsonArray::fromStringList(campusDnsDomainsToInstall(*domains,originalSources))!=configuration["dns_domains"])return {};
    return updatedCampusCapturePrefixes(resources,policy,*domains,originalSources);
}
