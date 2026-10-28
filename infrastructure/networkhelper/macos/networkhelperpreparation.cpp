#include "infrastructure/networkhelper/macos/networkhelperpreparation.h"
#include "application/networkprotection.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/dns/domainlimits.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/networkaddress/ipv4.h"
#ifdef Q_OS_MACOS
#include "infrastructure/dns/macos/originaldns.h"
#endif
#include <QHostAddress>
#include <QMap>
#include <QSet>
#include <QNetworkInterface>
#include <QUrl>

namespace {
MacHelperPreparation prepareOriginalDNS(const QJsonArray &required,const QJsonObject &network,const QJsonObject &dns,MacOriginalDnsReader read)
{
    using Status=PlatformOperationResult::Status;
    const auto unsupported=[](const char *message){return MacHelperPreparation{{Status::Unsupported,QString::fromLatin1(message)},{},{}};};
#ifdef Q_OS_MACOS
    if(!read)read=readMacDnsPreferences;
#endif
    const auto protection=originalDnsProtection(dns);
    if(!read || !protection)return unsupported("The original macOS DNS source is unavailable.");
    const auto namespaces=(*protection)["namespaces"].toArray(),resolvers=dns["macos_resolvers"].toArray();
    const auto inputs=dns["dynamic_store"].toObject();
    MacHelperPreparation result;QMap<QString,DnsSnapshot> preferences;QMap<QString,QJsonObject> sources;
    qsizetype servers=0;
    for(const auto &rule:required){
        bool found=false;
        for(const auto &value:(*protection)["targets"].toArray()){
            const auto target=value.toObject();const auto name=rule.toObject();
            if(target["kind"]!=name["kind"] || target["value"]!=name["value"])continue;
            for(const auto &reference:target["sources"].toArray()){
                const auto ref=reference.toObject();const auto at=ref["index"].toInt(-1);
                if(ref["kind"]!="namespace" || at<0 || at>=namespaces.size())return unsupported("A protected name lacks a native macOS resolver source.");
                const auto fact=namespaces[at].toObject(),origin=fact["source"].toObject();const auto index=origin["row"].toInt(-1);
                if(origin["provider"]!="macos_resolver" || index<0 || index>=resolvers.size())return unsupported("The protected macOS DNS scope cannot be selected.");
                const auto resolver=resolvers[index].toObject();
                if(resolver["scope"]!="unscoped" || resolver["interface_index"].toInteger(-1)<0 || !resolver["options"].toString().isEmpty()
                    || resolver["servers"].toArray().isEmpty())return unsupported("The native resolver requires an unsupported binding or transport.");
                QString service;QSet<QString> inspected;
                for(auto it=inputs.begin();it!=inputs.end();++it){
                    const QString suffix="/DNS";
                    const auto prefix=it.key().startsWith("Setup:")?QStringLiteral("Setup:/Network/Service/"):QStringLiteral("State:/Network/Service/");
                    if(!it.key().startsWith(prefix) || !it.key().endsWith(suffix))continue;
                    const auto id=it.key().sliced(prefix.size(),it.key().size()-prefix.size()-suffix.size());const QUuid uuid(id);
                    if(uuid.isNull() || uuid.toString(QUuid::WithoutBraces).compare(id,Qt::CaseInsensitive)!=0 || inspected.contains(id))continue;
                    inspected.insert(id);
                    const auto setup=inputs["Setup:/Network/Service/"+id+"/DNS"].toObject(),state=inputs["State:/Network/Service/"+id+"/DNS"].toObject();
                    const auto source=setup["ServerAddresses"].toArray().isEmpty()?state:setup;
                    const auto configuredPort=setup.contains("ServerPort")?setup["ServerPort"]:state["ServerPort"];
                    if(!configuredPort.isUndefined() && (!configuredPort.isDouble() || configuredPort!=QJsonValue(configuredPort.toInteger(-1))))continue;
                    if(!macDnsServersBelongTo(resolver["servers"].toArray(),source["ServerAddresses"].toArray())
                        || configuredPort.toInteger(DnsServerPort)!=resolver["port"].toInteger(DnsServerPort)
                        || !setup["Options"].toString().isEmpty() || !state["Options"].toString().isEmpty())continue;
                    bool namespaceMatches=false;
                    for(const auto &input:{setup,state}){
                        const auto field=fact["role"]=="search"?"SearchDomains":"SupplementalMatchDomains";
                        namespaceMatches|=input[field].toArray().contains(fact["name"]) || input["DomainName"]==fact["name"];
                    }
                    if(!namespaceMatches)continue;
                    if(resolver["interface_index"].toInteger()>0){
                        if(!preferences.contains(id))preferences.insert(id,read(id));
                        const auto snapshot=preferences[id];if(!snapshot.result.succeeded())return {snapshot.result,{},{}};
                        bool matched=false;
                        for(const auto &value:network["interfaces"].toArray()){
                            const auto row=value.toObject();matched|=row["name"]==snapshot.data["interface"] && row["index"]==resolver["interface_index"] && row["up"]==true;
                        }
                        if(!matched)continue;
                    }
                    if(!service.isEmpty() && service!=id)return unsupported("The effective resolver maps to multiple preferences services.");
                    service=id;
                }
                if(service.isEmpty())return unsupported("The effective DNS source has no replaceable preferences service.");
                if(!preferences.contains(service))preferences.insert(service,read(service));
                const auto snapshot=preferences[service];if(!snapshot.result.succeeded())return {snapshot.result,{},{}};
                if(snapshot.data["properties"]!=inputs["Setup:/Network/Service/"+service+"/DNS"].toObject()
                    || (!snapshot.data["original"].isString() && !snapshot.data["original"].isNull()))
                    return unsupported("The DNS preferences changed during source preparation.");
                QString local;QStringList sourceAddresses;
                for(const auto &row:network["interfaces"].toArray()){
                    const auto interface=row.toObject();
                    if(interface["name"]!=snapshot.data["interface"] || interface["up"]!=true)continue;
                    for(const auto &value:interface["addresses"].toArray())sourceAddresses.append(value.toString());
                    sourceAddresses.sort();
                    for(const auto &value:interface["addresses"].toArray()){
                        const auto address=value.toString().section('/',0,0);
                        if(canonicalUnicastIpv4(address)){local=address;break;}
                    }
                }
                if(local.isEmpty())return unsupported("The DNS source has no assigned IPv4 listener address.");
                QJsonArray endpoints;const auto port=resolver["port"].toInteger(DnsServerPort);
                if(port<1 || port>65535)return unsupported("The native DNS server port is invalid.");
                for(const auto &value:resolver["servers"].toArray()){
                    QHostAddress address(value.toString());
                    if(address.protocol()==QAbstractSocket::IPv6Protocol && address.isLinkLocal() && address.scopeId().isEmpty()
                        && resolver["interface_index"].toInteger()>0)address.setScopeId(snapshot.data["interface"].toString());
                    if(address.isNull() || address.isMulticast() || address==QHostAddress::AnyIPv4 || address==QHostAddress::AnyIPv6
                        || address==QHostAddress::Broadcast || (address.protocol()==QAbstractSocket::IPv6Protocol && address.isLinkLocal() && address.scopeId().isEmpty()))
                        return unsupported("The native DNS server is not a complete unicast endpoint.");
                    endpoints.append((address.protocol()==QAbstractSocket::IPv6Protocol?'['+address.toString()+']':address.toString())+':'+QString::number(port));
                }
                servers+=endpoints.size();if(servers>qsizetype(NetworkDnsDomainLimit))return unsupported("The original DNS source plan exceeds its bound.");
                const auto bound=resolver["interface_index"].toInteger();
                const QJsonObject source{{"name",rule},{"servers",endpoints},{"interface",bound?snapshot.data["interface"]:QJsonValue("")},{"source",service},{"listen",local+":0"}};
                if(!result.originalSources.contains(source))result.originalSources.append(source);
                const auto state=inputs.value("State:/Network/Service/"+service+"/DNS");
                QJsonObject context{{"servers",resolver["servers"]},{"port",port},{"interface_index",bound},{"interface",snapshot.data["interface"]},
                    {"domains",QJsonArray{resolver["domain"].toString()}},{"addresses",QJsonArray::fromStringList(sourceAddresses)},{"state",state.isUndefined()?QJsonValue(QJsonValue::Null):state}};
                if(sources.contains(service)){
                    auto previous=sources[service]["context"].toObject();auto expected=context;
                    auto domains=previous.take("domains").toArray();expected.remove("domains");
                    if(previous!=expected)return unsupported("One native DNS source requires one complete query context.");
                    if(!domains.contains(resolver["domain"].toString()))domains.append(resolver["domain"].toString());
                    context["domains"]=domains;
                }
                if(!validMacOriginalDnsContext(context))return unsupported("The native DNS query context is invalid.");
                sources[service]={{"service",service},{"original",snapshot.data["original"]},{"listen",local+":0"},{"context",context}};
                found=true;
            }
        }
        if(!found)return unsupported("The original DNS requirements are not fully mapped.");
    }
    for(const auto &source:sources)result.configuration.originalDns.append(source);
    return result;
}
}

MacHelperPreparation prepareMacNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu,const MacOriginalDnsReader &read)
{
    using Status = PlatformOperationResult::Status;
    const auto required=requiredOriginalDnsNames(resources,protection);
    if(!required)return {{Status::Unsupported,"Cannot determine complete original DNS requirements."},{}};
    auto original=required->isEmpty()?MacHelperPreparation{}:prepareOriginalDNS(*required,network,dns,read);
    if(!original.result.succeeded())return original;
    QString captureDiagnostic;
    const auto targets = campusCaptureTargets(resources,protection,{},original.originalSources, &captureDiagnostic);
    if (!targets || (targets->ipv4Prefixes.isEmpty() && targets->dnsDomains.isEmpty())) return {{Status::Unsupported,captureDiagnostic},{}};
    const auto reserved = tunAddressReservations(targets->ipv4Prefixes,dns,localDNS);
    if (!reserved) return {{Status::Failed,"DNS address reservations exceed the complete input bound."},{}};
    const auto addresses = privateTUNAddresses(network,*reserved);
    if (!addresses) return {{Status::Unsupported,"No unused private IPv4 address pair is available."},{}};
    if (!resources["underlay_interface"].isString()) return {{Status::Failed,"Missing original underlay preference."},{}};
    const auto interface = resources["underlay_interface"].toString();
    if (!interface.isEmpty()) {
        const auto actual = QNetworkInterface::interfaceFromName(interface);
        if (!actual.isValid() || !(actual.flags() & QNetworkInterface::IsUp))
            return {{Status::Failed,"The confirmed underlay interface is no longer available."},{}};
    }
    MacHelperConfiguration result{addresses->first,addresses->second,mtu,targets->ipv4Prefixes,targets->dnsDomains};
    if (!parseMacHelperApply(macHelperApplyRequest(QUuid::createUuid(),QUuid::createUuid(),result)))
        return {{Status::Failed,"Invalid or unsupported macOS capture configuration."},{}};
    result.originalDns=original.configuration.originalDns;
    result.dnsDomains=campusDnsDomainsToInstall(result.dnsDomains,original.originalSources);
    return {{},result,original.originalSources};
}

std::optional<QStringList> updatedMacCapturePrefixes(const QJsonObject &resources,const QJsonObject &policy,
    const MacHelperConfiguration &configuration,const QJsonArray &originalSources)
{
    const auto domains=campusDnsDomains(resources);
    if(!domains || campusDnsDomainsToInstall(*domains,originalSources)!=configuration.dnsDomains)return {};
    return updatedCampusCapturePrefixes(resources,policy,*domains,originalSources);
}

std::optional<MacHelperConfiguration> completeMacOriginalDNS(MacHelperConfiguration configuration,const QJsonObject &listeners)
{
    if(configuration.originalDns.size()!=listeners.size())return {};
    QJsonArray completed;
    for(const auto &value:configuration.originalDns){
        auto row=value.toObject();const auto source=row["service"].toString();const auto listener=listeners[source].toString();
        const QUrl endpoint("dns://"+listener),requested("dns://"+row["listen"].toString());
        if(!listeners[source].isString() || !endpoint.isValid() || endpoint.host()!=requested.host() || endpoint.port()<1
            || endpoint.port()>65535 || endpoint.userInfo().size() || endpoint.path().size() || endpoint.hasQuery() || endpoint.hasFragment())return {};
        row["listen"]=listener;completed.append(row);
    }
    configuration.originalDns=completed;
    if(!parseMacHelperApply(macHelperApplyRequest(QUuid::createUuid(),QUuid::createUuid(),configuration)))return {};
    return configuration;
}
