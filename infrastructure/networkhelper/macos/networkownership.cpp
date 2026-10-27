#include "infrastructure/networkhelper/macos/networkownership.h"
#include "infrastructure/routing/originalexit.h"
#include "infrastructure/routing/macos/tunroutes.h"
#include "infrastructure/dns/macos/tundns.h"
#include "infrastructure/dns/macos/resolver.h"
#include "infrastructure/dns/macos/originaldns.h"
#include "infrastructure/dns/dnssnapshot.h"
#include "infrastructure/networkaddress/ipv4.h"
#include <QUrl>
#include <algorithm>
#include <SystemConfiguration/SystemConfiguration.h>
#include <net/route.h>
#include <cstring>

namespace {
QJsonObject projection(const QJsonObject &row)
{
    QJsonObject value{{"destination",row["prefix"]},{"interface_index",row["index"]},{"flags",row["flags"]}};
    if (row["flags"].toInteger() & RTF_WASCLONED) value["cloned"] = true;
    const auto raw = QByteArray::fromHex(row["addresses"].toObject()[QString::number(RTAX_GATEWAY)].toString().toLatin1());
    if (raw.size() >= 8 && quint8(raw[1]) == AF_INET) {
        in_addr address{}; std::memcpy(&address,raw.constData()+4,sizeof(address)); char text[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET,&address,text,sizeof(text))) value["gateway"] = QString::fromLatin1(text);
    }
    return value;
}
}
std::optional<QJsonObject> macOriginalExitSnapshot(const QJsonObject &network,const QString &preferred)
{
    if(!network["routes"].isArray())return {};
    auto normalized=network;QJsonArray routes;
    for(const auto &value:network["routes"].toArray()){
        auto row=value.toObject();row["flags"]=row["flags"].toInteger() & ~qint64(RTF_IFREF);routes.append(row);
    }
    normalized["routes"]=routes;
    return originalExitSnapshot(normalized,preferred);
}
bool macOriginalDnsSourcesMatch(const MacHelperConfiguration &configuration,const QJsonObject &network,const QJsonObject &dns)
{
    const auto entries=dns["dynamic_store"].toObject();
    for(const auto &value:configuration.originalDns){
        const auto source=value.toObject();const auto original=MacOriginalDns::properties(source,true);
        const auto context=source["context"].toObject();const auto service=source["service"].toString();
        const auto state=entries.value("State:/Network/Service/"+service+"/DNS");
        if(!original || entries["Setup:/Network/Service/"+service+"/DNS"].toObject()!=*original
            || (state.isUndefined()?QJsonValue(QJsonValue::Null):state)!=context["state"])return false;
        bool assigned=false;const auto endpoint=QUrl("dns://"+source["listen"].toString()).host();
        for(const auto &value:network["interfaces"].toArray()){
            const auto row=value.toObject();
            if(row["name"]!=context["interface"] || row["up"]!=true || (context["interface_index"].toInteger()>0 && row["index"]!=context["interface_index"]))continue;
            QStringList addresses;for(const auto &address:row["addresses"].toArray())addresses.append(address.toString());addresses.sort();
            if(QJsonArray::fromStringList(addresses)!=context["addresses"].toArray())continue;
            for(const auto &address:addresses)assigned|=address.section('/',0,0)==endpoint;
        }
        if(!assigned)return false;
    }
    return true;
}
NetworkPolicySession::OriginalViewFilter macOriginalNetworkView(const QUuid &owner,
    const MacHelperConfiguration &configuration,const QJsonObject &device,const QJsonObject &confirmed)
{
    const auto capture = confirmed["capture"].toObject();
    const auto name = device["interface"].toString(); const int index = device["index"].toInt();
    if (!MacTunRoutes::validRecord(owner,capture) || device["owner"] != owner.toString(QUuid::WithoutBraces)
        || capture["interface"] != name || capture["index"] != index || capture["source"] != configuration.address || capture["peer"] != configuration.peer) return {};
    QJsonArray owned = confirmed["device_routes"].toArray();
    for (const auto &row : capture["routes"].toArray()) owned.append(row.toObject()["applied"]);
    const auto service = owner.toString(QUuid::WithoutBraces).toCFString();
    const auto key = SCDynamicStoreKeyCreateNetworkServiceEntity(nullptr,kSCDynamicStoreDomainState,service,kSCEntNetDNS);
    const auto dnsKey = QString::fromCFString(key); CFRelease(key); CFRelease(service);
    const QJsonValue expectedDns = confirmed.value("dns").toObject().value(dnsKey);
    if (!configuration.dnsDomains.isEmpty() && expectedDns.toObject() != MacTunDns::properties(configuration.peer,configuration.dnsDomains)) return {};
    const auto original=confirmed["original_dns"].toObject();
    if(configuration.originalDns.isEmpty()!=original.isEmpty() || (!original.isEmpty() && !MacOriginalDns::valid(owner,original)))return {};
    if(!original.isEmpty()){
        const auto records=original["entries"].toArray();if(records.size()!=configuration.originalDns.size())return {};
        for(const auto &value:configuration.originalDns){
            const auto source=value.toObject();bool found=false;const QUrl endpoint("dns://"+source["listen"].toString());
            for(const auto &entry:records){
                const auto record=entry.toObject();if(record["service"]!=source["service"])continue;
                const auto applied=MacOriginalDns::properties(record,false);
                found=record["original"]==source["original"] && record["context"]==source["context"] && applied && (*applied)["ServerAddresses"]==QJsonArray{endpoint.host()}
                    && (*applied)["ServerPort"]==endpoint.port();
            }
            if(!found)return {};
        }
    }
    return [configuration,name,index,owned,dnsKey,expectedDns,original](QJsonObject network,QJsonObject dns)
        -> std::optional<NetworkPolicySession::OriginalView> {
        if (!assignedUnixTunPair(name,index,configuration.address,configuration.peer) || !network["interfaces"].isArray() || !network["routes"].isArray()) return {};
        const auto native = readMacRoutes(); if (!native.result.succeeded()) return {};
        QJsonArray expected;
        for (const auto &row : owned) if (native.rows.contains(row)) expected.append(projection(row.toObject()));
        QJsonArray remaining;
        for (const auto &value : network["routes"].toArray()) {
            auto normalized = value.toObject(); normalized["flags"] = normalized["flags"].toInteger() & ~qint64(RTF_IFREF);
            const auto position = std::find(expected.begin(),expected.end(),QJsonValue(normalized));
            if (position != expected.end()) expected.erase(position);
            else remaining.append(value);
        }
        network["routes"] = remaining;
        QJsonArray interfaces; bool found = false;
        for (const auto &value : network["interfaces"].toArray()) {
            auto row = value.toObject();
            if (row["index"] == index && row["name"] == name) {
                if (found || row["up"] != true || !row["addresses"].isArray()) return {};
                found = true; auto addresses = row["addresses"].toArray();
                for (int n=addresses.size()-1;n>=0;--n) if (addresses[n] == configuration.address+"/32") addresses.removeAt(n);
                if (addresses.isEmpty()) continue;
                row["addresses"] = addresses;
            }
            interfaces.append(row);
        }
        if (!found) return {};
        network["interfaces"] = interfaces;
        auto entries = dns["dynamic_store"].toObject();
        if (!expectedDns.isUndefined() && entries[dnsKey] == expectedDns) {
            entries.remove(dnsKey);
            QJsonArray resolvers;
            for (const auto &value : dns["macos_resolvers"].toArray()) {
                const auto row = value.toObject();
                const bool owned = (configuration.dnsDomains.contains(row["domain"].toString()) && macDnsResolverUsesPeer(row,configuration.peer))
                    || macDnsResolverUsesPeer(row,configuration.peer,quint32(index));
                if (!owned) resolvers.append(value);
            }
            dns["macos_resolvers"] = resolvers;
        }
        for(const auto &value:original["entries"].toArray()){
            const auto record=value.toObject();const auto before=MacOriginalDns::properties(record,true),applied=MacOriginalDns::properties(record,false);
            if(!before || !applied)return {};
            const auto key="Setup:/Network/Service/"+record["service"].toString()+"/DNS";
            auto current=entries[key].toObject();
            if(current["ServerAddresses"]!=(*applied)["ServerAddresses"] || current["ServerPort"]!=(*applied)["ServerPort"])continue;
            for(const auto *field:{"ServerAddresses","ServerPort"}){
                if(before->contains(field))current[field]=(*before)[field];else current.remove(field);
            }
            if(current.isEmpty())entries.remove(key);else entries[key]=current;
            QJsonArray resolvers;
            for(const auto &value:dns["macos_resolvers"].toArray()){
                auto row=value.toObject();
                if(row["servers"]==(*applied)["ServerAddresses"] && row["port"].toInteger(DnsServerPort)==(*applied)["ServerPort"].toInteger()){
                    const auto restored=originalMacDnsResolver(row,record["context"].toObject());
                    if(!restored)return {};
                    row=*restored;
                }
                resolvers.append(row);
            }
            dns["macos_resolvers"]=resolvers;
        }
        dns["dynamic_store"] = entries;
        return NetworkPolicySession::OriginalView{network,dns};
    };
}
