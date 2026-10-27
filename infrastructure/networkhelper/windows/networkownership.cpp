#include "infrastructure/networkhelper/windows/networkownership.h"
#include <QSet>
#include <QUuid>
#include <algorithm>

namespace {
std::optional<QJsonObject> ownedInterface(const QJsonObject &network,const QJsonObject &device)
{
    if(!network["interfaces"].isArray() || !network["routes"].isArray())return {};
    std::optional<QJsonObject> found;
    for(const auto &item:network["interfaces"].toArray()){
        const auto row=item.toObject();
        if(row["index"]!=device["index"])continue;
        if(found || row["name"]!=device["name"] || row["up"]!=true || !row["addresses"].isArray()
            || !row["addresses"].toArray().contains(device["address"].toString()+"/32"))return {};
        found=row;
    }
    return found;
}
QJsonArray subtract(QJsonArray rows,const QJsonArray &owned)
{
    for(const auto &value:owned){const auto at=std::find(rows.begin(),rows.end(),value);if(at!=rows.end())rows.erase(at);}
    return rows;
}
QJsonArray captures(const QJsonObject &configuration,const QJsonObject &peer)
{
    QJsonArray rows{peer};
    for(const auto &prefix:configuration["capture_prefixes"].toArray()){
        if(prefix.toString()==peer["destination"].toString())continue;
        auto row=peer;row["destination"]=prefix;row["gateway"]=configuration["peer"];
        if(!rows.contains(row))rows.append(row);
    }
    return rows;
}
}

std::optional<WindowsNetworkOwnership> WindowsNetworkOwnership::capture(const QJsonObject &configuration,
    const QJsonObject &device,const QJsonObject &network,const QJsonObject &dns)
{
    const auto adapter=ownedInterface(network,device);
    if(!adapter || device["index"].toInteger()<=0 || device["address"]!=configuration["address"]
        || device["peer"]!=configuration["peer"] || !configuration["capture_prefixes"].isArray()
        || !configuration["dns_domains"].isArray() || !dns["nrpt"].isArray() || !dns["nrpt_sources"].isArray()
        || !dns["interfaces"].isArray() || !dns["clients"].isArray() || !dns["adapters"].isArray())return {};
    WindowsNetworkOwnership result;result.device=device;result.interfaceSnapshot=*adapter;
    QJsonObject localRoute;
    for(const auto &item:network["routes"].toArray()){
        const auto row=item.toObject();
        if(row["interface_index"]==device["index"] && row["destination"]==device["address"].toString()+"/32"){
            if(!localRoute.isEmpty())return {};
            localRoute=row;
        }
        if(row["interface_index"]==device["index"] && row["destination"]==device["peer"].toString()+"/32"){
            if(!result.peerRoute.isEmpty())return {};
            result.peerRoute=row;
        }
    }
    if(result.peerRoute.isEmpty() || !localRoute["protocol"].isDouble())return {};
    const auto owned=captures(configuration,result.peerRoute);
    for(const auto &item:network["routes"].toArray())
        if(item.toObject()["interface_index"]==device["index"] && item.toObject().value("protocol")==localRoute.value("protocol") && !owned.contains(item))result.automaticRoutes.append(item);
    QSet<QString> pending;
    for(const auto &name:configuration["dns_domains"].toArray())pending.insert("."+name.toString());
    for(const auto &item:dns["nrpt"].toArray()){
        const auto row=item.toObject();
        if(row["NameServers"]!=QJsonArray{device["peer"]})continue;
        const auto names=row["Namespace"].toArray();
        if(names.isEmpty())return {};
        for(const auto &name:names)if(!pending.remove(name.toString()))return {};
        result.dnsPolicies.append(item);
    }
    if(!pending.isEmpty())return {};
    const auto dnsId=QUuid(device["dns_id"].toString());
    if(configuration["dns_domains"].toArray().isEmpty()!=dnsId.isNull())return {};
    for(const auto &item:dns["nrpt_sources"].toArray()){
        const auto row=item.toObject();
        if(dnsId.isNull() || row["store"]!="local" || QUuid(row["id"].toString())!=dnsId)continue;
        const auto prefix=QStringLiteral("JustConnect/");
        const auto sourceClass=row["class"].toString();
        if(!result.dnsSourceRecords.isEmpty() || row["servers"]!=configuration["peer"] || !row["owner"].isNull()
            || row["version"]!=1 || row["options"]!=8 || !sourceClass.startsWith(prefix)
            || QUuid(sourceClass.sliced(prefix.size())).isNull())return {};
        QSet<QString> expected;
        for(const auto &name:configuration["dns_domains"].toArray())expected.insert("."+name.toString());
        for(const auto &name:row["namespaces"].toArray())if(!expected.remove(name.toString()))return {};
        if(!expected.isEmpty())return {};
        result.dnsSourceRecords.append(item);
    }
    if(!dnsId.isNull() && result.dnsSourceRecords.size()!=1)return {};
    for(const auto &item:dns["interfaces"].toArray())if(item.toObject()["InterfaceIndex"]==device["index"])result.dnsInterfaces.append(item);
    for(const auto &item:dns["clients"].toArray())if(item.toObject()["InterfaceIndex"]==device["index"])result.dnsClients.append(item);
    for(const auto &item:dns["adapters"].toArray()){
        const auto row=item.toObject();
        if(row["InterfaceIndex"]!=device["index"] && row["Ipv6IfIndex"]!=device["index"])continue;
        const auto id=QUuid(row["Guid"].toString());
        if(id.isNull() || id!=QUuid(device["guid"].toString()) || row["Luid"]!=device["luid"])return {};
        result.dnsAdapters.append(item);
    }
    if(result.dnsAdapters.size()!=1)return {};
    const auto filter=result.filter(configuration);
    if(!filter || !filter(network,dns))return {};
    return result;
}

NetworkPolicySession::OriginalViewFilter WindowsNetworkOwnership::filter(const QJsonObject &configuration) const
{
    if(configuration["address"]!=device["address"]
        || configuration["peer"]!=device["peer"] || !configuration["capture_prefixes"].isArray())return {};
    const auto required=captures(configuration,peerRoute);
    return [owned=*this,required](QJsonObject network,QJsonObject dns)->std::optional<NetworkPolicySession::OriginalView>{
        if(!ownedInterface(network,owned.device) || !dns["nrpt"].isArray() || !dns["nrpt_sources"].isArray() || !dns["interfaces"].isArray()
            || !dns["clients"].isArray() || !dns["adapters"].isArray())return {};
        auto routes=network["routes"].toArray();
        for(const auto &row:required){const auto at=std::find(routes.begin(),routes.end(),row);if(at==routes.end())return {};routes.erase(at);}
        network["routes"]=subtract(routes,owned.automaticRoutes);
        QJsonArray interfaces;
        for(const auto &item:network["interfaces"].toArray()){
            auto row=item.toObject();
            if(row["index"]==owned.device["index"]){
                row["addresses"]=subtract(row["addresses"].toArray(),owned.interfaceSnapshot["addresses"].toArray());
                auto expected=owned.interfaceSnapshot;expected["addresses"]=QJsonArray{};
                if(row==expected)continue;
            }
            interfaces.append(row);
        }
        network["interfaces"]=interfaces;
        dns["nrpt"]=subtract(dns["nrpt"].toArray(),owned.dnsPolicies);
        const auto sources=dns["nrpt_sources"].toArray();
        for(const auto &source:owned.dnsSourceRecords)if(!sources.contains(source))return {};
        dns["nrpt_sources"]=subtract(sources,owned.dnsSourceRecords);
        dns["interfaces"]=subtract(dns["interfaces"].toArray(),owned.dnsInterfaces);
        dns["clients"]=subtract(dns["clients"].toArray(),owned.dnsClients);
        dns["adapters"]=subtract(dns["adapters"].toArray(),owned.dnsAdapters);
        return NetworkPolicySession::OriginalView{network,dns};
    };
}
