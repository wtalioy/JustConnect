#include "infrastructure/networkhelper/windows/networkownership.h"
#include <QSet>
#include <QHostAddress>
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
        auto row=peer;row["destination"]=prefix;
        if(!rows.contains(row))rows.append(row);
    }
    return rows;
}
QJsonArray broadcasts(const QJsonObject &configuration,const QJsonObject &localRoute)
{
    QJsonArray rows;
    for(const auto &prefix:configuration["capture_prefixes"].toArray()){
        const auto subnet=QHostAddress::parseSubnet(prefix.toString());
        if(subnet.first.protocol()!=QAbstractSocket::IPv4Protocol || subnet.second<2 || subnet.second>=32)continue;
        const auto last=subnet.first.toIPv4Address()|quint32((quint64(1)<<(32-subnet.second))-1);
        auto row=localRoute;row["destination"]=QHostAddress(last).toString()+"/32";
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
        || !configuration["dns_domains"].isArray() || !dns["nrpt"].isArray()
        || !dns["interfaces"].isArray() || !dns["clients"].isArray())return {};
    WindowsNetworkOwnership result;result.device=device;result.interfaceSnapshot=*adapter;
    for(const auto &item:network["routes"].toArray()){
        const auto row=item.toObject();
        if(row["interface_index"]==device["index"] && row["destination"]==device["address"].toString()+"/32"){
            if(!result.localRoute.isEmpty())return {};
            result.localRoute=row;
        }
        if(row["interface_index"]==device["index"] && row["destination"]==device["peer"].toString()+"/32"){
            if(!result.peerRoute.isEmpty())return {};
            result.peerRoute=row;
        }
    }
    if(result.peerRoute.isEmpty() || !result.localRoute["protocol"].isDouble())return {};
    const auto owned=captures(configuration,result.peerRoute);
    for(const auto &item:network["routes"].toArray())
        if(item.toObject()["interface_index"]==device["index"] && item.toObject().value("protocol")==result.localRoute.value("protocol") && !owned.contains(item))result.automaticRoutes.append(item);
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
    for(const auto &item:dns["interfaces"].toArray())if(item.toObject()["InterfaceIndex"]==device["index"])result.dnsInterfaces.append(item);
    for(const auto &item:dns["clients"].toArray())if(item.toObject()["InterfaceIndex"]==device["index"])result.dnsClients.append(item);
    const auto filter=result.filter(configuration);
    if(!filter || !filter(network,dns))return {};
    return result;
}

NetworkPolicySession::OriginalViewFilter WindowsNetworkOwnership::filter(const QJsonObject &configuration) const
{
    if(configuration["address"]!=device["address"]
        || configuration["peer"]!=device["peer"] || !configuration["capture_prefixes"].isArray())return {};
    const auto required=captures(configuration,peerRoute);
    // Windows derives local broadcast host routes when an on-link capture prefix changes.
    const auto derived=broadcasts(configuration,localRoute);
    return [owned=*this,required,derived](QJsonObject network,QJsonObject dns)->std::optional<NetworkPolicySession::OriginalView>{
        if(!ownedInterface(network,owned.device) || !dns["nrpt"].isArray() || !dns["interfaces"].isArray() || !dns["clients"].isArray())return {};
        auto routes=network["routes"].toArray();
        for(const auto &row:required){const auto at=std::find(routes.begin(),routes.end(),row);if(at==routes.end())return {};routes.erase(at);}
        network["routes"]=subtract(subtract(routes,owned.automaticRoutes),derived);
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
        dns["interfaces"]=subtract(dns["interfaces"].toArray(),owned.dnsInterfaces);
        dns["clients"]=subtract(dns["clients"].toArray(),owned.dnsClients);
        return NetworkPolicySession::OriginalView{network,dns};
    };
}
