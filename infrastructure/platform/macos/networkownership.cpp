#include "networkownership.h"
#include "tunroutes.h"
#include "infrastructure/platform/ipv4.h"
#include <algorithm>
#include <SystemConfiguration/SystemConfiguration.h>
#include <net/route.h>
#include <cstring>

namespace {
QJsonObject projection(const QJsonObject &row)
{
    QJsonObject value{{"destination",row["prefix"]},{"interface_index",row["index"]},{"flags",row["flags"]}};
    const auto raw = QByteArray::fromHex(row["addresses"].toObject()[QString::number(RTAX_GATEWAY)].toString().toLatin1());
    if (raw.size() >= 8 && quint8(raw[1]) == AF_INET) {
        in_addr address{}; std::memcpy(&address,raw.constData()+4,sizeof(address)); char text[INET_ADDRSTRLEN]{};
        if (::inet_ntop(AF_INET,&address,text,sizeof(text))) value["gateway"] = QString::fromLatin1(text);
    }
    return value;
}
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
    if (!configuration.dnsDomains.isEmpty() && expectedDns.toObject() != QJsonObject{
        {QString::fromCFString(kSCPropNetDNSServerAddresses),QJsonArray{configuration.peer}},
        {QString::fromCFString(kSCPropNetDNSSupplementalMatchDomains),QJsonArray::fromStringList(configuration.dnsDomains)}}) return {};
    return [configuration,name,index,owned,dnsKey,expectedDns](QJsonObject network,QJsonObject dns)
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
        if (!expectedDns.isUndefined() && entries[dnsKey] == expectedDns) entries.remove(dnsKey);
        dns["dynamic_store"] = entries;
        return NetworkPolicySession::OriginalView{network,dns};
    };
}
