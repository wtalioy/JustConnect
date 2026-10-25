#include "infrastructure/networkhelper/windows/networkhelperpreparation.h"
#include "application/networkprotection.h"

WindowsHelperPreparation prepareWindowsNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu)
{
    using Status=PlatformOperationResult::Status;
    const auto targets=campusCaptureTargets(resources,protection);
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
        {"dns_domains",QJsonArray::fromStringList(targets->dnsDomains)}}};
}
