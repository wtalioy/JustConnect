#include "networkhelperpreparation.h"
#include "application/networkprotection.h"
#include <QNetworkInterface>

MacHelperPreparation prepareMacNetworkHelper(const QJsonObject &resources,const QJsonObject &protection,
    const QJsonObject &network,const QJsonObject &dns,const QString &localDNS,int mtu)
{
    using Status = PlatformOperationResult::Status;
    const auto targets = campusCaptureTargets(resources,protection);
    if (!targets || targets->ipv4Prefixes.isEmpty()) return {{Status::Unsupported,"Cannot derive safe campus capture targets."},{}};
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
    return {{},result};
}
