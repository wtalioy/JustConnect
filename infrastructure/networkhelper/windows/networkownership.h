#pragma once
#include "application/networkpolicysession.h"

// Retains the first confirmed private-device snapshot; later reads only subtract exact owned values.
class WindowsNetworkOwnership {
public:
    static std::optional<WindowsNetworkOwnership> capture(const QJsonObject &configuration,const QJsonObject &device,
        const QJsonObject &network,const QJsonObject &dns);
    NetworkPolicySession::OriginalViewFilter filter(const QJsonObject &configuration) const;
private:
    QJsonObject device,peerRoute,interfaceSnapshot;
    QJsonArray automaticRoutes,dnsPolicies,dnsInterfaces,dnsClients,dnsAdapters,dnsSourceRecords;
};
