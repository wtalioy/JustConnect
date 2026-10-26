#pragma once

#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/linux/networkhelper.h"

// A copied read-only projection; privileged recovery continues to use only root journals.
NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const QUuid &owner,
    const LinuxHelperConfiguration &configuration, const QJsonObject &device, int originalInterfaceIndex);

// Compare the projected original DNS facts with the sources prepared for this session.
bool linuxOriginalDnsSourcesMatch(const LinuxHelperConfiguration &configuration, const QJsonObject &network, const QJsonObject &dns);
