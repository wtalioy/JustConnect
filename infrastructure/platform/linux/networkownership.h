#pragma once

#include "application/networkpolicysession.h"
#include "networkhelper.h"

// A copied read-only projection; privileged recovery continues to use only root journals.
NetworkPolicySession::OriginalViewFilter linuxOriginalNetworkView(const QUuid &owner,
    const LinuxHelperConfiguration &configuration, const QJsonObject &device, int originalInterfaceIndex);
