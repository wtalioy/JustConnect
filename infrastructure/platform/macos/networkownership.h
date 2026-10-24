#pragma once
#include "application/networkpolicysession.h"
#include "networkhelper.h"

// This read-only projection grants no authority to restore native state.
NetworkPolicySession::OriginalViewFilter macOriginalNetworkView(const QUuid &owner,
    const MacHelperConfiguration &configuration,const QJsonObject &device,const QJsonObject &confirmed);
