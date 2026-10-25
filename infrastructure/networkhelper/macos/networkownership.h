#pragma once
#include "application/networkpolicysession.h"
#include "infrastructure/networkhelper/macos/networkhelper.h"

std::optional<QJsonObject> macOriginalExitSnapshot(const QJsonObject &network, const QString &interface);

// This read-only projection grants no authority to restore native state.
NetworkPolicySession::OriginalViewFilter macOriginalNetworkView(const QUuid &owner,
    const MacHelperConfiguration &configuration,const QJsonObject &device,const QJsonObject &confirmed);
