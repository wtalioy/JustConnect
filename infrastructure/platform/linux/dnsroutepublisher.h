#pragma once

#include "application/coreengine.h"
#include "networkhelperclient.h"
#include <QPointer>

// Serializes the core's DNS publication requests through the active owned helper.
class LinuxDNSRoutePublisher final : public QObject
{
public:
    LinuxDNSRoutePublisher(CoreEngine *core, LinuxNetworkHelperClient *helper, QObject *parent = nullptr, std::function<bool()> available = {});
private:
    void acknowledge(bool applied);
    std::function<bool()> available;
    QPointer<CoreEngine> core;
    QPointer<LinuxNetworkHelperClient> helper;
    QString generation, pendingGeneration, pendingRequest;
};
