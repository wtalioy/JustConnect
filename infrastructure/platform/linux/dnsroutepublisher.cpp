#include "dnsroutepublisher.h"
#include <utility>

LinuxDNSRoutePublisher::LinuxDNSRoutePublisher(CoreEngine *core, LinuxNetworkHelperClient *helper, QObject *parent)
    : QObject(parent), core(core), helper(helper)
{
    connect(core, &CoreEngine::sessionStarted, this, [this](const QString &value) { generation = value; });
    connect(core, &CoreEngine::dnsRoutesRequired, this, [this](const QJsonObject &request) {
        const auto requested = request["generation"].toString(), id = request["request_id"].toString();
        if (!this->core) return;
        if (!this->helper || requested != generation || !pendingRequest.isEmpty() || this->helper->state() != LinuxNetworkHelperClient::State::Active) {
            this->core->acknowledgeDNSRoutes(requested, id, false);
            return;
        }
        QStringList addresses;
        for (const auto &value : request["addresses"].toArray()) {
            if (!value.isString()) { this->core->acknowledgeDNSRoutes(requested, id, false); return; }
            addresses.append(value.toString());
        }
        pendingGeneration = requested;
        pendingRequest = id;
        this->helper->extend(addresses);
    });
    connect(helper, &LinuxNetworkHelperClient::finished, this,
        [this](LinuxNetworkHelperClient::Operation operation, PlatformOperationResult result) {
            if (operation == LinuxNetworkHelperClient::Operation::Extend) acknowledge(result.succeeded());
        });
    connect(helper, &LinuxNetworkHelperClient::ownershipLost, this, [this] { acknowledge(false); });
    connect(core, &CoreEngine::finished, this, [this] {
        generation.clear();
        pendingGeneration.clear();
        pendingRequest.clear();
        if (this->helper && this->helper->state() == LinuxNetworkHelperClient::State::Extending) this->helper->cancel();
    });
}

void LinuxDNSRoutePublisher::acknowledge(bool applied)
{
    const auto requested = std::exchange(pendingGeneration, {}), id = std::exchange(pendingRequest, {});
    if (core && !id.isEmpty()) core->acknowledgeDNSRoutes(requested, id, applied);
}
