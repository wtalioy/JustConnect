#pragma once

#include "application/coreengine.h"
#include "application/platformoperationresult.h"
#include <QPointer>
#include <functional>
#include <utility>

// Serializes the core's DNS publication requests through the active owned helper.
template<class Helper> class DNSRoutePublisher final : public QObject
{
public:
    DNSRoutePublisher(CoreEngine *core, Helper *helper, QObject *parent = nullptr, std::function<bool()> available = {})
        : QObject(parent), available(std::move(available)), core(core), helper(helper)
    {
        connect(core, &CoreEngine::sessionStarted, this, [this](const QString &value) { generation = value; });
        connect(core, &CoreEngine::dnsRoutesRequired, this, [this](const QJsonObject &request) {
            const auto requested = request["generation"].toString(), id = request["request_id"].toString();
            if (!this->core) return;
            if (requested.isEmpty() || id.isEmpty() || !request["addresses"].isArray() || (this->available && !this->available()) || !this->helper || requested != generation || !pendingRequest.isEmpty() || this->helper->state() != Helper::State::Active) {
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
        connect(helper, &Helper::finished, this,
            [this](typename Helper::Operation operation, PlatformOperationResult result) {
                if (operation == Helper::Operation::Extend) acknowledge(result.succeeded());
            });
        connect(helper, &Helper::ownershipLost, this, [this] { acknowledge(false); });
        connect(core, &CoreEngine::finished, this, [this] {
            generation.clear();
            pendingGeneration.clear();
            pendingRequest.clear();
            if (this->helper && this->helper->state() == Helper::State::Extending) this->helper->cancel();
        });
    }
private:
    void acknowledge(bool applied) {
        const auto requested = std::exchange(pendingGeneration, {}), id = std::exchange(pendingRequest, {});
        if (core && !id.isEmpty()) core->acknowledgeDNSRoutes(requested, id, applied);
    }
    std::function<bool()> available;
    QPointer<CoreEngine> core;
    QPointer<Helper> helper;
    QString generation, pendingGeneration, pendingRequest;
};
