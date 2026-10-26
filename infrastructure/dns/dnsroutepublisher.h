#pragma once

#include "application/coreengine.h"
#include "application/platformoperationresult.h"
#include <QPointer>
#include <functional>
#include <optional>
#include <utility>

// Serializes the core's DNS publication requests through the active owned helper.
template<class Helper> class DNSRoutePublisher final : public QObject
{
public:
    DNSRoutePublisher(CoreEngine *core, Helper *helper, QObject *parent = nullptr, std::function<bool()> available = {},
        std::function<std::optional<QStringList>(const QStringList &)> exclude = {})
        : QObject(parent), available(std::move(available)), exclude(std::move(exclude)), core(core), helper(helper)
    {
        connect(core, &CoreEngine::sessionStarted, this, [this](const QString &value) { generation = value; });
        connect(core, &CoreEngine::dnsRoutesRequired, this, [this](const QJsonObject &request) {
            const auto requested = request["generation"].toString(), id = request["request_id"].toString();
            if (!this->core) return;
            if ((request.contains("exclude") && !request["exclude"].isBool()) || requested.isEmpty() || id.isEmpty() || !request["addresses"].isArray() || (this->available && !this->available()) || !this->helper || requested != generation || !pendingRequest.isEmpty() || this->helper->state() != Helper::State::Active) {
                this->core->acknowledgeDNSRoutes(requested, id, false);
                return;
            }
            QStringList addresses;
            for (const auto &value : request["addresses"].toArray()) {
                if (!value.isString()) { this->core->acknowledgeDNSRoutes(requested, id, false); return; }
                addresses.append(value.toString());
            }
            const bool excluding = request["exclude"].toBool();
            std::optional<QStringList> prefixes;
            if (excluding) {
                if (this->exclude) prefixes = this->exclude(addresses);
                if (!prefixes) { this->core->acknowledgeDNSRoutes(requested, id, false); return; }
            }
            pendingGeneration = requested;
            pendingRequest = id;
            pendingExclusion = excluding;
            if (excluding) this->helper->reconcile(*prefixes);
            else this->helper->extend(addresses);
        });
        connect(helper, &Helper::finished, this,
            [this](typename Helper::Operation operation, PlatformOperationResult result) {
                if (operation == (pendingExclusion ? Helper::Operation::Routes : Helper::Operation::Extend)) acknowledge(result.succeeded());
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
    std::function<std::optional<QStringList>(const QStringList &)> exclude;
    bool pendingExclusion = false;
    QPointer<CoreEngine> core;
    QPointer<Helper> helper;
    QString generation, pendingGeneration, pendingRequest;
};
