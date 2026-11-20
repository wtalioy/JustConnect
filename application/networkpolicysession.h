#pragma once

#include "application/coreengine.h"
#include "application/dnssnapshot.h"
#include <QFutureWatcher>
#include <QPointer>
#include <functional>
#include <optional>
#include <utility>

class NetworkPolicySession : public QObject
{
    Q_OBJECT
public:
    using OriginalView = std::pair<QJsonObject, QJsonObject>;
    // The optional failure out-parameter lets platform ownership filters name
    // exactly which snapshot expectation was violated.
    using OriginalViewFilter = std::function<std::optional<OriginalView>(const QJsonObject &, const QJsonObject &, QString *)>;
    using PolicyApplier = std::function<void(const QJsonObject &)>;
    using DnsReader = std::function<DnsSnapshot()>;
    NetworkPolicySession(CoreEngine *engine, DnsReader reader, QObject *parent = nullptr,
        std::function<bool()> captureRequired = {});
    ~NetworkPolicySession() override;
    void clear();
    void setNetworkBusy(const QString &generation, bool busy);
    void setOriginalViewFilter(const QString &generation, OriginalViewFilter filter);
    void setPolicyApplier(const QString &generation, PolicyApplier applier);
    void completePolicy(const QString &generation, const QString &revision, CoreEngine::RequestStatus status);
    bool refresh();
    // Observation entry point: refreshes immediately when idle, otherwise
    // coalesces the change into one queued follow-up instead of dropping it
    // (publish() drains the queue once the busy flags clear).
    void requestRefresh();
    CoreEngine::RequestStatus synchronizeProtection();
    bool setCampusAddress(const QString &address, bool campus);
    bool setCampusName(const QString &name, bool campus);
    QString currentGeneration() const { return localProxy ? QString{} : generation; }
    QJsonArray campusAddresses() const { return confirmedPolicy["campus"].toArray(); }
    QJsonArray campusNames() const { return confirmedPolicy["campus_names"].toArray(); }
    bool isPolicyUpdating() const { return !pendingPolicy.isEmpty(); }
    std::optional<CoreEngine::RequestStatus> policyStatus() const { return lastPolicyStatus; }
    bool isBusy() const { return refreshQueued || networkBusy || workerBusy || networkPending || resourcesPending || isPolicyUpdating(); }
    CoreEngine::RequestStatus status() const { return currentStatus; }
    QJsonObject confirmedProtection() const { return confirmedPolicy; }
    QJsonObject model() const { return currentStatus == CoreEngine::RequestStatus::Success ? lastModel : QJsonObject{}; }
    QJsonObject localProxyResources() const { return localProxy && resourceStatus == CoreEngine::RequestStatus::Success ? resources : QJsonObject{}; }
    // Names the read or projection behind a non-Success status, for failure diagnostics.
    QString failureDetail() const;
signals:
    void changed();
private:
    struct ModelResult { quint64 serial; CoreEngine::RequestStatus status; QJsonObject model; QString reason; };
    bool submitPolicy(QJsonObject policy);
    void begin(const QString &generation, bool proxyOnly);
    void buildModel();
    static ModelResult finishModel(quint64 request, const QString &generation, const QJsonValue &version,
        const QJsonObject &campus, const QJsonObject &previous, const OriginalView &view);
    void publish();
    QPointer<CoreEngine> engine;
    DnsReader reader;
    OriginalViewFilter originalViewFilter;
    PolicyApplier policyApplier;
    bool networkBusy = false, refreshQueued = false, waitingForPolicyModel = false;
    QFutureWatcher<ModelResult> watcher;
    QString generation;
    quint64 serial = 0;
    quint64 workerSerial = 0;
    bool workerBusy = false, networkPending = false, resourcesPending = false, transportReady = false;
    bool localProxy = false;
    CoreEngine::RequestStatus networkStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus resourceStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus modelStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus currentStatus = CoreEngine::RequestStatus::Unavailable;
    QJsonObject network, resources, lastModel;
    QString modelFailureReason;
    QJsonValue networkVersion;
    QJsonObject confirmedPolicy, pendingPolicy;
    quint64 revision = 0;
    std::optional<CoreEngine::RequestStatus> lastPolicyStatus;
};
