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
    using OriginalViewFilter = std::function<std::optional<OriginalView>(const QJsonObject &, const QJsonObject &)>;
    using DnsReader = std::function<DnsSnapshot()>;
    NetworkPolicySession(CoreEngine *engine, DnsReader reader, QObject *parent = nullptr);
    ~NetworkPolicySession() override;
    void clear();
    void setNetworkBusy(const QString &generation, bool busy);
    void setOriginalViewFilter(const QString &generation, OriginalViewFilter filter);
    bool refresh();
    bool setCampusAddress(const QString &address, bool campus);
    bool setCampusName(const QString &name, bool campus);
    QString currentGeneration() const { return generation; }
    QJsonArray campusAddresses() const { return confirmedPolicy["campus"].toArray(); }
    QJsonArray campusNames() const { return confirmedPolicy["campus_names"].toArray(); }
    bool isPolicyUpdating() const { return !pendingPolicy.isEmpty(); }
    std::optional<CoreEngine::RequestStatus> policyStatus() const { return lastPolicyStatus; }
    bool isBusy() const { return refreshQueued || networkBusy || workerBusy || networkPending || resourcesPending || isPolicyUpdating(); }
    CoreEngine::RequestStatus status() const { return currentStatus; }
    QJsonObject confirmedProtection() const { return confirmedPolicy; }
    QJsonObject model() const { return currentModel; }
signals:
    void changed();
private:
    struct ModelResult { quint64 serial; CoreEngine::RequestStatus status; QJsonObject model; };
    bool submitPolicy(QJsonObject policy);
    void begin(const QString &generation);
    void buildModel();
    void publish();
    QPointer<CoreEngine> engine;
    DnsReader reader;
    OriginalViewFilter originalViewFilter;
    bool networkBusy = false, refreshQueued = false;
    QFutureWatcher<ModelResult> watcher;
    QString generation;
    quint64 serial = 0;
    quint64 workerSerial = 0;
    bool workerBusy = false, networkPending = false, resourcesPending = false, transportReady = false;
    CoreEngine::RequestStatus networkStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus resourceStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus modelStatus = CoreEngine::RequestStatus::Pending;
    CoreEngine::RequestStatus currentStatus = CoreEngine::RequestStatus::Unavailable;
    QJsonObject network, resources, currentModel;
    QJsonValue networkVersion;
    QJsonObject confirmedPolicy, pendingPolicy;
    quint64 revision = 0;
    std::optional<CoreEngine::RequestStatus> lastPolicyStatus;
};
