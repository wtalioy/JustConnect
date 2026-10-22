#pragma once

#include "application/coreengine.h"
#include "application/dnssnapshot.h"
#include <QFutureWatcher>
#include <QPointer>
#include <functional>

class NetworkPolicySession : public QObject
{
    Q_OBJECT
public:
    using DnsReader = std::function<DnsSnapshot()>;
    NetworkPolicySession(CoreEngine *engine, DnsReader reader, QObject *parent = nullptr);
    ~NetworkPolicySession() override;
    void clear();
    bool refresh();
    bool setCampusAddress(const QString &address, bool campus);
    QJsonArray campusAddresses() const { return confirmedPolicy["campus"].toArray(); }
    bool isPolicyUpdating() const { return !pendingPolicy.isEmpty(); }
    CoreEngine::RequestStatus policyStatus() const { return lastPolicyStatus; }
    bool isBusy() const { return workerBusy || networkPending || resourcesPending || isPolicyUpdating(); }
    CoreEngine::RequestStatus status() const { return currentStatus; }
    QJsonObject model() const { return currentModel; }
signals:
    void changed();
private:
    struct ModelResult { quint64 serial; CoreEngine::RequestStatus status; QJsonObject model; };
    void begin(const QString &generation);
    void buildModel();
    void publish();
    QPointer<CoreEngine> engine;
    DnsReader reader;
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
    CoreEngine::RequestStatus lastPolicyStatus = CoreEngine::RequestStatus::Unavailable;
};
