#pragma once

#include "application/connectionsession.h"
#include "application/systemproxysession.h"
#include <QTimer>

class NetworkPolicySession;

// One lifecycle owns the browser handoff and native campus capture.
class CoexistenceNetworkAccess final : public NetworkAccess
{
    Q_OBJECT
public:
    CoexistenceNetworkAccess(NetworkAccess *native, CoreEngine *core, NetworkPolicySession *policy,
                             SystemProxySession *proxy, QObject *parent = nullptr);
    void prepare(const QUuid &attempt) override;
    void activate(const QUuid &attempt, const ConnectionProfile &profile) override;
    void stop(const QUuid &attempt) override;
    void systemProxyChanged();
private:
    enum class Stage { Idle, Recovering, Preparing, Prepared, Activating, Synchronizing, Ready, Stopping, StopFailed };
    enum class Pending { None, Inspect, Resources, Update, Snapshot, Owners, Enable, Clear };
    void drive();
    void inspectFinished(const SystemProxyCheck &check);
    void proxyFinished(const PlatformOperationResult &result);
    void finishCycle();
    void fail(const PlatformOperationResult &result);
    void failObservation(const PlatformOperationResult &result);
    void driveStop();
    NetworkAccess *native;
    CoreEngine *core;
    SystemProxySession *proxy;
    QUuid attempt;
    QString generation;
    Stage stage = Stage::Idle;
    Pending pending = Pending::None;
    SystemProxyCheck observed;
    SystemProxyConfig frontend;
    QJsonArray listenerProofs;
    QJsonObject attemptedListenerRequest;
    QTimer scheduled;
    bool dirty = true, refreshRequested = false, nativeStopping = false, nativeEngaged = false, listenersKnown = false;
};
