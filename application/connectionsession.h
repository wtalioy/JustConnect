#ifndef CONNECTIONSESSION_H
#define CONNECTIONSESSION_H

#include <QObject>
#include <QTimer>
#include <QUrl>
#include <QMap>
#include <QDateTime>
#include <QUuid>
#include "application/platformoperationresult.h"

#include "application/coreengine.h"
#include "core/connectionprofile.h"
#include "core/connectionsessionstate.h"

struct SessionObservation { QString result; QDateTime observedAt; };
enum class ConnectionPhase { Initializing, Starting, Authenticating, AuthenticationSucceeded, Restoring, ReauthenticationRequired, TransportReady, NetworkRecovering, NetworkPreparing, NetworkRestoring, CampusReady };

// The backend confirms ownership recovery before core startup and release before core shutdown.
class NetworkAccess : public QObject
{
    Q_OBJECT
public:
    using QObject::QObject;
    virtual void prepare(const QUuid &attempt) = 0;
    virtual void activate(const QUuid &attempt, const ConnectionProfile &profile) = 0;
    virtual void stop(const QUuid &attempt) = 0;
signals:
    void prepared(const QUuid &attempt, PlatformOperationResult result);
    void ready(const QUuid &attempt, PlatformOperationResult result);
    void stopped(const QUuid &attempt, PlatformOperationResult result);
    void lost(const QUuid &attempt, PlatformOperationResult result);
    void restartRequired(const QUuid &attempt, const QString &detail);
};

class ConnectionSession : public QObject
{
Q_OBJECT

public:
    explicit ConnectionSession(CoreEngine *coreEngine, QObject *parent = nullptr, NetworkAccess *network = nullptr);

    bool start(const ConnectionProfile &profile, const ReconnectPolicy &policy);
    void stop();
    void blockNewConnections();
    void submitResponse(const QJsonObject &response);
    void forgetAuthenticationCache();

    ConnectionState state() const;
    ConnectionPhase phase() const { return currentPhase; }
    SessionObservation observation(const QString &stage) const { return observations.value(stage); }
    bool isActive() const;
    int reconnectAttempt() const { return sessionState.reconnectAttempt(); }
    ProxyOptions proxyOptions() const { return currentProfile.proxy; }
    KeepAliveOptions keepAliveOptions() const { return currentProfile.keepAlive; }

signals:
    void stateChanged(ConnectionState state);
    void diagnostic(const QString &code);
    void progressChanged();
    void authenticationCacheUpdated(const AuthenticationCache &cache);
    void authenticationCacheInvalidated();
    void authenticationRequired(const QJsonObject &request, const QUrl &callbackServer,const TlsOptions &tls);
    void reconnectScheduled(int delayMs);
    void finished(ConnectionError error);

private:
    void startCore();
    void startEngine();
    void stopNetwork();
    void stopCore();
    void becameReady(ConnectionPhase phase);
    void networkFailure(const PlatformOperationResult &result);
    void handleCoreFinished();
    QUrl serverUrl() const;
    void clearAuthentication();

    CoreEngine *coreEngine;
    NetworkAccess *network;
    QUuid attempt;
    enum class NetworkRestoreState { Idle, Pending, Failed };
    NetworkRestoreState networkRestore = NetworkRestoreState::Idle;
    bool coreActive = false, networkStopped = true, waitingCoreStop = false, networkLost = false;
    QTimer reconnectTimer;
    QTimer stableTimer;
    ConnectionSessionState sessionState;
    ConnectionProfile currentProfile;
    ConnectionPhase currentPhase = ConnectionPhase::Initializing;
    QMap<QString,SessionObservation> observations;
    QJsonObject pendingAuthentication;
    QString responseAction;
    bool blocked = false;
};

#endif // CONNECTIONSESSION_H
