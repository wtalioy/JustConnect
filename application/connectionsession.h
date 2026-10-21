#ifndef CONNECTIONSESSION_H
#define CONNECTIONSESSION_H

#include <QObject>
#include <QTimer>
#include <QUrl>
#include <QMap>
#include <QDateTime>

#include "application/coreengine.h"
#include "core/connectionprofile.h"
#include "core/connectionsessionstate.h"

struct SessionObservation { QString result; QDateTime observedAt; };
enum class ConnectionPhase { Initializing, Starting, Authenticating, AuthenticationSucceeded, Restoring, ReauthenticationRequired, TransportReady };

class ConnectionSession : public QObject
{
Q_OBJECT

public:
    explicit ConnectionSession(CoreEngine *coreEngine, QObject *parent = nullptr);

    bool start(const ConnectionProfile &profile, const ReconnectPolicy &policy);
    void stop();
    void submitResponse(const QJsonObject &response);
    void forgetAuthenticationCache();

    ConnectionState state() const;
    ConnectionPhase phase() const { return currentPhase; }
    SessionObservation observation(const QString &stage) const { return observations.value(stage); }
    bool isActive() const;
    int reconnectAttempt() const { return sessionState.reconnectAttempt(); }
    ProxyOptions proxyOptions() const { return currentProfile.proxy; }

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
    void handleCoreFinished();
    QUrl serverUrl() const;
    void clearAuthentication();

    CoreEngine *coreEngine;
    QTimer reconnectTimer;
    QTimer stableTimer;
    ConnectionSessionState sessionState;
    ConnectionProfile currentProfile;
    ConnectionPhase currentPhase = ConnectionPhase::Initializing;
    QMap<QString,SessionObservation> observations;
    QJsonObject pendingAuthentication;
    QString responseAction;
};

#endif // CONNECTIONSESSION_H
