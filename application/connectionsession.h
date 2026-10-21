#ifndef CONNECTIONSESSION_H
#define CONNECTIONSESSION_H

#include <QObject>
#include <QTimer>
#include <QUrl>

#include "application/coreengine.h"
#include "core/connectionprofile.h"
#include "core/connectionsessionstate.h"

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
    bool isActive() const;
    ProxyOptions proxyOptions() const { return currentProfile.proxy; }

signals:
    void stateChanged(ConnectionState state);
    void diagnostic(const QString &code);
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
    ConnectionSessionState sessionState;
    ConnectionProfile currentProfile;
    QJsonObject pendingAuthentication;
    QString responseAction;
};

#endif // CONNECTIONSESSION_H
