#pragma once
#include "application/coreengine.h"
#include <QObject>
#include <QPointer>
#include <QList>
#include <QPair>
class ConnectionSession;
class NetworkPolicySession;
class SystemProxySession;

class ConnectionDiagnostics final : public QObject
{
    Q_OBJECT
  public:
    ConnectionDiagnostics(CoreEngine *core, ConnectionSession *connection, NetworkPolicySession *policy,
                          SystemProxySession *proxy, QObject *parent = nullptr);
    QString report() const;
    QList<QPair<QString,QString>> fields() const;
  signals:
    void changed();

  private:
    QPointer<ConnectionSession> connection;
    QPointer<NetworkPolicySession> policy;
    QPointer<SystemProxySession> proxy;
    QString generation, mode, code;
    bool exitKnown = false, clashActive = false, tun = false;
};
