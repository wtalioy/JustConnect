#pragma once

#include <QElapsedTimer>
#include <QObject>
#include <QTimer>
#include <functional>

class ConnectionSession;
class SystemProxySession;

class ApplicationShutdown : public QObject
{
    Q_OBJECT
public:
    ApplicationShutdown(ConnectionSession *connection, SystemProxySession *proxy,
        std::function<bool()> pendingWork, QObject *parent = nullptr, int timeoutMs = 15000);
    void request();
signals:
    void ready();
    void failed(const QString &code);
private:
    void advance();
    ConnectionSession *connection;
    SystemProxySession *proxy;
    std::function<bool()> pendingWork;
    QTimer poll;
    QElapsedTimer elapsed;
    int timeoutMs;
    bool active = false, complete = false, coreStopRequested = false;
};
