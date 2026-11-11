#include "applicationshutdown.h"

#include "connectionsession.h"
#include "systemproxysession.h"

ApplicationShutdown::ApplicationShutdown(ConnectionSession *connection, SystemProxySession *proxy,
    std::function<bool()> pendingWork, QObject *parent, int timeoutMs)
    : QObject(parent), connection(connection), proxy(proxy), pendingWork(std::move(pendingWork)), timeoutMs(timeoutMs)
{
    connect(connection,&ConnectionSession::finished,this,[this] {
        if (!active && !complete) this->proxy->disable();
    });
    connect(connection,&ConnectionSession::stateChanged,this,[this](ConnectionState state) {
        if (state==ConnectionState::Reconnecting && !active && !complete) this->proxy->disable();
    });
    poll.setInterval(10);
    connect(&poll, &QTimer::timeout, this, &ApplicationShutdown::advance);
}

void ApplicationShutdown::request()
{
    if (active || complete) return;
    active = true;
    coreStopRequested = false;
    connection->blockNewConnections();
    elapsed.start();
    proxy->disable();
    poll.start();
    advance();
}

void ApplicationShutdown::advance()
{
    if (!active) return;
    const bool timedOut = elapsed.elapsed() >= timeoutMs;
    if (!coreStopRequested && (!proxy->isBusy() || timedOut)) {
        coreStopRequested = true;
        connection->stop();
    }
    const bool pending = proxy->isBusy() || connection->isActive() || pendingWork();
    if (!timedOut && pending) return;
    poll.stop();
    active = false;
    if (pending || proxy->needsCleanup()) {
        emit failed(pending ? QStringLiteral("shutdown_timeout") : QStringLiteral("shutdown_proxy_unrestored"));
        return;
    }
    complete = true;
    emit ready();
}
