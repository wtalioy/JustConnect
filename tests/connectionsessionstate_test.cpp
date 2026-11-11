#include <QCoreApplication>
#include <QDebug>

#include "core/connectionsessionstate.h"

namespace
{
bool normalLifecycle()
{
    ConnectionSessionState session;
    if (!session.requestStart({false, 1000})
        || session.state() != ConnectionState::Starting
        || !session.isActive())
    {
        qCritical() << "normalLifecycle failed at start";
        return false;
    }

    session.connectionEstablished();
    if (session.state() != ConnectionState::Running)
    {
        qCritical() << "normalLifecycle failed at running";
        return false;
    }

    if (!session.requestStop() || session.state() != ConnectionState::Stopping)
    {
        qCritical() << "normalLifecycle failed at stopping";
        return false;
    }

    if (session.engineFinished() != SessionFinishAction::Complete
        || session.state() != ConnectionState::Disconnected
        || session.isActive())
    {
        qCritical() << "normalLifecycle failed at completion";
        return false;
    }
    return true;
}

bool reconnectsOnlyEligibleFailures()
{
    ConnectionSessionState session;
    session.requestStart({true, 2500});
    session.connectionEstablished();
    session.recordError(ConnectionError::NETWORK_FAILED);

    if (session.engineFinished() != SessionFinishAction::Reconnect
        || session.state() != ConnectionState::Reconnecting
        || session.reconnectDelayMs() != 2500)
    {
        qCritical() << "reconnectsOnlyEligibleFailures failed at scheduling";
        return false;
    }

    session.beginReconnect();
    if (session.state() != ConnectionState::Starting || session.error() != ConnectionError::NONE)
    {
        qCritical() << "reconnectsOnlyEligibleFailures failed at restart";
        return false;
    }

    session.recordError(ConnectionError::INVALID_CONFIGURATION);
    if (session.engineFinished() != SessionFinishAction::Complete
        || session.state() != ConnectionState::Failed)
    {
        qCritical() << "reconnectsOnlyEligibleFailures reconnected an ineligible error";
        return false;
    }
    return true;
}

bool keepsFirstErrorAndCancelsPendingReconnect()
{
    ConnectionSessionState session;
    session.requestStart({true, 1000});
    session.connectionEstablished();
    session.recordError(ConnectionError::NETWORK_FAILED);
    session.recordError(ConnectionError::CLIENT_FAILED);
    if (session.error() != ConnectionError::NETWORK_FAILED)
    {
        qCritical() << "keepsFirstErrorAndCancelsPendingReconnect did not keep first error";
        return false;
    }

    session.engineFinished();
    if (session.requestStop()
        || session.state() != ConnectionState::Disconnected
        || session.wantsConnection() || session.error()!=ConnectionError::NONE)
    {
        qCritical() << "keepsFirstErrorAndCancelsPendingReconnect failed to cancel reconnect";
        return false;
    }
    return true;
}

bool establishedConnectionEndsAsInterrupted()
{
    ConnectionSessionState session;
    session.requestStart({false, 1000});
    session.connectionEstablished();
    session.recordError(ConnectionError::NETWORK_FAILED);

    if (session.engineFinished() != SessionFinishAction::Complete
        || session.state() != ConnectionState::Interrupted)
    {
        qCritical() << "establishedConnectionEndsAsInterrupted failed";
        return false;
    }
    return true;
}
bool boundedBackoffAndStableRecovery()
{
    ConnectionSessionState session;
    session.requestStart({true, 5000});
    const int delays[]{5000,10000,20000,30000,30000};
    for (int attempt=0;attempt<5;++attempt) {
        session.connectionEstablished();
        session.recordError(ConnectionError::NETWORK_FAILED);
        if (session.engineFinished()!=SessionFinishAction::Reconnect
            || session.reconnectAttempt()!=attempt+1 || session.reconnectDelayMs()!=delays[attempt]) return false;
        session.beginReconnect();
    }
    session.connectionEstablished();
    session.recordError(ConnectionError::TIMED_OUT);
    if (session.engineFinished()!=SessionFinishAction::Complete || session.isActive()) return false;
    session.requestStart({true,5000});
    session.recordError(ConnectionError::TIMED_OUT);
    session.engineFinished();session.beginReconnect();session.connectionEstablished();
    session.connectionStable();
    session.recordError(ConnectionError::NETWORK_FAILED);
    return session.engineFinished()==SessionFinishAction::Reconnect && session.reconnectAttempt()==1;
}

bool rejectsUnsafeRetriesAndDuplicateStop()
{
    for (auto error : {ConnectionError::OTHER, ConnectionError::CLIENT_FAILED, ConnectionError::SESSION_INVALID, ConnectionError::PERMISSION_DENIED, ConnectionError::TLS_TRUST,
        ConnectionError::TLS_PROTOCOL, ConnectionError::CORE_UNAVAILABLE, ConnectionError::CREDENTIALS_REQUIRED,
        ConnectionError::AUTHENTICATION_CHANGED, ConnectionError::AUTHENTICATION_UNSUPPORTED, ConnectionError::INVALID_CONFIGURATION}) {
        ConnectionSessionState session;
        session.requestStart({true,1});session.recordError(error);
        if (session.engineFinished()!=SessionFinishAction::Complete || session.isActive()) return false;
    }
    ConnectionSessionState session;
    session.requestStart({true,1});session.authenticationRequested();session.recordError(ConnectionError::TIMED_OUT);
    if (session.engineFinished()!=SessionFinishAction::Complete) return false;
    session.requestStart({true,1});
    return session.requestStop() && !session.requestStop()
        && session.engineFinished()==SessionFinishAction::Complete && !session.wantsConnection();
}

bool completedAuthenticationDoesNotDisableNetworkRecovery()
{
    ConnectionSessionState session;
    session.requestStart({true,1});session.authenticationRequested();session.connectionEstablished();
    session.recordError(ConnectionError::NETWORK_FAILED);
    if (session.engineFinished()!=SessionFinishAction::Reconnect || session.reconnectAttempt()!=1) return false;
    session.beginReconnect();session.authenticationRequested();session.connectionEstablished();
    session.recordError(ConnectionError::NETWORK_FAILED);
    return session.engineFinished()==SessionFinishAction::Reconnect && session.reconnectAttempt()==2;
}

bool networkRestartKeepsIntentAndExistingRetryBounds()
{
    ConnectionSessionState session;
    session.requestStart({true,1});
    if (session.interruptForReconnect()) return false;
    for (int attempt=1; attempt<=ConnectionSessionState::MaxReconnectAttempts; ++attempt) {
        session.connectionEstablished();
        if (!session.interruptForReconnect() || session.interruptForReconnect() || !session.wantsConnection()
            || session.state()!=ConnectionState::Stopping) return false;
        session.recordError(ConnectionError::NETWORK_FAILED);
        if (session.engineFinished()!=SessionFinishAction::Reconnect || session.reconnectAttempt()!=attempt) return false;
        session.beginReconnect();
    }
    session.connectionEstablished();session.interruptForReconnect();session.recordError(ConnectionError::NETWORK_FAILED);
    if (session.engineFinished()!=SessionFinishAction::Complete || session.wantsConnection()) return false;
    session.requestStart({true,1});session.connectionEstablished();session.interruptForReconnect();session.requestStop();
    if (session.wantsConnection() || session.engineFinished()!=SessionFinishAction::Complete) return false;
    session.requestStart({true,1});session.connectionEstablished();session.cancelReconnect();
    if (!session.interruptForReconnect() || session.wantsConnection()) return false;
    session.recordError(ConnectionError::NETWORK_FAILED);
    return session.engineFinished()==SessionFinishAction::Complete;
}

}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return networkRestartKeepsIntentAndExistingRetryBounds()
        && completedAuthenticationDoesNotDisableNetworkRecovery()
        && boundedBackoffAndStableRecovery()
        && rejectsUnsafeRetriesAndDuplicateStop()
        && normalLifecycle()
        && reconnectsOnlyEligibleFailures()
        && keepsFirstErrorAndCancelsPendingReconnect()
        && establishedConnectionEndsAsInterrupted()
        ? 0
        : 1;
}
