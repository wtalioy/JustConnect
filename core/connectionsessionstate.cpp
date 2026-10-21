#include "connectionsessionstate.h"

#include <algorithm>

ConnectionState ConnectionSessionState::state() const
{
    return currentState;
}

ConnectionError ConnectionSessionState::error() const
{
    return currentError;
}

bool ConnectionSessionState::isActive() const
{
    return currentState == ConnectionState::Starting
        || currentState == ConnectionState::Running
        || currentState == ConnectionState::Stopping
        || currentState == ConnectionState::Reconnecting;
}

bool ConnectionSessionState::wantsConnection() const
{
    return desiredConnected;
}

int ConnectionSessionState::reconnectDelayMs() const
{
    const int base = std::clamp(reconnectPolicy.delayMs, 1, 30000);
    return std::min(30000, base * (1 << std::max(0, retryCount - 1)));
}

bool ConnectionSessionState::requestStart(const ReconnectPolicy &policy)
{
    if (isActive())
    {
        return false;
    }

    reconnectPolicy = policy;
    retryCount = 0;
    interactiveAuthentication = false;
    desiredConnected = true;
    currentError = ConnectionError::NONE;
    currentState = ConnectionState::Starting;
    return true;
}

void ConnectionSessionState::connectionEstablished()
{
    if (currentState == ConnectionState::Starting)
    {
        currentState = ConnectionState::Running;
        interactiveAuthentication = false;
    }
}

void ConnectionSessionState::connectionStable()
{
    if (currentState == ConnectionState::Running) retryCount = 0;
}

void ConnectionSessionState::recordError(ConnectionError error)
{
    if (currentError == ConnectionError::NONE)
    {
        currentError = error;
    }
}

bool ConnectionSessionState::requestStop()
{
    desiredConnected = false;
    if (currentState == ConnectionState::Reconnecting)
    {
        currentState = ConnectionState::Disconnected;
        currentError = ConnectionError::NONE;
        return false;
    }
    if (currentState == ConnectionState::Starting || currentState == ConnectionState::Running)
    {
        currentState = ConnectionState::Stopping;
        return true;
    }
    return false;
}

SessionFinishAction ConnectionSessionState::engineFinished()
{
    const bool connectionWasEstablished = currentState == ConnectionState::Running;
    if (desiredConnected
        && reconnectPolicy.enabled
        && !interactiveAuthentication
        && retryCount < MaxReconnectAttempts
        && (currentError == ConnectionError::NETWORK_FAILED || currentError == ConnectionError::TIMED_OUT))
    {
        ++retryCount;
        currentState = ConnectionState::Reconnecting;
        return SessionFinishAction::Reconnect;
    }

    desiredConnected = false;
    if (connectionWasEstablished && currentError != ConnectionError::SESSION_INVALID)
    {
        currentState = ConnectionState::Interrupted;
    }
    else
    {
        currentState = currentError == ConnectionError::NONE
            ? ConnectionState::Disconnected
            : ConnectionState::Failed;
    }
    return SessionFinishAction::Complete;
}

void ConnectionSessionState::beginReconnect()
{
    if (currentState == ConnectionState::Reconnecting && desiredConnected)
    {
        currentError = ConnectionError::NONE;
        interactiveAuthentication = false;
        currentState = ConnectionState::Starting;
    }
}
