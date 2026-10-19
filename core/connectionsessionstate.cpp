#include "connectionsessionstate.h"

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
    return reconnectPolicy.delayMs;
}

bool ConnectionSessionState::requestStart(const ReconnectPolicy &policy)
{
    if (isActive())
    {
        return false;
    }

    reconnectPolicy = policy;
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
    }
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
        return false;
    }
    if (currentState == ConnectionState::Starting || currentState == ConnectionState::Running)
    {
        currentState = ConnectionState::Stopping;
        return true;
    }
    return currentState == ConnectionState::Stopping;
}

ProcessFinishAction ConnectionSessionState::processFinished()
{
    const bool connectionWasEstablished = currentState == ConnectionState::Running;
    if (desiredConnected
        && reconnectPolicy.enabled
        && isReconnectable(currentError))
    {
        currentState = ConnectionState::Reconnecting;
        return ProcessFinishAction::Reconnect;
    }

    desiredConnected = false;
    if (connectionWasEstablished)
    {
        currentState = ConnectionState::Interrupted;
    }
    else
    {
        currentState = currentError == ConnectionError::NONE
            ? ConnectionState::Disconnected
            : ConnectionState::Failed;
    }
    return ProcessFinishAction::Complete;
}

void ConnectionSessionState::beginReconnect()
{
    if (currentState == ConnectionState::Reconnecting && desiredConnected)
    {
        currentError = ConnectionError::NONE;
        currentState = ConnectionState::Starting;
    }
}

bool ConnectionSessionState::isReconnectable(ConnectionError error)
{
    return error == ConnectionError::AUTH_EXPIRED || error == ConnectionError::OTHER;
}
