#ifndef CONNECTIONSESSIONSTATE_H
#define CONNECTIONSESSIONSTATE_H

#include "connectionerror.h"

enum class ConnectionState
{
    Disconnected,
    Starting,
    Running,
    Stopping,
    Reconnecting,
    Interrupted,
    Failed,
};

struct ReconnectPolicy
{
    bool enabled = false;
    int delayMs = 1000;
};

enum class SessionFinishAction
{
    Complete,
    Reconnect,
};

class ConnectionSessionState
{
public:
    ConnectionState state() const;
    ConnectionError error() const;
    bool isActive() const;
    bool wantsConnection() const;
    void cancelReconnect() { desiredConnected = false; }
    int reconnectDelayMs() const;
    int reconnectAttempt() const { return retryCount; }
    static constexpr int MaxReconnectAttempts = 5;
    static constexpr int MaxReconnectDelayMs = 30000;
    void connectionStable();
    void authenticationRequested() { interactiveAuthentication = true; }

    bool requestStart(const ReconnectPolicy &policy);
    void connectionEstablished();
    void recordError(ConnectionError error);
    bool requestStop();
    SessionFinishAction engineFinished();
    void beginReconnect();

private:
    ConnectionState currentState = ConnectionState::Disconnected;
    ConnectionError currentError = ConnectionError::NONE;
    ReconnectPolicy reconnectPolicy;
    bool desiredConnected = false;
    bool interactiveAuthentication = false;
    int retryCount = 0;
};

#endif // CONNECTIONSESSIONSTATE_H
