#include "connectionsession.h"

ConnectionSession::ConnectionSession(CoreEngine *coreEngine, QObject *parent)
    : QObject(parent),
      coreEngine(coreEngine)
{
    coreEngine->setParent(this);
    reconnectTimer.setSingleShot(true);
    stableTimer.setSingleShot(true);
    stableTimer.setInterval(60000);
    connect(&stableTimer, &QTimer::timeout, this, [this] { sessionState.connectionStable(); });
    connect(coreEngine, &CoreEngine::diagnostic, this, &ConnectionSession::diagnostic);
    connect(coreEngine, &CoreEngine::observation, this, [this](const QString &stage,const QString &result,const QDateTime &observedAt) {
        // The adapter delivers generation-checked events in ABI order; wall time can move backwards.
        if ((state()!=ConnectionState::Starting && state()!=ConnectionState::Running) || !observedAt.isValid()) return;
        observations[stage]={result,observedAt};
        if (stage=="library" && state()==ConnectionState::Starting) currentPhase=ConnectionPhase::Starting;
        else if (stage=="authentication" && result=="required") currentPhase=ConnectionPhase::ReauthenticationRequired;
        else if (state()==ConnectionState::Starting) {
            if (stage=="restore") currentPhase=result=="succeeded" ? ConnectionPhase::AuthenticationSucceeded : ConnectionPhase::Restoring;
            else if (stage=="authentication") currentPhase=result=="succeeded" ? ConnectionPhase::AuthenticationSucceeded : ConnectionPhase::Authenticating;
        }
        emit progressChanged();
    });
    connect(coreEngine,&CoreEngine::authenticationCacheUpdated,this,[this](const AuthenticationCache &cache) {
        if (!currentProfile.behavior.rememberAuthentication
            || (state()!=ConnectionState::Starting && state()!=ConnectionState::Running)) return;
        currentProfile.authenticationCache=cache;
        emit authenticationCacheUpdated(cache);
    });
    connect(coreEngine,&CoreEngine::authenticationCacheInvalidated,this,[this] {
        if (!currentProfile.behavior.rememberAuthentication
            || (state()!=ConnectionState::Starting && state()!=ConnectionState::Running)) return;
        currentProfile.authenticationCache={};
        emit authenticationCacheInvalidated();
    });
    connect(coreEngine, &CoreEngine::authenticationRequired, this, [this](const QJsonObject &request) {
        if (sessionState.state() != ConnectionState::Starting) return;
        currentPhase=ConnectionPhase::Authenticating;
        emit progressChanged();
        sessionState.authenticationRequested();
        pendingAuthentication = request;
        responseAction.clear();
        emit authenticationRequired(request, serverUrl(),currentProfile.tls);
    });
    connect(coreEngine, &CoreEngine::responseRejected, this, [this] {
        responseAction.clear();
        if (!pendingAuthentication.isEmpty() && sessionState.state() == ConnectionState::Starting)
            emit authenticationRequired(pendingAuthentication, serverUrl(),currentProfile.tls);
    });
    connect(coreEngine, &CoreEngine::responseAccepted, this, [this] {
        if (responseAction == "cancel") stop();
        else clearAuthentication();
    });
    connect(coreEngine, &CoreEngine::connectionEstablished, this, [this] {
        clearAuthentication();
        if (sessionState.state() != ConnectionState::Starting) return;
        currentPhase=ConnectionPhase::TransportReady;
        sessionState.connectionEstablished();
        stableTimer.start();
        emit stateChanged(sessionState.state());
    });
    connect(coreEngine, &CoreEngine::finished, this, [this](ConnectionError error) {
        if (!sessionState.isActive()) return;
        clearAuthentication();
        if (error==ConnectionError::SESSION_INVALID) currentPhase=ConnectionPhase::ReauthenticationRequired;
        sessionState.recordError(error);
        handleCoreFinished();
    });
    connect(&reconnectTimer, &QTimer::timeout, this, [this]()
    {
        if (sessionState.state() != ConnectionState::Reconnecting)
        {
            return;
        }
        sessionState.beginReconnect();
        emit stateChanged(sessionState.state());
        startCore();
    });
}

bool ConnectionSession::start(const ConnectionProfile &profile, const ReconnectPolicy &policy)
{
    if (blocked || !sessionState.requestStart(policy))
    {
        return false;
    }

    currentProfile = profile;
    if (!currentProfile.behavior.rememberAuthentication) currentProfile.authenticationCache={};
    emit stateChanged(sessionState.state());
    startCore();
    return true;
}

void ConnectionSession::blockNewConnections()
{
    blocked=true;
    reconnectTimer.stop();
    stableTimer.stop();
    sessionState.cancelReconnect();
}

void ConnectionSession::stop()
{
    stableTimer.stop();
    clearAuthentication();
    const ConnectionState previousState = sessionState.state();
    const bool engineNeedsStop = sessionState.requestStop();
    if (previousState == ConnectionState::Reconnecting)
    {
        reconnectTimer.stop();
        emit stateChanged(sessionState.state());
        emit finished(sessionState.error());
        return;
    }

    if (engineNeedsStop)
    {
        emit stateChanged(sessionState.state());
        coreEngine->stop();
    }
}

void ConnectionSession::forgetAuthenticationCache()
{
    currentProfile.authenticationCache={};
    currentProfile.behavior.rememberAuthentication=false;
}

void ConnectionSession::submitResponse(const QJsonObject &response)
{
    if (pendingAuthentication.isEmpty() || !responseAction.isEmpty()
        || response["generation"] != pendingAuthentication["generation"]
        || response["request_id"] != pendingAuthentication["request_id"]
        || sessionState.state() != ConnectionState::Starting) return;
    responseAction = response["action"].toString();
    coreEngine->respond(response);
}

QUrl ConnectionSession::serverUrl() const
{
    QUrl url;
    url.setScheme("https");
    url.setHost(currentProfile.endpoint.server);
    url.setPort(currentProfile.endpoint.port);
    return url;
}

ConnectionState ConnectionSession::state() const
{
    return sessionState.state();
}

bool ConnectionSession::isActive() const
{
    return sessionState.isActive();
}

void ConnectionSession::startCore()
{
    currentPhase=ConnectionPhase::Initializing;
    observations.clear();
    emit progressChanged();
    clearAuthentication();
    if (!coreEngine->start(currentProfile)) {
        sessionState.recordError(ConnectionError::OTHER);
        handleCoreFinished();
    }
}

void ConnectionSession::handleCoreFinished()
{
    stableTimer.stop();
    if (sessionState.engineFinished() == SessionFinishAction::Reconnect)
    {
        emit stateChanged(sessionState.state());
        emit reconnectScheduled(sessionState.reconnectDelayMs());
        reconnectTimer.start(sessionState.reconnectDelayMs());
        return;
    }

    emit stateChanged(sessionState.state());
    emit finished(sessionState.error());
}

void ConnectionSession::clearAuthentication()
{
    pendingAuthentication = {};
    responseAction.clear();
}
