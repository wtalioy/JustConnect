#include "connectionsession.h"

ConnectionSession::ConnectionSession(CoreEngine *coreEngine, QObject *parent, NetworkAccess *network)
    : QObject(parent),
      coreEngine(coreEngine), network(network)
{
    coreEngine->setParent(this);
    if (network) {
        network->setParent(this);
        connect(network, &NetworkAccess::prepared, this, [this](const QUuid &id, PlatformOperationResult result) {
            if (id != attempt || state() != ConnectionState::Starting || networkRestore != NetworkRestoreState::Idle
                || currentPhase != ConnectionPhase::NetworkRecovering || coreActive) return;
            if (!result.succeeded()) { networkFailure(result); stop(); }
            else startEngine();
        });
        connect(network, &NetworkAccess::ready, this, [this](const QUuid &id, PlatformOperationResult result) {
            if (id != attempt || state() != ConnectionState::Starting || currentPhase != ConnectionPhase::NetworkPreparing) return;
            if (!result.succeeded()) { networkFailure(result); stop(); }
            else becameReady(ConnectionPhase::CampusReady);
        });
        connect(network, &NetworkAccess::quiesced, this, [this](const QUuid &id) {
            if (id == attempt && networkRestore == NetworkRestoreState::Pending) stopCore();
        });
        connect(network, &NetworkAccess::stopped, this, [this](const QUuid &id, PlatformOperationResult result) {
            if (id != attempt || networkRestore != NetworkRestoreState::Pending) return;
            networkRestore = result.succeeded() ? NetworkRestoreState::Idle : NetworkRestoreState::Failed;
            if (!result.succeeded()) {
                networkFailure(result);
                // A lost helper cannot keep the core's last device reference alive indefinitely.
                if (networkLost) stopCore();
                emit progressChanged();
                return;
            }
            networkStopped = true;
            if (coreActive) stopCore();
            else handleCoreFinished();
        });
        connect(network, &NetworkAccess::restartRequired, this, [this](const QUuid &id, const QString &detail) {
            if (id != attempt || networkStopped || networkLost || !sessionState.interruptForReconnect()) return;
            networkLost = true;
            stableTimer.stop();
            clearAuthentication();
            emit diagnostic(detail);
            emit stateChanged(sessionState.state());
            stopNetwork();
        });
        connect(network, &NetworkAccess::lost, this, [this](const QUuid &id, PlatformOperationResult result) {
            if (id != attempt || !isActive() || networkStopped || networkLost) return;
            networkLost = true;
            networkFailure(result);
            stop();
        });
    }
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
        else if (state()==ConnectionState::Starting && currentPhase != ConnectionPhase::NetworkPreparing) {
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
        if (currentPhase == ConnectionPhase::NetworkPreparing) return;
        if (this->network) {
            currentPhase = ConnectionPhase::NetworkPreparing;
            emit progressChanged();
            this->network->activate(attempt, currentProfile);
        } else becameReady(ConnectionPhase::TransportReady);
    });
    connect(coreEngine, &CoreEngine::finished, this, [this](ConnectionError error) {
        if (!coreActive || !sessionState.isActive()) return;
        coreActive = false;
        waitingCoreStop = false;
        stableTimer.stop();
        clearAuthentication();
        if (error==ConnectionError::SESSION_INVALID) currentPhase=ConnectionPhase::ReauthenticationRequired;
        sessionState.recordError(error);
        if (networkStopped) handleCoreFinished();
        else if (networkRestore != NetworkRestoreState::Failed) stopNetwork();
        else emit progressChanged();
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

    if (engineNeedsStop) emit stateChanged(sessionState.state());
    if (state() != ConnectionState::Stopping || (waitingCoreStop && networkRestore != NetworkRestoreState::Failed)) return;
    if (!networkStopped) stopNetwork();
    else stopCore();
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
    attempt = QUuid::createUuid();
    networkStopped = !network;
    networkRestore = NetworkRestoreState::Idle;
    networkLost = waitingCoreStop = false;
    currentPhase = network ? ConnectionPhase::NetworkRecovering : ConnectionPhase::Initializing;
    observations.clear();
    clearAuthentication();
    emit progressChanged();
    if (network) network->prepare(attempt);
    else startEngine();
}

void ConnectionSession::startEngine()
{
    currentPhase = ConnectionPhase::Initializing;
    emit progressChanged();
    coreActive = true;
    if (!coreEngine->start(currentProfile) && coreActive) {
        coreActive = false;
        sessionState.recordError(ConnectionError::OTHER);
        if (!networkStopped) stopNetwork();
        else handleCoreFinished();
    }
}

void ConnectionSession::becameReady(ConnectionPhase phase)
{
    currentPhase = phase;
    sessionState.connectionEstablished();
    stableTimer.start();
    emit stateChanged(sessionState.state());
}

void ConnectionSession::stopNetwork()
{
    if (networkRestore == NetworkRestoreState::Pending) return;
    networkRestore = NetworkRestoreState::Pending;
    currentPhase = ConnectionPhase::NetworkRestoring;
    emit progressChanged();
    network->stop(attempt);
}

void ConnectionSession::stopCore()
{
    if (!coreActive || waitingCoreStop) return;
    waitingCoreStop = true;
    coreEngine->stop();
}

void ConnectionSession::networkFailure(const PlatformOperationResult &result)
{
    if (result.status != PlatformOperationResult::Status::Cancelled)
        sessionState.recordError(result.status == PlatformOperationResult::Status::PermissionDenied
            ? ConnectionError::PERMISSION_DENIED : ConnectionError::OTHER);
    emit diagnostic(result.detail);
}

void ConnectionSession::handleCoreFinished()
{
    stableTimer.stop();
    // Both releases are confirmed here; real core/recovery errors keep their priority.
    if (networkLost && sessionState.wantsConnection()) sessionState.recordError(ConnectionError::NETWORK_FAILED);
    if (sessionState.error() == ConnectionError::SESSION_INVALID) currentPhase = ConnectionPhase::ReauthenticationRequired;
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
