#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>

#include "application/connectionsession.h"

namespace
{
class FakeCoreEngine : public CoreEngine
{
public:
    int startCalls = 0;
    int stopCalls = 0;
    QJsonObject lastResponse;
    bool acceptResponse = true;
    ConnectionProfile lastProfile;

    bool start(const ConnectionProfile &profile, Operation = Operation::Connect) override
    {
        lastProfile=profile;
        ++startCalls;
        return true;
    }

    void stop() override
    {
        ++stopCalls;
    }

    void respond(const QJsonObject &response) override {
        lastResponse = response;
        if (acceptResponse) emit responseAccepted();
    }

    void complete(ConnectionError error = ConnectionError::NONE)
    {
        emit finished(error);
    }

    void establishConnection()
    {
        emit connectionEstablished();
    }


};

class FakeNetworkAccess : public NetworkAccess
{
public:
    QUuid attempt;
    int preparations = 0, activations = 0, stops = 0;
    void prepare(const QUuid &id) override { attempt = id; ++preparations; }
    void activate(const QUuid &id, const ConnectionProfile &) override { if (id == attempt) ++activations; }
    void stop(const QUuid &id) override { if (id == attempt) ++stops; }
};

bool ordersNetworkOwnershipAroundTheCore()
{
    auto *engine = new FakeCoreEngine;
    auto *network = new FakeNetworkAccess;
    ConnectionSession session(engine, nullptr, network);
    int finishes = 0;
    QObject::connect(&session, &ConnectionSession::finished, [&](ConnectionError) { ++finishes; });
    if (!session.start({}, {}) || engine->startCalls || network->preparations != 1
        || session.phase() != ConnectionPhase::NetworkRecovering) return false;
    const auto first = network->attempt;
    emit network->prepared(QUuid::createUuid(), {});
    if (engine->startCalls) return false;
    emit network->prepared(first, {});
    emit network->prepared(first, {});
    if (engine->startCalls != 1) return false;
    engine->establishConnection();engine->establishConnection();
    if (session.state() != ConnectionState::Starting || network->activations != 1
        || session.phase() != ConnectionPhase::NetworkPreparing) return false;
    emit engine->observation("renewal", "succeeded", QDateTime::currentDateTimeUtc());
    if (session.phase() != ConnectionPhase::NetworkPreparing) return false;
    emit network->ready(QUuid::createUuid(), {});
    if (session.state() != ConnectionState::Starting) return false;
    emit network->ready(first, {});
    if (session.state() != ConnectionState::Running || session.phase() != ConnectionPhase::CampusReady) return false;
    session.stop();session.stop();
    if (network->stops != 1 || engine->stopCalls || !session.isActive()) return false;
    emit network->ready(first, {});
    emit network->stopped(first, {PlatformOperationResult::Status::Failed, "keep responsibility", true});
    if (!session.isActive() || engine->stopCalls || session.start({}, {})) return false;
    session.stop();
    if (network->stops != 2) return false;
    emit network->stopped(first, {});
    emit network->stopped(first, {});
    if (engine->stopCalls != 1 || finishes) return false;
    engine->complete();
    if (session.isActive() || finishes != 1) return false;
    if (!session.start({}, {}) || network->attempt == first) return false;
    emit network->prepared(first, {});emit network->ready(first, {});emit network->stopped(first, {});
    if (engine->startCalls != 1 || network->activations != 1) return false;
    session.stop();
    emit network->prepared(network->attempt, {});
    if (engine->startCalls != 1) return false;
    emit network->stopped(network->attempt, {});
    return !session.isActive() && finishes == 2 && engine->stopCalls == 1;
}

bool restoresBeforeReconnectAndDoesNotLoopAuthorization()
{
    auto *engine = new FakeCoreEngine;
    auto *network = new FakeNetworkAccess;
    ConnectionSession session(engine, nullptr, network);
    session.start({}, {true, 1});
    emit network->prepared(network->attempt, {});
    engine->establishConnection();emit network->ready(network->attempt, {});
    engine->complete(ConnectionError::NETWORK_FAILED);
    if (network->stops != 1 || network->preparations != 1 || session.phase() != ConnectionPhase::NetworkRestoring) return false;
    QCoreApplication::processEvents();
    if (engine->startCalls != 1 || session.state() == ConnectionState::Reconnecting) return false;
    emit network->stopped(network->attempt, {});
    QElapsedTimer elapsed;elapsed.start();
    while (network->preparations == 1 && elapsed.elapsed() < 3000) QCoreApplication::processEvents();
    if (network->preparations != 2 || engine->startCalls != 1 || session.reconnectAttempt() != 1) return false;
    emit network->prepared(network->attempt, {});
    engine->establishConnection();
    emit network->ready(network->attempt, {PlatformOperationResult::Status::PermissionDenied, "denied"});
    if (network->stops != 2 || engine->stopCalls) return false;
    emit network->stopped(network->attempt, {});
    if (engine->stopCalls != 1) return false;
    engine->complete();
    QCoreApplication::processEvents();
    return session.state() == ConnectionState::Failed && !session.isActive() && network->preparations == 2;
}

bool delegatesSessionLifecycleThroughPort()
{
    auto *engine = new FakeCoreEngine();
    ConnectionSession session(engine);
    ConnectionProfile profile;
    int finishedCalls = 0;
    QObject::connect(
        &session,
        &ConnectionSession::finished,
        [&](ConnectionError) { ++finishedCalls; }
    );

    if (!session.start(profile, {})
        || engine->startCalls != 1
        || session.state() != ConnectionState::Starting
        || !session.isActive()
        || session.start(profile, {}))
    {
        qCritical() << "start delegation failed";
        return false;
    }

    engine->establishConnection();
    if (session.state() != ConnectionState::Running)
    {
        qCritical() << "connection establishment was not reflected";
        return false;
    }

    session.stop();
    if (engine->stopCalls != 1
        || session.state() != ConnectionState::Stopping)
    {
        qCritical() << "input or stop delegation failed";
        return false;
    }

    engine->complete();
    if (finishedCalls != 1
        || session.state() != ConnectionState::Disconnected
        || session.isActive())
    {
        qCritical() << "completion delegation failed";
        return false;
    }
    return true;
}

bool distinguishesInterruptedConnectionFromStartupFailure()
{
    auto *engine = new FakeCoreEngine();
    ConnectionSession session(engine);
    ConnectionProfile profile;

    session.start(profile, {});
    engine->establishConnection();
    engine->complete(ConnectionError::NETWORK_FAILED);

    if (session.state() != ConnectionState::Interrupted)
    {
        qCritical() << "established connection was reported as startup failure";
        return false;
    }
    return true;
}

bool authenticatesOnlyTheCurrentRequest()
{
    auto *engine = new FakeCoreEngine;
    ConnectionSession session(engine);
    ConnectionProfile profile;
    session.start(profile, {});
    QJsonObject request{{"schema_version", 1}, {"generation", "1"}, {"request_id", "1"}};
    emit engine->authenticationRequired(request);
    auto answer = CoreEngine::responseFor(request, {{"action", "submit"}, {"code", "验证码"}, {"skip_secondary_auth", true}});
    engine->acceptResponse = false;
    session.submitResponse(answer);
    if (engine->lastResponse != answer) return false;
    session.submitResponse(CoreEngine::responseFor(request, {{"action", "cancel"}}));
    if (engine->lastResponse != answer || engine->stopCalls) return false;
    emit engine->responseRejected();
    engine->acceptResponse = true;
    session.submitResponse(answer);
    auto stale = answer;
    stale["action"] = "cancel";
    stale["generation"] = "0";
    session.submitResponse(stale);
    if (engine->stopCalls || engine->lastResponse != answer) return false;
    stale["generation"] = "1";
    stale["request_id"] = "0";
    session.submitResponse(stale);
    if (engine->stopCalls) return false;
    session.submitResponse(CoreEngine::responseFor(request, {{"action", "cancel"}}));
    if (engine->stopCalls != 0) return false;
    request["request_id"] = "2";
    emit engine->authenticationRequired(request);
    session.submitResponse(CoreEngine::responseFor(request, {{"action", "cancel"}}));
    if (engine->stopCalls != 1 || session.state() != ConnectionState::Stopping) return false;
    engine->complete();
    session.start(profile, {});
    request["generation"] = "2";
    emit engine->authenticationRequired(request);
    session.submitResponse(answer);
    if (engine->stopCalls != 1 || engine->lastResponse["action"] != "cancel") return false;
    return true;
}

bool authenticationTimeoutEndsWaitAndAllowsManualRetry()
{
    auto *engine=new FakeCoreEngine;
    ConnectionSession session(engine);
    ConnectionProfile profile;
    int reconnects=0;
    QObject::connect(&session,&ConnectionSession::reconnectScheduled,[&](int){++reconnects;});
    session.start(profile,{true,1});
    QJsonObject request{{"schema_version",1},{"generation","1"},{"request_id","1"}};
    emit engine->authenticationRequired(request);
    const auto expired=CoreEngine::responseFor(request,{{"action","submit"},{"code","old-code"}});
    engine->complete(ConnectionError::TIMED_OUT);
    session.submitResponse(expired);
    if(session.state()!=ConnectionState::Failed || session.isActive() || reconnects || !engine->lastResponse.isEmpty())return false;
    if(!session.start(profile,{}))return false;
    request["generation"]="2";request["request_id"]="2";
    emit engine->authenticationRequired(request);
    session.submitResponse(expired);
    if(!engine->lastResponse.isEmpty())return false;
    const auto current=CoreEngine::responseFor(request,{{"action","submit"},{"code","new-code"}});
    session.submitResponse(current);
    return engine->lastResponse==current && engine->startCalls==2;
}

bool cacheFollowsSessionPolicyAndExplicitClear()
{
    auto *engine=new FakeCoreEngine;
    ConnectionSession session(engine);
    ConnectionProfile profile;
    profile.behavior.rememberAuthentication=true;
    profile.credentials.username="login-alias";
    profile.authenticationCache={"canonical-account","original"};
    int updates=0,invalidations=0;
    QObject::connect(&session,&ConnectionSession::authenticationCacheUpdated,[&](const AuthenticationCache &){++updates;});
    QObject::connect(&session,&ConnectionSession::authenticationCacheInvalidated,[&]{++invalidations;});
    const auto reconnect=[&] {
        const auto before=engine->startCalls;
        engine->establishConnection();engine->complete(ConnectionError::NETWORK_FAILED);
        QElapsedTimer timer;timer.start();
        while(engine->startCalls==before && timer.elapsed()<3000) QCoreApplication::processEvents();
        return engine->startCalls==before+1;
    };
    if (!session.start(profile,{true,1})) return false;
    emit engine->authenticationCacheUpdated({"canonical-account","refreshed"});
    if (!reconnect() || engine->lastProfile.authenticationCache.data!="refreshed"
        || engine->lastProfile.credentials.username!="login-alias" || updates!=1) return false;
    emit engine->authenticationCacheInvalidated();
    if (!reconnect() || !engine->lastProfile.authenticationCache.data.isEmpty() || invalidations!=1) return false;
    emit engine->authenticationCacheUpdated({"canonical-account","new authentication"});
    if (!reconnect() || engine->lastProfile.authenticationCache.data!="new authentication") return false;
    session.forgetAuthenticationCache();
    emit engine->authenticationCacheUpdated({"canonical-account","late refresh"});
    emit engine->authenticationCacheInvalidated();
    if (!reconnect() || !engine->lastProfile.authenticationCache.data.isEmpty()
        || engine->lastProfile.behavior.rememberAuthentication || updates!=2 || invalidations!=1) return false;
    session.stop();
    emit engine->authenticationCacheUpdated({"canonical-account","during stop"});
    engine->complete();
    emit engine->authenticationCacheUpdated({"canonical-account","after stop"});
    if (updates!=2) return false;
    profile.behavior.rememberAuthentication=false;
    if (!session.start(profile,{}) || !engine->lastProfile.authenticationCache.data.isEmpty()) return false;
    emit engine->authenticationCacheUpdated({"canonical-account","not allowed"});
    engine->complete();
    return updates==2;
}

bool cancellingBackoffPreventsLateRestart()
{
    auto *engine=new FakeCoreEngine;
    ConnectionSession session(engine);
    int finishes=0;
    QObject::connect(&session,&ConnectionSession::finished,[&](ConnectionError){++finishes;});
    session.start({}, {true,1});engine->complete(ConnectionError::NETWORK_FAILED);
    if (session.state()!=ConnectionState::Reconnecting) return false;
    session.stop();session.stop();
    QElapsedTimer timer;timer.start();
    while(timer.elapsed()<30) QCoreApplication::processEvents();
    if (engine->startCalls!=1 || engine->stopCalls || finishes!=1 || session.isActive()) return false;
    session.start({},{});session.stop();session.stop();engine->establishConnection();engine->complete();
    return engine->startCalls==2 && engine->stopCalls==1 && finishes==2 && session.state()==ConnectionState::Disconnected;
}

bool progressUsesObservedEventsAndRejectsLateResults()
{
    auto *engine=new FakeCoreEngine;
    ConnectionSession session(engine);
    const auto now=QDateTime::currentDateTimeUtc();
    session.start({},{});
    if (session.phase()!=ConnectionPhase::Initializing || session.observation("renewal").observedAt.isValid()) return false;
    emit engine->diagnostic("transport_connected");
    if (session.state()!=ConnectionState::Starting) return false;
    emit engine->observation("library","succeeded",now);
    if (session.phase()!=ConnectionPhase::Starting) return false;
    emit engine->observation("restore","running",now);
    if (session.phase()!=ConnectionPhase::Restoring) return false;
    emit engine->observation("restore","succeeded",now.addMSecs(1));
    if (session.phase()!=ConnectionPhase::AuthenticationSucceeded) return false;
    engine->establishConnection();
    if (session.phase()!=ConnectionPhase::TransportReady) return false;
    emit engine->observation("renewal","succeeded",now);
    emit engine->observation("renewal","failed",now.addSecs(-3600));
    if (session.observation("renewal").result!="failed" || session.observation("renewal").observedAt!=now.addSecs(-3600)) return false;
    emit engine->observation("renewal","running",now.addSecs(-3600));
    if (session.observation("renewal").result!="running") return false;
    session.stop();emit engine->observation("renewal","failed",now.addMSecs(2));engine->complete();
    if (session.observation("renewal").result!="running") return false;
    session.start({},{});
    if (session.observation("renewal").observedAt.isValid()) return false;
    engine->establishConnection();
    emit engine->observation("authentication","required",now);
    engine->complete(ConnectionError::SESSION_INVALID);
    return session.phase()==ConnectionPhase::ReauthenticationRequired && session.state()==ConnectionState::Failed;
}

}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    return ordersNetworkOwnershipAroundTheCore()
        && restoresBeforeReconnectAndDoesNotLoopAuthorization()
        && progressUsesObservedEventsAndRejectsLateResults()
        && cancellingBackoffPreventsLateRestart()
        && delegatesSessionLifecycleThroughPort()
        && distinguishesInterruptedConnectionFromStartupFailure()
        && authenticatesOnlyTheCurrentRequest()
        && cacheFollowsSessionPolicyAndExplicitClear()
        && authenticationTimeoutEndsWaitAndAllowsManualRetry() ? 0 : 1;
}
