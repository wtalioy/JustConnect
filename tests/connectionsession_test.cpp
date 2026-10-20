#include <QCoreApplication>
#include <QDebug>

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

    bool start(const ConnectionProfile &, Operation = Operation::Connect) override
    {
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
    engine->complete(ConnectionError::OTHER);

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

}

int main(int argc, char *argv[])
{
    QCoreApplication application(argc, argv);
    return delegatesSessionLifecycleThroughPort()
        && distinguishesInterruptedConnectionFromStartupFailure()
        && authenticatesOnlyTheCurrentRequest()
        && authenticationTimeoutEndsWaitAndAllowsManualRetry() ? 0 : 1;
}
