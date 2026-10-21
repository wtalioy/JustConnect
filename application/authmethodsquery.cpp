#include "authmethodsquery.h"

AuthMethodsQuery::AuthMethodsQuery(CoreEngine *engine,QObject *parent) : QObject(parent),engine(engine) {
    engine->setParent(this);
    connect(engine,&CoreEngine::authMethodsReady,this,[this](const QJsonArray &values) {
        if (!active || cancelled) return;
        methods=values; received=true;
    });
    connect(engine,&CoreEngine::finished,this,[this](ConnectionError error) {
        if (!active) return;
        active=false;
        const auto result=methods; methods={};
        emit settled();
        if (cancelled) return;
        if (error==ConnectionError::NONE && received) emit ready(result);
        else emit failed(error==ConnectionError::NONE ? ConnectionError::INVALID_CONFIGURATION : error);
    });
}
bool AuthMethodsQuery::start(const ConnectionProfile &profile) {
    if (active) return false;
    ConnectionProfile query;
    query.tls=profile.tls;
    query.endpoint.server=profile.endpoint.server; query.endpoint.port=profile.endpoint.port;
    active=true; cancelled=received=false; methods={};
    if (engine->start(query,CoreEngine::Operation::AuthMethods)) return true;
    active=false;
    return false;
}
void AuthMethodsQuery::stop() {
    if (!active || cancelled) return;
    cancelled=true; methods={}; engine->stop();
}
