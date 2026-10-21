#include "application/applicationshutdown.h"
#include "application/connectionsession.h"
#include "application/systemproxysession.h"

#include <QCoreApplication>
#include <QElapsedTimer>
#include <QSemaphore>
#include <QThread>
#include <atomic>
#include <cstdlib>
#include <iostream>

static void check(bool ok,const char *message) {
    if (!ok) {std::cerr << message << '\n';std::exit(1);}
}
template<class Predicate> static void until(Predicate done) {
    QElapsedTimer timer;timer.start();
    while (!done() && timer.elapsed()<2000) {QCoreApplication::processEvents();QThread::msleep(1);}
    check(done(),"shutdown operation timed out");
}
class Engine : public CoreEngine {
public:
    int starts=0,stops=0;
    bool start(const ConnectionProfile &,Operation) override {++starts;return true;}
    void respond(const QJsonObject &) override {}
    void stop() override {++stops;}
};
class Proxy : public SystemProxyBackend {
public:
    bool blockedApply=false,blockedClear=false,failClear=false;
    std::atomic<int> applies=0,clears=0;
    QSemaphore entered,proceed;
    SystemProxyCheck check(const SystemProxyConfig &) override {return {};}
    PlatformOperationResult apply(const SystemProxyConfig &) override {
        ++applies;if (blockedApply) {entered.release();proceed.acquire();}return {};
    }
    PlatformOperationResult clear() override {
        ++clears;if (blockedClear) {entered.release();proceed.acquire();}
        return failClear ? PlatformOperationResult{PlatformOperationResult::Status::PermissionDenied,"fixture",true} : PlatformOperationResult{};
    }
};
static void restoresBeforeStoppingAndWaitsForWrites() {
    auto *engine=new Engine;ConnectionSession connection(engine);
    auto backend=std::make_unique<Proxy>();auto *native=backend.get();SystemProxySession proxy(std::move(backend));
    native->blockedApply=true;native->blockedClear=true;
    connection.start({},{});proxy.enable({1081,1080,{}});
    check(native->entered.tryAcquire(1,1000),"apply did not start");
    bool pending=true;int ready=0,failed=0;
    ApplicationShutdown shutdown(&connection,&proxy,[&]{return pending;});
    QObject::connect(&shutdown,&ApplicationShutdown::ready,[&]{++ready;});
    QObject::connect(&shutdown,&ApplicationShutdown::failed,[&](const QString &){++failed;});
    shutdown.request();shutdown.request();
    check(engine->stops==0 && !connection.start({},{}),"in-flight apply must finish before stopping core");
    native->proceed.release();until([&]{return native->clears==1;});
    check(native->entered.tryAcquire(1,1000) && engine->stops==0,"restoration remains asynchronous before core stop");
    native->proceed.release();until([&]{return engine->stops==1;});
    check(!ready && !proxy.needsCleanup(),"restoration must be confirmed first");
    emit engine->finished(ConnectionError::NONE);QCoreApplication::processEvents();
    check(!ready,"credential continuations must finish before quit");
    pending=false;until([&]{return ready==1;});shutdown.request();
    check(!failed && engine->stops==1 && native->clears==1 && !connection.start({},{}),"shutdown must be idempotent and forbid restart");
}
static void timeoutRetainsLiveObjectsAndBlocksReconnect() {
    auto *engine=new Engine;ConnectionSession connection(engine);SystemProxySession proxy(std::make_unique<Proxy>());
    connection.start({},{true,1});
    int failed=0,ready=0;
    ApplicationShutdown shutdown(&connection,&proxy,[]{return false;},nullptr,20);
    QObject::connect(&shutdown,&ApplicationShutdown::failed,[&](const QString &code){check(code=="shutdown_timeout","wrong timeout reason");++failed;});
    QObject::connect(&shutdown,&ApplicationShutdown::ready,[&]{++ready;});
    shutdown.request();shutdown.request();until([&]{return failed==1;});
    check(!ready && engine->stops==1 && connection.isActive() && !connection.start({},{}),"timeout must not pretend the core stopped");
    emit engine->finished(ConnectionError::NETWORK_FAILED);
    check(connection.state()!=ConnectionState::Reconnecting,"timeout must disable retry intent");
    shutdown.request();until([&]{return ready==1;});
    check(engine->starts==1 && engine->stops==1,"late cleanup must not restart or stop twice");
}
static void failedRestoreIsReportedAndCanBeRetriedExplicitly() {
    auto *engine=new Engine;ConnectionSession connection(engine);
    auto backend=std::make_unique<Proxy>();auto *native=backend.get();SystemProxySession proxy(std::move(backend));
    proxy.enable({1081,1080,{}});until([&]{return !proxy.isBusy();});
    connection.start({},{});native->failClear=true;
    int failed=0,ready=0;
    ApplicationShutdown shutdown(&connection,&proxy,[]{return false;});
    QObject::connect(&shutdown,&ApplicationShutdown::failed,[&](const QString &code){check(code=="shutdown_proxy_unrestored","wrong restoration reason");++failed;});
    QObject::connect(&shutdown,&ApplicationShutdown::ready,[&]{++ready;});
    shutdown.request();until([&]{return engine->stops==1;});emit engine->finished(ConnectionError::NONE);
    until([&]{return failed==1;});
    check(proxy.needsCleanup() && !ready && native->clears==1,"failed restoration must retain ownership without an automatic loop");
    native->failClear=false;shutdown.request();until([&]{return ready==1;});
    check(!proxy.needsCleanup() && native->clears==2,"explicit retry must restore remaining changes");
}
static void pendingPlatformAndCredentialTimeoutsKeepEventLoopAlive() {
    for (bool platform : {false,true}) {
        auto *engine=new Engine;ConnectionSession connection(engine);
        auto backend=std::make_unique<Proxy>();auto *native=backend.get();SystemProxySession proxy(std::move(backend));
        if (platform) {
            proxy.enable({1081,1080,{}});until([&]{return !proxy.isBusy();});native->blockedClear=true;
        }
        connection.start({},{});int failures=0,ready=0,ticks=0;
        ApplicationShutdown shutdown(&connection,&proxy,[&]{return !platform;},nullptr,25);
        QObject::connect(&shutdown,&ApplicationShutdown::failed,[&](const QString &code){check(code=="shutdown_timeout","pending work timeout reason");++failures;});
        QObject::connect(&shutdown,&ApplicationShutdown::ready,[&]{++ready;});
        QTimer heartbeat;heartbeat.setInterval(1);QObject::connect(&heartbeat,&QTimer::timeout,[&]{++ticks;});heartbeat.start();
        shutdown.request();
        if (!platform) emit engine->finished(ConnectionError::NONE);
        until([&]{return failures==1;});
        check(!ready && ticks>2 && !connection.start({},{}),"timeout must remain responsive without false readiness");
        if (platform) {
            check(proxy.isBusy() && engine->stops==1,"timed out platform operation must retain its owner");
            native->proceed.release();until([&]{return !proxy.isBusy();});emit engine->finished(ConnectionError::NONE);
        }
    }
}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    pendingPlatformAndCredentialTimeoutsKeepEventLoopAlive();
    restoresBeforeStoppingAndWaitsForWrites();
    timeoutRetainsLiveObjectsAndBlocksReconnect();
    failedRestoreIsReportedAndCanBeRetriedExplicitly();
}
