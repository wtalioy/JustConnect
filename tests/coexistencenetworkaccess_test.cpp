#include "application/coexistencenetworkaccess.h"
#include "application/networkpolicysession.h"
#include <QCoreApplication>
#include <QElapsedTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QSemaphore>
#include <QThread>
#include <functional>
#include <algorithm>

namespace {
void check(bool condition, const char *message) { if (!condition) qFatal("%s", message); }
void until(const std::function<bool()> &condition) {
    QElapsedTimer time; time.start();
    bool done = condition();
    while (!done && time.elapsed() < 3000) { QCoreApplication::processEvents(); QThread::msleep(1); done = condition(); }
    check(done, "asynchronous coexistence operation did not finish");
}
class Proxy final : public SystemProxyBackend {
public:
    QMutex mutex;
    QStringList endpoints{"127.0.0.1:7890"}, original;
    bool owned = false, clearFails = false, blockApply = false;
    int applies = 0, clears = 0, inspections = 0;
    SystemProxyConfig installed;
    QSemaphore entered, release;
    void external(QStringList values) { QMutexLocker lock(&mutex); endpoints = values; owned = false; }
    SystemProxyCheck check(const SystemProxyConfig &) override { return inspect(); }
    SystemProxyCheck inspect() override {
        QMutexLocker lock(&mutex); ++inspections;
        return {{}, false, !endpoints.isEmpty(), owned, owned ? original : endpoints};
    }
    PlatformOperationResult apply(const SystemProxyConfig &config) override {
        if (blockApply) { entered.release(); release.acquire(); }
        QMutexLocker lock(&mutex);
        ::check(!owned && config.upstream.contains(endpoints.value(0)), "automatic apply must match current upstream");
        installed = config; ++applies; original = endpoints; owned = true;
        endpoints = {QString("127.0.0.1:%1").arg(config.httpPort)};
        return {};
    }
    PlatformOperationResult clear() override {
        QMutexLocker lock(&mutex); ++clears;
        if (clearFails) return {PlatformOperationResult::Status::Failed, "restore failed", true};
        if (owned) endpoints = original;
        owned = false;
        return {};
    }
};
class Engine final : public CoreEngine {
public:
    QStringList verified{"127.0.0.1:7890"}, lastEndpoints;
    bool available = true, lastManaged = false, selected = false, listenersEnabled = true;
    int updates = 0;
    RequestStatus refreshStatus = RequestStatus::Success;
    bool start(const ConnectionProfile &, Operation) override { return true; }
    void stop() override {}
    void respond(const QJsonObject &) override {}
    void updateCoexistence(const QString &id, const QStringList &endpoints, bool managed) override {
        ++updates; lastManaged = managed; lastEndpoints = endpoints;
        selected = available && (managed || std::any_of(endpoints.begin(), endpoints.end(), [&](const QString &v) { return verified.contains(v); }));
        emit coexistenceUpdated(id, refreshStatus);
    }
    void readSnapshot(Snapshot kind, const QString &id) override {
        QJsonObject data;
        if (kind == Snapshot::Resources)
            data = {{"resources", QJsonObject{{"listeners", listenersEnabled
                ? QJsonObject{{"http", "127.0.0.1:19381"}, {"socks", "127.0.0.1:19380"}} : QJsonObject{}}}}};
        else if (kind == Snapshot::Coexistence)
            data = {{"coexistence", QJsonObject{{"available", available}, {"active", selected}, {"endpoints", QJsonArray::fromStringList(verified)}}}};
        else { emit snapshotReady(kind, id, {}, RequestStatus::Unavailable); return; }
        emit snapshotReady(kind, id, data, RequestStatus::Success);
    }
};
class Native final : public NetworkAccess {
public:
    int prepares = 0, activations = 0, stops = 0;
    SystemProxySession *proxy;
    explicit Native(SystemProxySession *proxy) : proxy(proxy) {}
    void prepare(const QUuid &id) override { ++prepares; emit prepared(id, {}); }
    void activate(const QUuid &id, const ConnectionProfile &) override { ++activations; emit ready(id, {}); }
    void stop(const QUuid &id) override {
        check(!proxy->isBusy() && !proxy->needsCleanup(), "native capture released before browser restoration");
        ++stops; emit quiesced(id); emit stopped(id, {});
    }
};
struct Fixture {
    Engine core;
    NetworkPolicySession policy{&core, [] { return DnsSnapshot{}; }};
    Proxy *backend = new Proxy;
    SystemProxySession proxy{std::unique_ptr<SystemProxyBackend>(backend)};
    Native *native = new Native(&proxy);
    CoexistenceNetworkAccess access{native, &core, &policy, &proxy};
    QUuid attempt = QUuid::createUuid();
    int prepared = 0, ready = 0, stopped = 0, errors = 0, quiesced = 0;
    Fixture() {
        QObject::connect(&access, &NetworkAccess::prepared, [&](const QUuid &id, PlatformOperationResult r) { check(id == attempt && r.succeeded(), "preparation failed"); ++prepared; });
        QObject::connect(&access, &NetworkAccess::ready, [&](const QUuid &id, PlatformOperationResult r) { check(id == attempt && r.succeeded(), "activation failed"); ++ready; });
        QObject::connect(&access, &NetworkAccess::stopped, [&](const QUuid &id, PlatformOperationResult r) { check(id == attempt, "wrong stop attempt"); ++stopped; if (!r.succeeded()) ++errors; });
        QObject::connect(&access, &NetworkAccess::quiesced, [&](const QUuid &) { ++quiesced; });
    }
    void start() {
        access.prepare(attempt); until([&] { return prepared == 1; });
        check(backend->inspections == 1 && native->prepares == 1, "startup did not recover proxy before native preparation");
        emit core.sessionStarted("42");
        access.activate(attempt, {});
    }
    void change(QStringList endpoints) {
        const auto before = core.updates;
        backend->external(endpoints); access.systemProxyChanged();
        until([&] { return core.updates > before && !proxy.isBusy(); });
        QCoreApplication::processEvents();
    }
};
void followsSwitchesAndRestarts() {
    Fixture f; f.start(); until([&] { return f.ready == 1; });
    check(f.backend->applies == 1 && f.proxy.isAutomatic() && f.core.selected && f.core.lastManaged,
          "startup did not install one owned frontend and select Clash");
    check(f.backend->installed.httpPort == 19381 && f.backend->installed.socksPort == 19380,
          "handoff did not use active core listeners");
    f.change({}); until([&] { return !f.proxy.needsCleanup(); });
    check(!f.core.selected && f.backend->endpoints.isEmpty() && f.ready == 1 && !f.native->stops,
          "system proxy OFF was reversed or campus capture stopped");
    f.core.verified = {"127.0.0.1:7891"}; f.change(f.core.verified);
    until([&] { return f.proxy.isEnabled() && f.core.lastManaged; });
    check(f.backend->applies == 2, "new verified upstream was not handed off");
    int refreshFailures = 0;
    QObject::connect(&f.core, &CoreEngine::diagnostic, [&](const QString &code) { if (code == "coexistence_refresh_failed") ++refreshFailures; });
    f.core.refreshStatus = CoreEngine::RequestStatus::Failed;
    f.access.systemProxyChanged(); until([&] { return refreshFailures == 1; });
    check(f.ready == 1 && !f.native->stops && f.proxy.isEnabled(), "transient Clash query failure stopped campus access");
    f.core.refreshStatus = CoreEngine::RequestStatus::Success;
    const auto before = f.core.updates;
    f.core.verified = {"127.0.0.1:7892"}; f.access.systemProxyChanged();
    until([&] { return f.core.updates > before; });
    check(f.core.selected && f.core.lastManaged && f.backend->applies == 2,
          "core port restart rebuilt the owned frontend or lost the ordinary exit");
    f.core.available = false; f.core.verified.clear();
    const auto unavailable = f.core.updates; f.access.systemProxyChanged();
    until([&] { return f.core.updates > unavailable; });
    check(!f.core.selected && f.proxy.isEnabled() && f.backend->applies == 2,
          "Clash shutdown restored a dead proxy port instead of retaining direct frontend service");
    f.access.stop(f.attempt); until([&] { return f.stopped == 1; });
    check(!f.errors && f.quiesced == 1 && f.native->stops == 1 && !f.proxy.needsCleanup(), "orderly disconnect left ownership");
}
void retainsRestoreResponsibility() {
    Fixture f; f.start(); until([&] { return f.ready == 1; });
    f.backend->clearFails = true; f.access.stop(f.attempt);
    until([&] { return f.stopped == 1; });
    QCoreApplication::processEvents();
    check(f.errors == 1 && f.native->stops == 0 && f.proxy.needsCleanup() && f.backend->clears == 1,
          "failed restore released native capture or retried without an explicit request");
    f.backend->clearFails = false; f.access.stop(f.attempt);
    until([&] { return f.stopped == 2; });
    check(f.errors == 1 && f.native->stops == 1 && !f.proxy.needsCleanup(), "explicit restore retry failed");
}
void cancelsDuringApply() {
    Fixture f; f.backend->blockApply = true; f.start();
    until([&] { return f.backend->entered.tryAcquire(); });
    f.access.stop(f.attempt); f.backend->release.release();
    until([&] { return f.stopped == 1; });
    check(!f.ready && !f.errors && !f.proxy.needsCleanup() && f.backend->clears == 1,
          "cancelled handoff published ready or left its proxy installed");
}
void leavesUnrelatedProxyAndDisabledListenersAlone() {
    Fixture f;
    f.backend->external({"127.0.0.1:9988"});
    f.core.listenersEnabled = false;
    f.start(); until([&] { return f.ready == 1; });
    check(!f.core.selected && !f.proxy.needsCleanup() && !f.backend->applies,
          "unrelated proxy acquired authority or disabled listeners blocked native campus access");
    f.access.stop(f.attempt); until([&] { return f.stopped == 1; });
    check(f.backend->endpoints == QStringList{"127.0.0.1:9988"} && !f.backend->clears,
          "disconnect modified an unrelated proxy");
}
void cancellationBeforeNativePreparationLeavesNoCapture() {
    Fixture f;
    f.access.prepare(f.attempt);
    f.access.stop(f.attempt);
    until([&] { return f.stopped == 1; });
    check(!f.prepared && !f.native->prepares && !f.native->stops && !f.proxy.needsCleanup(),
          "late inspection started a cancelled native attempt");
}
}
int main(int argc, char **argv) {
    QCoreApplication app(argc, argv);
    followsSwitchesAndRestarts(); retainsRestoreResponsibility(); cancelsDuringApply();
    leavesUnrelatedProxyAndDisabledListenersAlone(); cancellationBeforeNativePreparationLeavesNoCapture();
}
