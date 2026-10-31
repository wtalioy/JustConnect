#include "coexistencenetworkaccess.h"
#include "application/networkpolicysession.h"
#include <QUrl>
#include <algorithm>

namespace {
using Status = CoreEngine::RequestStatus;
using Result = PlatformOperationResult;
Result failed(const QString &detail) { return {Result::Status::Failed, detail}; }
int listenerPort(const QJsonValue &value) {
    const QUrl url("http://" + value.toString());
    return url.host() == "127.0.0.1" && url.userInfo().isEmpty() && url.path().isEmpty()
        && url.query().isEmpty() && url.fragment().isEmpty() ? url.port(0) : 0;
}
}

CoexistenceNetworkAccess::CoexistenceNetworkAccess(NetworkAccess *nativeAccess, CoreEngine *engine,
    NetworkPolicySession *policy, SystemProxySession *systemProxy, QObject *parent)
    : NetworkAccess(parent), native(nativeAccess), core(engine), proxy(systemProxy)
{
    native->setParent(this);
    scheduled.setSingleShot(true);
    connect(&scheduled, &QTimer::timeout, this, &CoexistenceNetworkAccess::drive);
    connect(core, &CoreEngine::sessionStarted, this, [this](const QString &id) {
        if (stage == Stage::Prepared) generation = id;
    });
    connect(native, &NetworkAccess::prepared, this, [this](const QUuid &id, Result result) {
        if (id != attempt || stage != Stage::Preparing) return;
        stage = Stage::Prepared;
        emit prepared(id, result);
    });
    connect(native, &NetworkAccess::ready, this, [this](const QUuid &id, Result result) {
        if (id != attempt || stage != Stage::Activating) return;
        if (!result.succeeded()) { emit ready(id, result); return; }
        stage = Stage::Synchronizing;
        dirty = refreshRequested = true;
        scheduled.start();
    });
    connect(native, &NetworkAccess::quiesced, this, [this](const QUuid &id) {
        if (id == attempt && stage == Stage::Stopping && nativeStopping) emit quiesced(id);
    });
    connect(native, &NetworkAccess::stopped, this, [this](const QUuid &id, Result result) {
        if (id != attempt || stage != Stage::Stopping || !nativeStopping) return;
        nativeStopping = false;
        stage = result.succeeded() ? Stage::Idle : Stage::StopFailed;
        emit stopped(id, result);
    });
    connect(native, &NetworkAccess::lost, this, &NetworkAccess::lost);
    connect(native, &NetworkAccess::restartRequired, this, &NetworkAccess::restartRequired);
    connect(proxy, &SystemProxySession::inspectionFinished, this, &CoexistenceNetworkAccess::inspectFinished);
    connect(proxy, &SystemProxySession::operationFinished, this, [this](bool, const Result &result) { proxyFinished(result); });
    connect(proxy, &SystemProxySession::busyChanged, this, [this](bool busy) {
        if (!busy) scheduled.start();
    });
    connect(core, &CoreEngine::coexistenceUpdated, this, [this](const QString &id, Status status) {
        if (id != generation || pending != Pending::Update || (stage != Stage::Synchronizing && stage != Stage::Ready)) return;
        if (status != Status::Success) {
            pending = Pending::None;
            if (stage == Stage::Ready) emit this->core->diagnostic("coexistence_refresh_failed");
            else fail(failed("Cannot confirm the ordinary Clash exit."));
            return;
        }
        pending = Pending::Snapshot;
        this->core->readSnapshot(CoreEngine::Snapshot::Coexistence, generation);
    });
    connect(core, &CoreEngine::snapshotReady, this,
        [this](CoreEngine::Snapshot kind, const QString &id, const QJsonObject &data, Status status) {
        if (id != generation || (stage != Stage::Synchronizing && stage != Stage::Ready)) return;
        if (kind == CoreEngine::Snapshot::Resources && pending == Pending::Resources) {
            pending = Pending::None;
            if (status != Status::Success) { fail(failed("Cannot read active browser proxy listeners.")); return; }
            const auto listeners = data["resources"].toObject()["listeners"].toObject();
            frontend.httpPort = listenerPort(listeners["http"]);
            frontend.socksPort = listenerPort(listeners["socks"]);
            listenersKnown = true;
            drive();
        } else if (kind == CoreEngine::Snapshot::Coexistence && pending == Pending::Snapshot) {
            pending = Pending::None;
            if (status != Status::Success) { fail(failed("Cannot confirm the Clash coexistence state.")); return; }
            const auto state = data["coexistence"].toObject();
            QStringList upstream;
            for (const auto &value : state["endpoints"].toArray()) upstream.append(value.toString());
            if (proxy->isAutomatic() && proxy->needsCleanup() && !observed.managed) {
                pending = Pending::Clear;
                if (!proxy->disable()) { pending = Pending::None; fail(failed("Cannot release the changed browser proxy.")); }
                return;
            }
            if (!proxy->needsCleanup() && observed.active && state["available"].toBool()
                && std::any_of(observed.endpoints.begin(), observed.endpoints.end(), [&](const QString &endpoint) { return upstream.contains(endpoint); })) {
                if (frontend.httpPort < 1 || frontend.socksPort < 1) {
                    fail({Result::Status::Unsupported, "Automatic browser coexistence requires both local HTTP and SOCKS listeners."}); return;
                }
                frontend.upstream = upstream;
                pending = Pending::Enable;
                if (!proxy->enable(frontend)) { pending = Pending::None; fail(failed("Cannot hand off the browser proxy.")); }
                return;
            }
            finishCycle();
        }
    });
    connect(policy, &NetworkPolicySession::changed, this, [this, policy] {
        if (stage == Stage::Ready && !policy->isBusy() && policy->status() == Status::Success) {
            refreshRequested = true;
            scheduled.start();
        }
    });
}

void CoexistenceNetworkAccess::prepare(const QUuid &id) {
    if (stage != Stage::Idle) return;
    attempt = id;
    generation.clear();
    frontend = {};
    observed = {};
    pending = Pending::None;
    dirty = true;
    refreshRequested = nativeStopping = false;
    nativeEngaged = listenersKnown = false;
    stage = Stage::Recovering;
    drive();
}
void CoexistenceNetworkAccess::activate(const QUuid &id, const ConnectionProfile &profile) {
    if (id != attempt || stage != Stage::Prepared) return;
    stage = Stage::Activating;
    native->activate(id, profile);
}
void CoexistenceNetworkAccess::stop(const QUuid &id) {
    if (id != attempt || stage == Stage::Idle || (stage == Stage::Stopping && nativeStopping)) return;
    stage = Stage::Stopping;
    pending = Pending::None;
    if (proxy->isBusy()) proxy->disable();
    driveStop();
}
void CoexistenceNetworkAccess::systemProxyChanged() {
    dirty = refreshRequested = true;
    if (stage == Stage::Ready || stage == Stage::Synchronizing) scheduled.start();
}
void CoexistenceNetworkAccess::drive() {
    if (stage == Stage::Stopping) { driveStop(); return; }
    if (pending != Pending::None || proxy->isBusy()) return;
    if (stage == Stage::Recovering || ((stage == Stage::Synchronizing || stage == Stage::Ready) && dirty)) {
        dirty = false;
        pending = Pending::Inspect;
        if (!proxy->inspect()) pending = Pending::None;
        return;
    }
    if ((stage != Stage::Synchronizing && stage != Stage::Ready) || !refreshRequested) return;
    if (generation.isEmpty()) { fail(failed("The active core generation is unavailable.")); return; }
    if (!listenersKnown) {
        pending = Pending::Resources;
        core->readSnapshot(CoreEngine::Snapshot::Resources, generation);
        return;
    }
    refreshRequested = false;
    pending = Pending::Update;
    core->updateCoexistence(generation, observed.endpoints, observed.managed && proxy->isAutomatic());
}
void CoexistenceNetworkAccess::inspectFinished(const SystemProxyCheck &check) {
    if (pending != Pending::Inspect || stage == Stage::Stopping || stage == Stage::StopFailed) return;
    pending = Pending::None;
    if (!check.result.succeeded() && (check.result.status != Result::Status::Unsupported || check.result.mayHaveChanged)) {
        fail(check.result); return;
    }
    observed = check;
    if (stage == Stage::Recovering) {
        stage = Stage::Preparing;
        nativeEngaged = true;
        native->prepare(attempt);
    } else drive();
}
void CoexistenceNetworkAccess::proxyFinished(const Result &result) {
    if (stage == Stage::Stopping) {
        if (!result.succeeded()) { stage = Stage::StopFailed; emit stopped(attempt, result); }
        else scheduled.start();
        return;
    }
    if (pending != Pending::Enable && pending != Pending::Clear) return;
    pending = Pending::None;
    if (!result.succeeded()) { fail(result); return; }
    dirty = refreshRequested = true;
    scheduled.start();
}
void CoexistenceNetworkAccess::finishCycle() {
    if (stage == Stage::Synchronizing) { stage = Stage::Ready; emit ready(attempt, {}); }
    if (dirty || refreshRequested) scheduled.start();
}
void CoexistenceNetworkAccess::fail(const Result &result) {
    if (stage == Stage::Recovering) emit prepared(attempt, result);
    else if (stage == Stage::Synchronizing) emit ready(attempt, result);
    else if (stage == Stage::Ready) emit lost(attempt, result);
}
void CoexistenceNetworkAccess::driveStop() {
    if (proxy->isBusy() || nativeStopping) return;
    if (proxy->needsCleanup()) {
        if (!proxy->disable()) { stage = Stage::StopFailed; emit stopped(attempt, failed("Cannot restore the browser proxy.")); }
        return;
    }
    nativeStopping = true;
    if (!nativeEngaged) {
        stage = Stage::Idle;
        nativeStopping = false;
        emit quiesced(attempt);
        emit stopped(attempt, {});
        return;
    }
    native->stop(attempt);
}
