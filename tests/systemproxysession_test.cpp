#include <functional>
#include <memory>

#include <QCoreApplication>
#include <QDebug>
#include <QElapsedTimer>
#include <QSemaphore>
#include <QThread>

#include "application/systemproxysession.h"

namespace
{
class FakeSystemProxyBackend : public SystemProxyBackend
{
public:
    bool conflict = false;
    int conflictChecks = 0;
    int applyCalls = 0;
    int clearCalls = 0;
    PlatformOperationResult failure{PlatformOperationResult::Status::Failed, "operation failed"};
    SystemProxyCheck checkResult;
    bool applySucceeds = true;
    bool clearSucceeds = true;
    SystemProxyConfig lastConfig;
    QSemaphore operationStarted;
    QSemaphore allowOperationToFinish;

    SystemProxyCheck check(const SystemProxyConfig &config) override
    {
        ++conflictChecks;
        lastConfig = config;
        auto result = checkResult; result.conflict = conflict; return result;
    }

    PlatformOperationResult apply(const SystemProxyConfig &config) override
    {
        ++applyCalls;
        lastConfig = config;
        operationStarted.release();
        allowOperationToFinish.acquire();
        return applySucceeds ? PlatformOperationResult{} : failure;
    }

    PlatformOperationResult clear() override
    {
        ++clearCalls;
        return clearSucceeds ? PlatformOperationResult{} : failure;
    }
};

bool waitUntil(const std::function<bool()> &condition)
{
    QElapsedTimer timer;
    timer.start();
    while (!condition() && timer.elapsed() < 1000)
    {
        QCoreApplication::processEvents();
        QThread::msleep(1);
    }
    return condition();
}

bool delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState()
{
    auto backend = std::make_unique<FakeSystemProxyBackend>();
    FakeSystemProxyBackend *fake = backend.get();
    fake->conflict = true;
    SystemProxySession session(std::move(backend));
    const SystemProxyConfig config{1081, 1080, "localhost"};
    if(session.disable() || fake->clearCalls!=0) {
        qCritical()<<"a new session must not clear another application's proxy";return false;
    }

    bool conflictResult = false;
    QObject::connect(&session, &SystemProxySession::conflictCheckFinished,
                     [&](const SystemProxyCheck &check) { conflictResult = check.result.succeeded() && check.conflict; });
    if (!session.checkConflict(config)
        || !waitUntil([&]() { return !session.isBusy(); })
        || !conflictResult
        || fake->conflictChecks != 1
        || session.isEnabled())
    {
        qCritical() << "delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState failed at conflict check";
        return false;
    }

    if (!session.enable(config)
        || !fake->operationStarted.tryAcquire(1, 1000)
        || !session.isBusy()
        || session.isEnabled()
        || session.disable())
    {
        qCritical() << "delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState failed while enabling";
        return false;
    }

    fake->allowOperationToFinish.release();
    if (!waitUntil([&]() { return !session.isBusy(); })
        || !session.isEnabled()
        || fake->applyCalls != 1
        || fake->lastConfig.httpPort != 1081
        || fake->lastConfig.socksPort != 1080
        || fake->lastConfig.bypass != "localhost")
    {
        qCritical() << "delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState failed after enabling";
        return false;
    }

    if (session.enable(config) || fake->applyCalls!=1) {
        qCritical()<<"owned state must be restored before applying another configuration";return false;
    }
    if (!session.disable()
        || !waitUntil([&]() { return !session.isBusy(); })
        || session.isEnabled()
        || fake->clearCalls != 1)
    {
        qCritical() << "delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState failed at disable";
        return false;
    }

    if (session.disable() || fake->clearCalls != 1)
    {
        qCritical() << "an already restored session must not clear externally-owned proxy state";
        return false;
    }

    fake->applySucceeds = false;
    if (!session.enable(config)
        || !fake->operationStarted.tryAcquire(1, 1000))
    {
        qCritical() << "failed enable did not start";
        return false;
    }
    fake->allowOperationToFinish.release();
    if (!waitUntil([&]() { return !session.isBusy(); }) || session.isEnabled())
    {
        qCritical() << "failed enable must not change owned state";
        return false;
    }
    fake->applySucceeds = true;

    if (!session.enable(config)
        || !fake->operationStarted.tryAcquire(1, 1000))
    {
        qCritical() << "clearBeforeShutdown failed to start enable";
        return false;
    }
    fake->allowOperationToFinish.release();
    session.clearBeforeShutdown();
    if (session.isBusy()
        || session.isEnabled()
        || fake->applyCalls != 3
        || fake->clearCalls != 2)
    {
        qCritical() << "clearBeforeShutdown must clear an in-flight enable";
        return false;
    }
    return true;
}

bool reportsFailuresAndRetainsCleanupState()
{
    using Status = PlatformOperationResult::Status;
    auto backend = std::make_unique<FakeSystemProxyBackend>();
    auto *fake = backend.get();
    SystemProxySession session(std::move(backend));
    PlatformOperationResult received;
    int completions = 0;
    QObject::connect(&session, &SystemProxySession::operationFinished, [&](bool, const PlatformOperationResult &r) { received = r; ++completions; });
    SystemProxyCheck checked;
    QObject::connect(&session, &SystemProxySession::conflictCheckFinished, [&](const SystemProxyCheck &r) { checked = r; });
    fake->checkResult.result = {Status::PermissionDenied, "query denied"};
    session.checkConflict({1081,1080,{}});
    if (!waitUntil([&] { return !session.isBusy(); }) || checked.result.status != Status::PermissionDenied || fake->applyCalls != 0) return false;
    for (auto status : {Status::Failed, Status::Cancelled, Status::PermissionDenied, Status::Unsupported, Status::TimedOut}) {
        fake->applySucceeds = false; fake->failure = {status, "apply incomplete", true};
        const int before = completions;
        session.enable({1081,1080,{}}); fake->allowOperationToFinish.release();
        if (!waitUntil([&] { return completions > before; }) || received.status != status || session.isEnabled() || !session.needsCleanup()) return false;
        fake->clearSucceeds = false;
        session.disable();
        if (!waitUntil([&] { return !session.isBusy(); }) || !session.needsCleanup() || received.succeeded()) return false;
        fake->clearSucceeds = true;
        session.disable();
        if (!waitUntil([&] { return !session.isBusy(); }) || session.needsCleanup()) return false;
    }
    fake->applySucceeds = true; session.enable({1081,1080,{}}); fake->allowOperationToFinish.release();
    if (!waitUntil([&] { return !session.isBusy(); }) || !session.isEnabled()) return false;
    fake->clearSucceeds = false; fake->failure = {Status::PermissionDenied,"shutdown denied",true};
    auto result = session.clearBeforeShutdown();
    return result.status == Status::PermissionDenied && session.needsCleanup() && !session.isEnabled();
}
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    return delegatesPlatformOperationsAsynchronouslyAndTracksOwnedState() && reportsFailuresAndRetainsCleanupState() ? 0 : 1;
}
