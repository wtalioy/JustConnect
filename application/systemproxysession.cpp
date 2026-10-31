#include "systemproxysession.h"

#include <QtConcurrent>
#include <utility>

SystemProxySession::SystemProxySession(
    std::unique_ptr<SystemProxyBackend> backend,
    QObject *parent
)
    : QObject(parent),
      backend(std::move(backend))
{
    connect(&operationWatcher, &QFutureWatcher<OperationResult>::finished,
            this, &SystemProxySession::handleOperationFinished);
}

SystemProxySession::~SystemProxySession()
{
    operationWatcher.waitForFinished();
}

bool SystemProxySession::checkConflict(const SystemProxyConfig &config)
{
    return startOperation(Operation::CheckConflict, config);
}
bool SystemProxySession::inspect() { return startOperation(Operation::Inspect); }

bool SystemProxySession::enable(const SystemProxyConfig &config)
{
    if (needsCleanup()) return false;
    return startOperation(Operation::Enable, config);
}

bool SystemProxySession::disable()
{
    if (currentOperation==Operation::Enable || currentOperation==Operation::CheckConflict || currentOperation==Operation::Inspect) {
        restoreRequested=true;return true;
    }
    if (!needsCleanup()) return false;
    return startOperation(Operation::Disable);
}

bool SystemProxySession::isEnabled() const
{
    return enabled && !uncertain;
}

bool SystemProxySession::isBusy() const
{
    return currentOperation != Operation::None;
}

bool SystemProxySession::needsCleanup() const { return enabled || uncertain; }

void SystemProxySession::updateState(Operation operation, const PlatformOperationResult &result)
{
    if (operation == Operation::CheckConflict || operation == Operation::Inspect) {
        uncertain |= result.mayHaveChanged;
        return;
    }
    if (result.succeeded()) {
        enabled = operation == Operation::Enable;
        uncertain = false;
    } else if (result.mayHaveChanged) uncertain = true;
}

bool SystemProxySession::startOperation(Operation operation, const SystemProxyConfig &config)
{
    const bool continuing=operation==Operation::Disable
        && (currentOperation==Operation::Enable || currentOperation==Operation::CheckConflict || currentOperation==Operation::Inspect) && operationWatcher.isFinished();
    if (isBusy() && !continuing) return false;

    currentOperation = operation;
    if (operation == Operation::Enable) automatic = !config.upstream.isEmpty();
    if (!continuing) emit busyChanged(true);

    SystemProxyBackend *proxyBackend = backend.get();
    operationWatcher.setFuture(QtConcurrent::run(
        [proxyBackend, operation, config]()
        {
            OperationResult result{operation};
            switch (operation)
            {
            case Operation::CheckConflict:
                result.check = proxyBackend->check(config);
                result.result = result.check.result;
                break;
            case Operation::Inspect:
                result.check = proxyBackend->inspect();
                result.result = result.check.result;
                break;
            case Operation::Enable:
                result.result = proxyBackend->apply(config);
                break;
            case Operation::Disable:
                result.result = proxyBackend->clear();
                break;
            case Operation::None:
                break;
            }
            return result;
        }
    ));
    return true;
}

void SystemProxySession::handleOperationFinished()
{
    const OperationResult result = operationWatcher.result();
    const bool wasEnabled = enabled, wasUncertain = uncertain;
    updateState(result.operation, result.result);
    if (!needsCleanup()) automatic = false;
    const bool stateChanged = enabled != wasEnabled || uncertain != wasUncertain;

    const bool restoring=std::exchange(restoreRequested,false) && needsCleanup();
    // A completed apply and its requested restoration are one busy interval.
    if (restoring) startOperation(Operation::Disable);
    else { currentOperation=Operation::None;emit busyChanged(false); }

    if (stateChanged)
    {
        emit enabledChanged(isEnabled());
    }

    if (result.operation == Operation::CheckConflict)
    {
        emit conflictCheckFinished(result.check);
    }
    else if (result.operation == Operation::Inspect)
    {
        emit inspectionFinished(result.check);
    }
    else
    {
        emit operationFinished(isEnabled(), result.result);
    }
}
