#include "systemproxysession.h"

#include <QtConcurrent>

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

bool SystemProxySession::enable(const SystemProxyConfig &config)
{
    if (needsCleanup()) return false;
    return startOperation(Operation::Enable, config);
}

bool SystemProxySession::disable()
{
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

PlatformOperationResult SystemProxySession::clearBeforeShutdown()
{
    const Operation operation = currentOperation;
    disconnect(&operationWatcher, nullptr, this, nullptr);
    operationWatcher.waitForFinished();
    PlatformOperationResult result;
    if (operation != Operation::None) {
        result = operationWatcher.result().result;
        updateState(operation, result);
    }
    if (operation != Operation::Disable && needsCleanup()) {
        result = backend->clear();
        updateState(Operation::Disable, result);
    }
    currentOperation = Operation::None;
    return result;
}

void SystemProxySession::updateState(Operation operation, const PlatformOperationResult &result)
{
    if (operation == Operation::CheckConflict) return;
    if (result.succeeded()) {
        enabled = operation == Operation::Enable;
        uncertain = false;
    } else if (result.mayHaveChanged) uncertain = true;
}

bool SystemProxySession::startOperation(Operation operation, const SystemProxyConfig &config)
{
    if (isBusy())
    {
        return false;
    }

    currentOperation = operation;
    emit busyChanged(true);

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
    currentOperation = Operation::None;

    const bool wasEnabled = enabled, wasUncertain = uncertain;
    updateState(result.operation, result.result);
    const bool stateChanged = enabled != wasEnabled || uncertain != wasUncertain;

    emit busyChanged(false);

    if (stateChanged)
    {
        emit enabledChanged(isEnabled());
    }

    if (result.operation == Operation::CheckConflict)
    {
        emit conflictCheckFinished(result.check);
    }
    else
    {
        emit operationFinished(isEnabled(), result.result);
    }
}
