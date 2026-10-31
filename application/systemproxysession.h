#ifndef SYSTEMPROXYSESSION_H
#define SYSTEMPROXYSESSION_H

#include <memory>

#include <QFutureWatcher>
#include <QObject>

#include "systemproxybackend.h"

class SystemProxySession : public QObject
{
Q_OBJECT

public:
    explicit SystemProxySession(std::unique_ptr<SystemProxyBackend> backend, QObject *parent = nullptr);
    ~SystemProxySession() override;

    bool checkConflict(const SystemProxyConfig &config);
    bool inspect();
    bool enable(const SystemProxyConfig &config);
    bool disable();
    bool isEnabled() const;
    bool isBusy() const;
    bool needsCleanup() const;
    bool isAutomatic() const { return automatic; }

signals:
    void enabledChanged(bool enabled);
    void busyChanged(bool busy);
    void conflictCheckFinished(const SystemProxyCheck &check);
    void inspectionFinished(const SystemProxyCheck &check);
    void operationFinished(bool enabled, const PlatformOperationResult &result);

private:
    enum class Operation
    {
        None,
        CheckConflict,
        Inspect,
        Enable,
        Disable
    };

    struct OperationResult
    {
        Operation operation;
        SystemProxyCheck check;
        PlatformOperationResult result;
    };

    bool startOperation(Operation operation, const SystemProxyConfig &config = {});
    void handleOperationFinished();

    std::unique_ptr<SystemProxyBackend> backend;
    QFutureWatcher<OperationResult> operationWatcher;
    Operation currentOperation = Operation::None;
    bool enabled = false;
    bool uncertain = false;
    bool restoreRequested = false;
    bool automatic = false;
    void updateState(Operation operation, const PlatformOperationResult &result);
};

#endif // SYSTEMPROXYSESSION_H
