#pragma once
#include "application/systemproxybackend.h"
#include <memory>
#include <functional>
#include <QJsonObject>
#ifdef Q_OS_WIN
#include "infrastructure/systemproxy/windows/proxyapi.h"
#elif defined(Q_OS_MACOS)
#include "infrastructure/systemproxy/macos/proxyapi.h"
#else
#include "infrastructure/process/command.h"
#endif

class PlatformSystemProxyBackend : public SystemProxyBackend
{
public:
    // Success confirms durable publication; an empty object removes the record. Caller holds the recovery lock.
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
#ifdef Q_OS_WIN
    explicit PlatformSystemProxyBackend(WindowsProxyApi api = {}, CheckpointWriter writer = {})
        : api(api), checkpointWriter(std::move(writer)) {}
#elif defined(Q_OS_MACOS)
    explicit PlatformSystemProxyBackend(MacProxyApi api = {}, CheckpointWriter writer = {})
        : api(std::move(api)), checkpointWriter(std::move(writer)) {}
#else
    explicit PlatformSystemProxyBackend(PlatformCommandRunner runner = [](const QString &p, const QStringList &a) {
        return runPlatformCommand(p, a);
    }, CheckpointWriter writer = {}) : runner(std::move(runner)), checkpointWriter(std::move(writer)) {}
#endif
    PlatformSystemProxyBackend(const PlatformSystemProxyBackend &) = delete;
    PlatformSystemProxyBackend &operator=(const PlatformSystemProxyBackend &) = delete;
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
#if defined(Q_OS_WIN) || defined(Q_OS_LINUX) || defined(Q_OS_MACOS)
    // Original proxy/PAC values may contain secrets; persist only in protected credential storage.
    QJsonObject recoverySnapshot() const;
    PlatformOperationResult recover(const QJsonObject &record);
#endif
private:
    struct Snapshot;
    std::shared_ptr<Snapshot> snapshot;
#ifdef Q_OS_WIN
    WindowsProxyApi api;
#elif defined(Q_OS_MACOS)
    MacProxyApi api;
#else
    PlatformCommandRunner runner;
#endif
    CheckpointWriter checkpointWriter;
#if defined(Q_OS_LINUX) || defined(Q_OS_WIN) || defined(Q_OS_MACOS)
    PlatformOperationResult checkpoint(bool remove = false);
#endif
};
