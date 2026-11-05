#pragma once
#include "application/systemproxybackend.h"
#include <memory>
#include <functional>
#include <QJsonObject>
#if defined(Q_OS_WIN)
#include "infrastructure/systemproxy/windows/proxyapi.h"
#else
#include "infrastructure/systemproxy/macos/proxyapi.h"
#endif

class PlatformSystemProxyBackend : public SystemProxyBackend
{
public:
    // Success confirms durable publication; an empty object removes the record. Caller holds the recovery lock.
    using CheckpointWriter = std::function<PlatformOperationResult(const QJsonObject &)>;
#if defined(Q_OS_WIN)
    explicit PlatformSystemProxyBackend(WindowsProxyApi api = {}, CheckpointWriter writer = {})
        : api(api), checkpointWriter(std::move(writer)) {}
#else
    explicit PlatformSystemProxyBackend(MacProxyApi api = {}, CheckpointWriter writer = {})
        : api(std::move(api)), checkpointWriter(std::move(writer)) {}
#endif
    PlatformSystemProxyBackend(const PlatformSystemProxyBackend &) = delete;
    PlatformSystemProxyBackend &operator=(const PlatformSystemProxyBackend &) = delete;
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    SystemProxyCheck inspect() override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
    // Original proxy/PAC values may contain secrets; persist only in protected credential storage.
    QJsonObject recoverySnapshot() const;
    PlatformOperationResult recover(const QJsonObject &record);
private:
    SystemProxyCheck observe(const SystemProxyConfig *config);
    struct Snapshot;
    std::shared_ptr<Snapshot> snapshot;
#if defined(Q_OS_WIN)
    WindowsProxyApi api;
#else
    MacProxyApi api;
#endif
    CheckpointWriter checkpointWriter;
    PlatformOperationResult checkpoint(bool remove = false);
};
