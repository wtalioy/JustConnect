#pragma once

#include "application/systemproxybackend.h"
#include <memory>

class ProxyRecoveryBackend final : public SystemProxyBackend
{
public:
    explicit ProxyRecoveryBackend(QString executable = {});
    ~ProxyRecoveryBackend() override;
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
private:
    struct Worker;
    std::unique_ptr<Worker> worker;
};

int runProxyRecoveryWorker(SystemProxyBackend &backend, const QString &endpoint, const QString &lockFile,
                           const QString &legacyLockFile = {});
