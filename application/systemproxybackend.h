#pragma once
#include "platformoperationresult.h"
#include <QStringList>

struct SystemProxyConfig
{
    int httpPort = 0;
    int socksPort = 0;
    QString bypass;
    // Nonempty only for automatic handoff from verified local upstream listeners.
    QStringList upstream;
};

struct SystemProxyCheck
{
    PlatformOperationResult result;
    bool conflict = false;
    bool active = false;
    bool managed = false;
    QStringList endpoints;
};

class SystemProxyBackend
{
public:
    virtual ~SystemProxyBackend() = default;
    virtual SystemProxyCheck check(const SystemProxyConfig &config) = 0;
    virtual SystemProxyCheck inspect() { return {{PlatformOperationResult::Status::Unsupported, "Proxy observation is unavailable"}}; }
    virtual PlatformOperationResult apply(const SystemProxyConfig &config) = 0;
    virtual PlatformOperationResult clear() = 0;
    virtual PlatformOperationResult beginRecovery(const QString &, bool resume)
    {
        return resume ? PlatformOperationResult{PlatformOperationResult::Status::Unsupported,
            "This backend cannot confirm a previous recovery owner"} : PlatformOperationResult{};
    }
};
