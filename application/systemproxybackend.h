#pragma once
#include "platformoperationresult.h"

struct SystemProxyConfig
{
    int httpPort = 0;
    int socksPort = 0;
    QString bypass;
};

struct SystemProxyCheck
{
    PlatformOperationResult result;
    bool conflict = false;
    bool active = false;
};

class SystemProxyBackend
{
public:
    virtual ~SystemProxyBackend() = default;
    virtual SystemProxyCheck check(const SystemProxyConfig &config) = 0;
    virtual PlatformOperationResult apply(const SystemProxyConfig &config) = 0;
    virtual PlatformOperationResult clear() = 0;
    virtual PlatformOperationResult beginRecovery(const QString &, bool resume)
    {
        return resume ? PlatformOperationResult{PlatformOperationResult::Status::Unsupported,
            "This backend cannot confirm a previous recovery owner"} : PlatformOperationResult{};
    }
};
