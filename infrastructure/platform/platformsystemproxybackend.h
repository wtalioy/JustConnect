#pragma once
#include "application/systemproxybackend.h"
#include <memory>
#ifdef Q_OS_WIN
#include "windows/proxyapi.h"
#else
#include "platformcommand.h"
#endif

class PlatformSystemProxyBackend : public SystemProxyBackend
{
public:
#ifdef Q_OS_WIN
    explicit PlatformSystemProxyBackend(WindowsProxyApi api = {}) : api(api) {}
#else
    explicit PlatformSystemProxyBackend(PlatformCommandRunner runner = [](const QString &p, const QStringList &a) {
        return runPlatformCommand(p, a);
    }) : runner(std::move(runner)) {}
#endif
    PlatformSystemProxyBackend(const PlatformSystemProxyBackend &) = delete;
    PlatformSystemProxyBackend &operator=(const PlatformSystemProxyBackend &) = delete;
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
private:
    struct Snapshot;
    std::shared_ptr<Snapshot> snapshot;
#ifdef Q_OS_WIN
    WindowsProxyApi api;
#else
    PlatformCommandRunner runner;
#endif
};
