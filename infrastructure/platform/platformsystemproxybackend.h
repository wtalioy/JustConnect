#pragma once
#include "application/systemproxybackend.h"
#ifdef Q_OS_WIN
#include "windowsproxyapi.h"
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
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
private:
#ifdef Q_OS_WIN
    WindowsProxyApi api;
#else
    PlatformCommandRunner runner;
#endif
};
