#pragma once
#include "infrastructure/platform/platformsystemproxybackend.h"
#include "infrastructure/platform/proxyjournal.h"
#include <optional>

// All operations require the recovery worker's per-user lock, including the first load.
class LinuxPersistentProxyBackend final : public SystemProxyBackend
{
public:
    static QString credentialKey();
    LinuxPersistentProxyBackend(CredentialStore &credentials, QString key,
        PlatformCommandRunner runner = [](const QString &p,const QStringList &a) { return runPlatformCommand(p,a); });
    SystemProxyCheck check(const SystemProxyConfig &config) override;
    PlatformOperationResult apply(const SystemProxyConfig &config) override;
    PlatformOperationResult clear() override;
private:
    PlatformOperationResult recover();
    ProxyRecoveryJournal journal;
    PlatformSystemProxyBackend native;
    bool initialized = false, recovering = false;
    std::optional<PlatformOperationResult> rejected;
};
